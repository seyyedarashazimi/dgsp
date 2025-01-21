use crate::db::{PLMInterface, RevokedListInterface};
use crate::params::DGSP_POS_BYTES;
use crate::utils::{bytes_to_u64, u64_to_bytes};
use crate::Result;
use serde::{Deserialize, Serialize};
use sled::Transactional;
use std::fmt::Display;
use std::path::Path;

/// A typed abort reason for Sled transactions.
#[derive(Serialize, Deserialize, Debug)]
enum TxAbortReason {
    IdNotFound(u64),
    UsernameAlreadyExists(String),
}

impl From<sled::Error> for crate::Error {
    fn from(e: sled::Error) -> Self {
        Self::DbInternalError(format!("sled error: {}", e))
    }
}

impl<E> From<sled::transaction::TransactionError<E>> for crate::Error
where
    E: ToString,
{
    fn from(e: sled::transaction::TransactionError<E>) -> Self {
        match e {
            sled::transaction::TransactionError::Storage(err) => err.into(),
            sled::transaction::TransactionError::Abort(reason) => {
                // Attempt to parse from JSON
                match serde_json::from_str::<TxAbortReason>(&reason.to_string()) {
                    Ok(TxAbortReason::IdNotFound(id)) => crate::Error::IdNotFound(id),
                    Ok(TxAbortReason::UsernameAlreadyExists(name)) => {
                        crate::Error::UsernameAlreadyExists(name)
                    },
                    Err(_) => sled::Error::Unsupported(reason.to_string()).into(),
                }
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct InDiskPLMEntry {
    ctr_certs: u64,
    is_active: bool,
    username: String,
}

/// Private List of the Manager in the DGSP scheme. It is responsible for storing and updating
/// username of each user, user activity status, and the number of issued certificates created
/// for each user.
#[derive(Debug, Clone)]
pub struct InDiskPLM {
    #[allow(unused)]
    db: sled::Db,
    plme_tree: sled::Tree,
    name_tree: sled::Tree,
    meta_tree: sled::Tree,
}

const NEXT_ID_KEY: &[u8] = b"__next_id";

impl PLMInterface for InDiskPLM {
    fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path> + Send,
    {
        let path = path.as_ref().join("plm");
        let db = sled::open(&path)?;
        let plme_tree = db.open_tree("plme_tree")?;
        let name_tree = db.open_tree("name_tree")?;
        let meta_tree = db.open_tree("meta_tree")?;
        Ok(Self {
            db,
            plme_tree,
            name_tree,
            meta_tree,
        })
    }

    /// Add a new user if it does not already exist.
    ///
    /// Returns `Ok(id)` if newly added. Otherwise, throws an `crate::errors::Error` error if given
    /// username already existed, or if an error occurs.
    fn add_new_user<S>(&self, username: S) -> Result<u64>
    where
        S: AsRef<str> + Display + Send,
    {
        let username_bytes = username.as_ref().as_bytes();

        let new_id = (&self.plme_tree, &self.name_tree, &self.meta_tree).transaction(
            |(ptree, ntree, mtree)| {
                if ntree.get(username_bytes)?.is_some() {
                    let reason = TxAbortReason::UsernameAlreadyExists(username.to_string());
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        serde_json::to_string(&reason).unwrap(),
                    ));
                }

                // Get the current next_id
                let next_id = match mtree.get(NEXT_ID_KEY)? {
                    Some(id_bytes) => bytes_to_u64(&id_bytes),
                    None => 0u64,
                };

                let entry = InDiskPLMEntry {
                    ctr_certs: 0,
                    is_active: true,
                    username: username.to_string(),
                };
                let serialized = bincode::serialize(&entry)
                    .map_err(|_| sled::Error::Unsupported("Serialization error".into()))?;

                ptree.insert(&u64_to_bytes(next_id), serialized)?; // Insert the user record
                ntree.insert(username_bytes, &u64_to_bytes(next_id))?; // Update the username index
                mtree.insert(NEXT_ID_KEY, &u64_to_bytes(next_id + 1))?; // Update the next user ID counter

                Ok(next_id)
            },
        )?;

        Ok(new_id)
    }

    /// Deactivate a user by ID
    fn deactivate_id(&self, id: u64) -> Result<()> {
        let id_key = u64_to_bytes(id);
        self.plme_tree.transaction(|ptree| {
            let val = ptree.get(id_key)?;
            if let Some(val) = val {
                let mut entry: InDiskPLMEntry = bincode::deserialize(&val)
                    .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
                entry.is_active = false;
                let serialized = bincode::serialize(&entry)
                    .map_err(|_| sled::Error::Unsupported("Serialization error".into()))?;
                ptree.insert(&id_key, serialized)?;
            } else {
                let reason = TxAbortReason::IdNotFound(id);
                return Err(sled::transaction::ConflictableTransactionError::Abort(
                    serde_json::to_string(&reason).unwrap(),
                ));
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Get counter of created certificates for a given user ID
    fn get_ctr_id(&self, id: u64) -> Result<u64> {
        let id_key = u64_to_bytes(id);
        if let Some(val) = self.plme_tree.get(id_key)? {
            let entry: InDiskPLMEntry = bincode::deserialize(&val)
                .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
            Ok(entry.ctr_certs)
        } else {
            Err(crate::Error::IdNotFound(id))
        }
    }

    /// Get username by ID
    fn get_username(&self, id: u64) -> Result<String> {
        let id_key = u64_to_bytes(id);
        if let Some(val) = self.plme_tree.get(id_key)? {
            let entry: InDiskPLMEntry = bincode::deserialize(&val)
                .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
            Ok(entry.username)
        } else {
            Err(crate::Error::IdNotFound(id))
        }
    }

    /// Check if ID exists
    fn id_exists(&self, id: u64) -> Result<bool> {
        let id_key = u64_to_bytes(id);
        if self.plme_tree.contains_key(id_key)? {
            Ok(true)
        } else {
            Err(crate::Error::IdNotFound(id))
        }
    }

    /// Check if ID is active
    fn id_is_active(&self, id: u64) -> Result<bool> {
        let id_key = u64_to_bytes(id);
        if let Some(val) = self.plme_tree.get(id_key)? {
            let entry: InDiskPLMEntry = bincode::deserialize(&val)
                .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
            Ok(entry.is_active)
        } else {
            Err(crate::Error::IdNotFound(id))
        }
    }

    /// Increment number of created certificates of a user by `add` value.
    ///
    /// Returns `Ok(id)` if request is valid and no error occurs. Otherwise, throws an
    /// `crate::errors::Error` error if current ctr_cert value of the ID plus `add` value exceeds
    /// [`u64::MAX`] bound.
    fn increment_ctr_id_by(&self, id: u64, add: u64) -> Result<()> {
        let id_key = u64_to_bytes(id);
        self.plme_tree.transaction(|ptree| {
            if let Some(val) = ptree.get(id_key)? {
                let mut entry: InDiskPLMEntry = bincode::deserialize(&val)
                    .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
                entry.ctr_certs =
                    entry
                        .ctr_certs
                        .checked_add(add)
                        .ok_or(sled::Error::Unsupported(format!(
                            "Exceeds max certificate generation for the user {}",
                            id
                        )))?;

                let serialized = bincode::serialize(&entry)
                    .map_err(|_| sled::Error::Unsupported("Serialization error".into()))?;
                ptree.insert(&id_key, serialized)?;
            } else {
                return Err(sled::transaction::ConflictableTransactionError::Abort(
                    format!("IdNotFound:{}", id),
                ));
            }
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(feature = "benchmarking")]
#[doc(hidden)]
impl InDiskPLM {
    #[cfg(feature = "benchmarking")]
    #[doc(hidden)]
    pub fn delete_sequential_usernames_to_the_end(&self, start_id: u64) -> Result<()> {
        self.db.flush()?;
        (&self.plme_tree, &self.name_tree, &self.meta_tree).transaction(
            |(ptree, ntree, mtree)| {
                let last_id = match mtree.get(NEXT_ID_KEY)? {
                    Some(id_bytes) => bytes_to_u64(&id_bytes),
                    None => 0u64,
                };

                if last_id < start_id {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        format!(
                            "Given id:{start_id} is not in the database. The last id is {last_id}."
                        ),
                    ));
                }

                for u in (start_id..last_id).rev() {
                    ptree.remove(&u.to_be_bytes())?;
                    ntree.remove(u.to_string().as_bytes())?;
                }

                mtree.insert(NEXT_ID_KEY, &u64_to_bytes(start_id))?;

                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "benchmarking")]
    #[doc(hidden)]
    pub fn flush_plm(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

/// RevokedList is a public list containing the DGSP.pos values to show which signatures and issued
/// certificates are revoked.
pub struct InDiskRevokedList {
    db: sled::Db,
}

impl RevokedListInterface for InDiskRevokedList {
    fn open<P: AsRef<Path> + Send>(path: P) -> Result<Self> {
        let path = path.as_ref().join("rl");
        let db = sled::open(&path)?;
        Ok(Self { db })
    }

    /// Check if a given pos exists in the RevokedList
    fn contains(&self, pos: &[u8]) -> Result<bool> {
        Ok(self.db.contains_key(pos)?)
    }

    /// Insert a given pos into the RevokedList
    fn insert(&self, pos: [u8; DGSP_POS_BYTES]) -> Result<()> {
        self.db.insert(pos, &[])?;
        Ok(())
    }
}

#[cfg(feature = "benchmarking")]
#[doc(hidden)]
impl InDiskRevokedList {
    #[cfg(feature = "benchmarking")]
    #[doc(hidden)]
    pub fn clear(&self) -> Result<()> {
        self.db.flush()?;
        self.db.clear()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::in_disk::InDiskPLM;
    use crate::params::DGSP_POS_BYTES;
    use crate::Error;
    use rand::distributions::Alphanumeric;
    use rand::rngs::OsRng;
    use rand::{Rng, RngCore};
    use tempfile::TempDir;

    const TEST_DB_PATH: &str = "test_db";

    fn random_str(length: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    #[test]
    fn test_plm_add_username() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = InDiskPLM::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let id = plm.add_new_user(&username).unwrap();
        assert_eq!(id, 0u64);
        assert_eq!(
            plm.add_new_user(&username),
            Err(Error::UsernameAlreadyExists(username.clone()))
        );
        let id2 = plm.add_new_user(format!("{}2", username).as_str()).unwrap();
        assert_eq!(id2, 1u64);
    }

    #[test]
    fn test_plm_id() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = InDiskPLM::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let id = plm.add_new_user(&username).unwrap();
        assert!(plm.id_exists(id).unwrap());
        assert!(plm.id_is_active(id).unwrap());
        assert_eq!(plm.get_ctr_id(id).unwrap(), 0u64);
        assert_eq!(plm.get_username(id).unwrap(), username);
        plm.deactivate_id(id).unwrap();
        assert!(!plm.id_is_active(id).unwrap());
    }

    #[test]
    fn test_plm_ctr_cert() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = InDiskPLM::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let id = plm.add_new_user(&username).unwrap();
        plm.increment_ctr_id_by(id, 1u64).unwrap();
        assert_eq!(plm.get_ctr_id(id).unwrap(), 1u64);

        let error_prefix = "sled error: Unsupported: ";
        assert_eq!(
            plm.increment_ctr_id_by(id, u64::MAX),
            Err(Error::DbInternalError(format!(
                "{}Exceeds max certificate generation for the user {}",
                error_prefix, id
            )))
        );
    }

    #[test]
    fn test_revoked_list() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let rl = InDiskRevokedList::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let mut pos = [0u8; DGSP_POS_BYTES];
        OsRng.fill_bytes(&mut pos);
        assert!(!rl.contains(&pos).unwrap());
        rl.insert(pos).unwrap();
        assert!(rl.contains(&pos).unwrap());
    }
}
