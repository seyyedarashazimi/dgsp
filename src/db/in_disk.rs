use crate::db::{PLMInterface, RevokedListInterface};
use crate::params::DGSP_POS_BYTES;
use crate::utils::{bytes_to_u64, u64_to_bytes};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sled::Transactional;
use std::fmt::Display;
use std::ops::Deref;
use std::path::Path;

impl From<sled::Error> for crate::Error {
    fn from(e: sled::Error) -> Self {
        Self::DbInternalError(format!("sled error: {}", e))
    }
}

impl From<std::io::Error> for crate::Error {
    fn from(e: std::io::Error) -> Self {
        Self::DbInternalError(format!("io error: {}", e))
    }
}

impl<E> From<sled::transaction::TransactionError<E>> for crate::Error
where
    E: ToString,
{
    fn from(e: sled::transaction::TransactionError<E>) -> Self {
        match e {
            sled::transaction::TransactionError::Storage(err) => err.into(), // Handle storage errors
            sled::transaction::TransactionError::Abort(reason) => {
                let message = reason.to_string();
                if message.starts_with("IdNotFound:") {
                    // Try to parse the number from the message
                    if let Some(number_str) = message.strip_prefix("IdNotFound:") {
                        if let Ok(number) = number_str.trim().parse::<u64>() {
                            return crate::Error::IdNotFound(number);
                        }
                    }
                }
                if message.starts_with("UsernameAlreadyExists:") {
                    // Parse the username from the message
                    if let Some(str) = message.strip_prefix("UsernameAlreadyExists:") {
                        let username = str.trim().parse::<String>().unwrap();
                        return crate::Error::UsernameAlreadyExists(username);
                    }
                }
                sled::Error::Unsupported(message).into()
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    db: sled::Db,
    plme_tree: sled::Tree,
    name_tree: sled::Tree,
    meta_tree: sled::Tree,
}

const NEXT_ID_KEY: &[u8] = b"__next_id";

#[async_trait]
impl PLMInterface for InDiskPLM {
    async fn open<P>(path: P) -> Result<Self, crate::Error>
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
    async fn add_new_user<S>(&self, username: S) -> Result<u64, crate::Error>
    where
        S: AsRef<str> + Display + Send,
    {
        let username_bytes = username.as_ref().as_bytes();

        let new_id = (&self.plme_tree, &self.name_tree, &self.meta_tree).transaction(
            |(ptree, ntree, mtree)| {
                if ntree.get(username_bytes)?.is_some() {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        format!("UsernameAlreadyExists:{}", username),
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
    async fn deactivate_id(&self, id: u64) -> Result<(), crate::Error> {
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
                return Err(sled::transaction::ConflictableTransactionError::Abort(
                    format!("IdNotFound:{}", id),
                ));
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Get counter of created certificates for a given user ID
    async fn get_ctr_id(&self, id: u64) -> Result<u64, crate::Error> {
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
    async fn get_username(&self, id: u64) -> Result<String, crate::Error> {
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
    async fn id_exists(&self, id: u64) -> Result<bool, crate::Error> {
        let id_key = u64_to_bytes(id);
        if self.plme_tree.get(id_key)?.is_some() {
            Ok(true)
        } else {
            Err(crate::Error::IdNotFound(id))
        }
    }

    /// Check if ID is active
    async fn id_is_active(&self, id: u64) -> Result<bool, crate::Error> {
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
    async fn increment_ctr_id_by(&self, id: u64, add: u64) -> Result<(), crate::Error> {
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

impl Deref for InDiskPLM {
    type Target = sled::Db;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

// impl InDiskPLM {
//     pub fn size_in_disk(&self) -> Result<u64, crate::Error> {
//         self.db.flush()?;
//         disk_usage(&self.path)
//     }
// }

/// RevokedList is a public list containing the DGSP.pos values to show which signatures and issued
/// certificates are revoked.
pub struct InDiskRevokedList {
    db: sled::Db,
}

impl Deref for InDiskRevokedList {
    type Target = sled::Db;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

#[async_trait]
impl RevokedListInterface for InDiskRevokedList {
    async fn open<P: AsRef<Path> + Send>(path: P) -> Result<Self, crate::Error> {
        let path = path.as_ref().join("rl");
        let db = sled::open(&path)?;
        Ok(Self { db })
    }

    /// Check if a given pos exists in the RevokedList
    async fn contains(&self, pos: &[u8]) -> Result<bool, crate::Error> {
        Ok(self.db.get(pos)?.is_some())
    }

    /// Insert a given pos into the RevokedList
    async fn insert(&self, pos: [u8; DGSP_POS_BYTES]) -> Result<(), crate::Error> {
        self.db.insert(pos, &[])?;
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

    #[tokio::test]
    async fn test_plm_add_username() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = InDiskPLM::open(temp_dir.path().join(TEST_DB_PATH))
            .await
            .unwrap();
        let id = plm.add_new_user(&username).await.unwrap();
        assert_eq!(id, 0u64);
        assert_eq!(
            plm.add_new_user(&username).await,
            Err(Error::UsernameAlreadyExists(username.clone()))
        );
        let id2 = plm
            .add_new_user(format!("{}2", username).as_str())
            .await
            .unwrap();
        assert_eq!(id2, 1u64);
    }

    #[tokio::test]
    async fn test_plm_id() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = InDiskPLM::open(temp_dir.path().join(TEST_DB_PATH))
            .await
            .unwrap();
        let id = plm.add_new_user(&username).await.unwrap();
        assert!(plm.id_exists(id).await.unwrap());
        assert!(plm.id_is_active(id).await.unwrap());
        assert_eq!(plm.get_ctr_id(id).await.unwrap(), 0u64);
        assert_eq!(plm.get_username(id).await.unwrap(), username);
        plm.deactivate_id(id).await.unwrap();
        assert!(!plm.id_is_active(id).await.unwrap());
    }

    #[tokio::test]
    async fn test_plm_ctr_cert() {
        let username = random_str(rand::thread_rng().gen_range(1..30));
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let plm = InDiskPLM::open(temp_dir.path().join(TEST_DB_PATH))
            .await
            .unwrap();
        let id = plm.add_new_user(&username).await.unwrap();
        plm.increment_ctr_id_by(id, 1u64).await.unwrap();
        assert_eq!(plm.get_ctr_id(id).await.unwrap(), 1u64);

        let error_prefix = "sled error: Unsupported: ";
        assert_eq!(
            plm.increment_ctr_id_by(id, u64::MAX).await,
            Err(Error::DbInternalError(format!(
                "{}Exceeds max certificate generation for the user {}",
                error_prefix, id
            )))
        );
    }

    #[tokio::test]
    async fn test_revoked_list() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let rl = InDiskRevokedList::open(temp_dir.path().join(TEST_DB_PATH))
            .await
            .unwrap();
        let mut pos = [0u8; DGSP_POS_BYTES];
        OsRng.fill_bytes(&mut pos);
        assert!(!rl.contains(&pos).await.unwrap());
        rl.insert(pos).await.unwrap();
        assert!(rl.contains(&pos).await.unwrap());
    }
}
