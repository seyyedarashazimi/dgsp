use crate::utils::{bytes_to_u64, u64_to_bytes};
use serde::{Deserialize, Serialize};
use sled::Transactional;
use std::path::Path;

const DGSP_POS_BYTES: usize = 16;

impl From<sled::Error> for crate::error::Error {
    fn from(e: sled::Error) -> Self {
        Self::DbInternalError(format!("sled error: {}", e))
    }
}

impl<E> From<sled::transaction::TransactionError<E>> for crate::error::Error
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
                            return crate::error::Error::IdNotFound(number);
                        }
                    }
                }
                if message == "UsernameAlreadyExists" {
                    return crate::error::Error::UsernameAlreadyExists(message);
                }
                sled::Error::Unsupported(reason.to_string()).into()
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PLMEntry {
    ctr_certs: u64,
    is_active: bool,
    username: String,
}

pub struct PLM {
    plme_tree: sled::Tree,
    name_tree: sled::Tree,
    meta_tree: sled::Tree,
}

const NEXT_ID_KEY: &[u8] = b"__next_id";

impl PLM {
    /// Open or create the PLM database with required trees.
    pub fn open() -> Result<Self, crate::error::Error> {
        let base_dir = Path::new("database");
        let db = sled::open(base_dir.join("plm"))?;
        let plme_tree = db.open_tree("plme_tree")?;
        let name_tree = db.open_tree("name_tree")?;
        let meta_tree = db.open_tree("meta_tree")?;

        Ok(Self {
            plme_tree,
            name_tree,
            meta_tree,
        })
    }

    /// Add a new user if it does not already exist.
    ///
    /// Returns `Ok(id)` if newly added. Otherwise, throws an `crate::errors::Error` error if given
    /// username already existed, or if an error occurs.
    pub fn add_new_user(&mut self, username: &str) -> Result<u64, crate::error::Error> {
        self._add_new_user(username)
    }

    fn _add_new_user(&self, username: &str) -> Result<u64, crate::error::Error> {
        let username_bytes = username.as_bytes();

        let new_id = (&self.plme_tree, &self.name_tree, &self.meta_tree).transaction(
            |(ptree, ntree, mtree)| {
                // Check if username already exists
                if ntree.get(username_bytes)?.is_some() {
                    // User already exists
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        "UsernameAlreadyExists",
                    ));
                }

                // Get the current next_id
                let next_id = match mtree.get(NEXT_ID_KEY)? {
                    Some(id_bytes) => {
                        let mut arr = [0u8; 8];
                        arr.copy_from_slice(&id_bytes);
                        if self.plme_tree.get(arr)?.is_some() {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                "ID is already in-use",
                            ));
                        }
                        bytes_to_u64(&arr)
                        // bytes_to_u64(&id_bytes)
                    },
                    None => 0u64,
                };

                let user_id = next_id;
                let entry = PLMEntry {
                    ctr_certs: 0,
                    is_active: true,
                    username: username.to_owned(),
                };
                let serialized = bincode::serialize(&entry)
                    .map_err(|_| sled::Error::Unsupported("Serialization error".into()))?;

                // Insert the user record and update the username index
                ptree.insert(&u64_to_bytes(user_id), serialized)?;
                ntree.insert(username_bytes, &u64_to_bytes(user_id))?;

                // Update the next user ID counter
                let new_next_id = user_id + 1;
                ptree.insert(NEXT_ID_KEY, &u64_to_bytes(new_next_id))?;

                Ok(user_id)
            },
        )?;

        Ok(new_id)
    }

    /// Deactivate a user by ID
    pub fn deactivate_id(&mut self, id: u64) -> Result<(), crate::error::Error> {
        self._deactivate_id(id)
    }

    fn _deactivate_id(&self, id: u64) -> Result<(), crate::error::Error> {
        let id_key = u64_to_bytes(id);
        self.plme_tree.transaction(|ptree| {
            let val = ptree.get(id_key)?;
            if let Some(val) = val {
                let mut entry: PLMEntry = bincode::deserialize(&val)
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

    /// Get ctr_certs by ID
    pub fn get_ctr_id(&self, id: u64) -> Result<u64, crate::error::Error> {
        let id_key = u64_to_bytes(id);
        if let Some(val) = self.plme_tree.get(id_key)? {
            let entry: PLMEntry = bincode::deserialize(&val)
                .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
            Ok(entry.ctr_certs)
        } else {
            Err(crate::error::Error::IdNotFound(id))
        }
    }

    /// Get username by ID
    pub fn get_username(&self, id: u64) -> Result<String, crate::error::Error> {
        let id_key = u64_to_bytes(id);
        if let Some(val) = self.plme_tree.get(id_key)? {
            let entry: PLMEntry = bincode::deserialize(&val)
                .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
            Ok(entry.username)
        } else {
            Err(crate::error::Error::IdNotFound(id))
        }
    }

    /// Check if ID exists
    pub fn id_exists(&self, id: u64) -> Result<bool, crate::error::Error> {
        let id_key = u64_to_bytes(id);
        if self.plme_tree.get(id_key)?.is_some() {
            Ok(true)
        } else {
            Err(crate::error::Error::IdNotFound(id))
        }
    }

    /// Check if ID is active
    pub fn id_is_active(&self, id: u64) -> Result<bool, crate::error::Error> {
        let id_key = u64_to_bytes(id);
        if let Some(val) = self.plme_tree.get(id_key)? {
            let entry: PLMEntry = bincode::deserialize(&val)
                .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
            Ok(entry.is_active)
        } else {
            Err(crate::error::Error::IdNotFound(id))
        }
    }

    /// Increment ctr_certs by `add`
    pub fn increment_ctr_id_by(&mut self, id: u64, add: u64) -> Result<(), crate::error::Error> {
        self._increment_ctr_id_by(id, add)
    }

    fn _increment_ctr_id_by(&self, id: u64, add: u64) -> Result<(), crate::error::Error> {
        let id_key = u64_to_bytes(id);
        self.plme_tree.transaction(|ptree| {
            if let Some(val) = ptree.get(id_key)? {
                let mut entry: PLMEntry = bincode::deserialize(&val)
                    .map_err(|_| sled::Error::Unsupported("Deserialization error".into()))?;
                entry.ctr_certs =
                    entry
                        .ctr_certs
                        .checked_add(add)
                        .ok_or(sled::Error::Unsupported(format!(
                            "Exceeds max certificate generation for the user {}",
                            id
                        )))?;
                // entry.ctr_certs = entry.ctr_certs.checked_add(add).unwrap_or(u64::MAX);
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

pub struct RevokedList {
    tree: sled::Tree,
}

impl RevokedList {
    pub fn open() -> Result<Self, crate::error::Error> {
        let base_dir = Path::new("database");
        let db = sled::open(base_dir.join("rl"))?;
        let tree = db.open_tree("revoked_list")?;
        Ok(Self { tree })
    }

    pub fn contains(&self, pos: &[u8; DGSP_POS_BYTES]) -> Result<bool, crate::error::Error> {
        Ok(self.tree.get(pos)?.is_some())
    }

    pub fn insert(&mut self, pos: [u8; DGSP_POS_BYTES]) -> Result<(), crate::error::Error> {
        self._insert(pos)
    }

    fn _insert(&self, pos: [u8; DGSP_POS_BYTES]) -> Result<(), crate::error::Error> {
        self.tree.insert(pos, &[])?;
        Ok(())
    }
}

// fn main() -> Result<(), sled::Error> {
//     // Example usage:
//     let db = sled::open("my_db")?;
//     let plm = PLM::open(db.clone())?;
//     let revoked_list = RevokedList::open(&db)?;
//
//     let (user_id, added) = plm.add_new_user("alice")?;
//     println!("Added user 'alice': id={} added={}", user_id, added);
//
//     plm.increment_ctr_id_by(user_id, 10)?;
//     let ctr = plm.get_ctr_id(user_id)?;
//     println!("Counter for user_id {}: {}", user_id, ctr);
//
//     plm.deactivate_id(user_id)?;
//     let active = plm.id_is_active(user_id)?;
//     println!("Is user_id {} active?: {}", user_id, active);
//
//     let pos = [0u8; DGSP_POS_BYTES];
//     revoked_list.insert(pos)?;
//     let is_revoked = revoked_list.contains(&pos)?;
//     println!("Is pos revoked?: {}", is_revoked);
//
//     Ok(())
// }
