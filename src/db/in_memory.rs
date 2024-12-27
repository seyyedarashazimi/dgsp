use crate::db::{PLMInterface, RevokedListInterface};
use crate::params::DGSP_POS_BYTES;
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

impl<T> From<PoisonError<T>> for crate::Error {
    fn from(err: PoisonError<T>) -> Self {
        Self::DbInternalError(format!("Lock error: {}", err))
    }
}

struct InMemoryPLMEntry {
    ctr_certs: u64,
    is_active: bool,
    username: String,
}

#[derive(Default)]
struct InMemoryPLMData {
    vec: Vec<InMemoryPLMEntry>,
    set: HashSet<String>,
}

impl InMemoryPLMData {
    fn ensure_id_exists(&self, id: u64) -> Result<(), crate::Error> {
        if id < (self.vec.len() as u64) {
            Ok(())
        } else {
            Err(crate::Error::IdNotFound(id))
        }
    }
}

/// Private List of the Manager in the DGSP scheme. It is responsible for storing and updating
/// username of each user, user activity status, and the number of issued certificates created
/// for each user.
#[derive(Default)]
pub struct InMemoryPLM {
    data: Arc<Mutex<InMemoryPLMData>>,
}

#[async_trait(?Send)]
impl PLMInterface for InMemoryPLM {
    async fn open<P: AsRef<Path>>(_: P) -> Result<Self, crate::Error> {
        Ok(Self {
            data: Arc::new(Mutex::new(InMemoryPLMData::default())),
        })
    }

    /// Add a new user if it does not already exist.
    ///
    /// Returns `Ok(id)` if newly added. Otherwise, throws an `crate::errors::Error` error if given
    /// username already existed, or if an error occurs.
    async fn add_new_user(&self, username: &str) -> Result<u64, crate::Error> {
        let mut data = self.data.lock()?;
        if data.set.contains(username) {
            return Err(crate::Error::UsernameAlreadyExists(username.into()));
        }
        let new_id = data.vec.len() as u64;
        data.vec.push(InMemoryPLMEntry {
            ctr_certs: 0,
            is_active: true,
            username: username.to_owned(),
        });
        data.set.insert(username.to_owned());
        Ok(new_id)
    }

    /// Deactivate a user by ID
    async fn deactivate_id(&self, id: u64) -> Result<(), crate::Error> {
        let mut data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        data.vec[id as usize].is_active = false;
        Ok(())
    }

    /// Get counter of created certificates for a given user ID
    async fn get_ctr_id(&self, id: u64) -> Result<u64, crate::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].ctr_certs)
    }

    /// Get username by ID
    async fn get_username(&self, id: u64) -> Result<String, crate::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].username.clone())
    }

    /// Check if ID exists
    async fn id_exists(&self, id: u64) -> Result<bool, crate::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(true)
    }

    /// Check if ID is active
    async fn id_is_active(&self, id: u64) -> Result<bool, crate::Error> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].is_active)
    }

    /// Increment number of created certificates of a user by `add` value.
    ///
    /// Returns `Ok(id)` if request is valid and no error occurs. Otherwise, throws an
    /// `crate::errors::Error` error if current ctr_cert value of the ID plus `add` value exceeds
    /// [`u64::MAX`] bound.
    async fn increment_ctr_id_by(&self, id: u64, add: u64) -> Result<(), crate::Error> {
        let mut data = self.data.lock()?;
        if data.vec[id as usize].ctr_certs > u64::MAX - add {
            return Err(crate::Error::DbInternalError(format!(
                "Exceeds max certificate generation for the user {}",
                id
            )));
        }
        data.vec[id as usize].ctr_certs += add;
        Ok(())
    }
}

/// RevokedList is a public list containing the DGSP.pos values to show which signatures and issued
/// certificates are revoked.
#[derive(Default)]
pub struct InMemoryRevokedList(Arc<Mutex<HashSet<[u8; DGSP_POS_BYTES]>>>);

#[async_trait(?Send)]
impl RevokedListInterface for InMemoryRevokedList {
    async fn open<P: AsRef<Path>>(_: P) -> Result<Self, crate::Error> {
        Ok(InMemoryRevokedList::default())
    }

    /// Check if a given pos exists in the RevokedList
    async fn contains(&self, pos: &[u8]) -> Result<bool, crate::Error> {
        let data = self.0.lock()?;
        Ok(data.contains(pos))
    }

    /// Insert a given pos into the RevokedList
    async fn insert(&self, pos: [u8; DGSP_POS_BYTES]) -> Result<(), crate::Error> {
        let mut data = self.0.lock()?;
        data.insert(pos);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let plm = InMemoryPLM::open(temp_dir.path().join(TEST_DB_PATH))
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
        let plm = InMemoryPLM::open(temp_dir.path().join(TEST_DB_PATH))
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
        let plm = InMemoryPLM::open(temp_dir.path().join(TEST_DB_PATH))
            .await
            .unwrap();
        let id = plm.add_new_user(&username).await.unwrap();
        plm.increment_ctr_id_by(id, 1u64).await.unwrap();
        assert_eq!(plm.get_ctr_id(id).await.unwrap(), 1u64);

        let error_prefix = "";
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
        let rl = InMemoryRevokedList::open(temp_dir.path().join(TEST_DB_PATH))
            .await
            .unwrap();
        let mut pos = [0u8; DGSP_POS_BYTES];
        OsRng.fill_bytes(&mut pos);
        assert!(!rl.contains(&pos).await.unwrap());
        rl.insert(pos).await.unwrap();
        assert!(rl.contains(&pos).await.unwrap());
    }
}
