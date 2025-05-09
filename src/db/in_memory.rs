use crate::db::{PLMInterface, RevokedListInterface};
use crate::params::DGSP_ZETA_BYTES;
use crate::Result;
use std::collections::HashSet;
use std::fmt::Display;
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
    fn ensure_id_exists(&self, id: u64) -> Result<()> {
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

impl PLMInterface for InMemoryPLM {
    fn open<P: AsRef<Path> + Send>(_: P) -> Result<Self> {
        Ok(Self {
            data: Arc::new(Mutex::new(InMemoryPLMData::default())),
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
        let username = username.as_ref();
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
    fn deactivate_id(&self, id: u64) -> Result<()> {
        let mut data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        data.vec[id as usize].is_active = false;
        Ok(())
    }

    /// Get counter of created certificates for a given user ID
    fn get_ctr_id(&self, id: u64) -> Result<u64> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].ctr_certs)
    }

    /// Get username by ID
    fn get_username(&self, id: u64) -> Result<String> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].username.clone())
    }

    /// Check if ID exists
    fn id_exists(&self, id: u64) -> Result<bool> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(true)
    }

    /// Check if ID is active
    fn id_is_active(&self, id: u64) -> Result<bool> {
        let data = self.data.lock()?;
        data.ensure_id_exists(id)?;
        Ok(data.vec[id as usize].is_active)
    }

    /// Increment number of created certificates of a user by `add` value.
    ///
    /// Returns `Ok(id)` if request is valid and no error occurs. Otherwise, throws an
    /// `crate::errors::Error` error if current ctr_cert value of the ID plus `add` value exceeds
    /// [`u64::MAX`] bound.
    fn increment_ctr_id_by(&self, id: u64, add: u64) -> Result<()> {
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

#[cfg(feature = "benchmarking")]
#[doc(hidden)]
impl InMemoryPLM {
    #[cfg(feature = "benchmarking")]
    #[doc(hidden)]
    pub fn delete_sequential_usernames_to_the_end(&self, start_id: u64) -> Result<()> {
        let mut data = self.data.lock()?;

        let last_id = data.vec.len();

        if (last_id as u64) < start_id {
            return Err(crate::Error::DbInternalError(format!(
                "given id:{start_id} is not in the database."
            )));
        }

        for u in ((start_id as usize)..last_id).rev() {
            data.vec.pop().unwrap();
            data.set.remove(&u.to_string());
        }

        Ok(())
    }
}

/// RevokedList is a public list containing the DGSP.pos values to show which signatures and issued
/// certificates are revoked.
#[derive(Default)]
pub struct InMemoryRevokedList(Arc<Mutex<HashSet<[u8; DGSP_ZETA_BYTES]>>>);

impl RevokedListInterface for InMemoryRevokedList {
    fn open<P: AsRef<Path> + Send>(_: P) -> Result<Self> {
        Ok(InMemoryRevokedList::default())
    }

    /// Check if a given pos exists in the RevokedList
    fn contains(&self, pos: &[u8]) -> Result<bool> {
        let data = self.0.lock()?;
        Ok(data.contains(pos))
    }

    /// Insert a given pos into the RevokedList
    fn insert(&self, pos: [u8; DGSP_ZETA_BYTES]) -> Result<()> {
        let mut data = self.0.lock()?;
        data.insert(pos);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::DGSP_ZETA_BYTES;
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
        let plm = InMemoryPLM::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
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
        let plm = InMemoryPLM::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
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
        let plm = InMemoryPLM::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let id = plm.add_new_user(&username).unwrap();
        plm.increment_ctr_id_by(id, 1u64).unwrap();
        assert_eq!(plm.get_ctr_id(id).unwrap(), 1u64);

        let error_prefix = "";
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
        let rl = InMemoryRevokedList::open(temp_dir.path().join(TEST_DB_PATH)).unwrap();
        let mut pos = [0u8; DGSP_ZETA_BYTES];
        OsRng.fill_bytes(&mut pos);
        assert!(!rl.contains(&pos).unwrap());
        rl.insert(pos).unwrap();
        assert!(rl.contains(&pos).unwrap());
    }
}
