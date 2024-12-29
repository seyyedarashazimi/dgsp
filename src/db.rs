use crate::params::DGSP_POS_BYTES;
use async_trait::async_trait;
use std::path::Path;

#[cfg(feature = "in-disk")]
pub mod in_disk;
#[cfg(feature = "in-memory")]
pub mod in_memory;

/// Private List of the Manager in the DGSP scheme. It is responsible for storing and updating
/// username of each user, user activity status, and the number of issued certificates created
/// for each user.
#[async_trait]
pub trait PLMInterface {
    /// Open or create the PLM database, using the given `path`.
    async fn open<P: AsRef<Path> + Send>(path: P) -> Result<Self, crate::Error>
    where
        Self: Sized;

    /// Add a new user if it does not already exist.
    ///
    /// Returns `Ok(id)` if newly added. Otherwise, throws an error if given username already
    /// exists, or if other errors occur.
    async fn add_new_user(&self, username: &str) -> Result<u64, crate::Error>;

    /// Deactivate a user by ID
    async fn deactivate_id(&self, id: u64) -> Result<(), crate::Error>;

    /// Get counter of created certificates for a given user ID
    async fn get_ctr_id(&self, id: u64) -> Result<u64, crate::Error>;

    /// Get username by ID
    async fn get_username(&self, id: u64) -> Result<String, crate::Error>;

    /// Check if ID exists
    async fn id_exists(&self, id: u64) -> Result<bool, crate::Error>;

    /// Check if ID is active
    async fn id_is_active(&self, id: u64) -> Result<bool, crate::Error>;

    /// Increment number of created certificates of a user by `add` value.
    ///
    /// Returns `Ok(id)` if request is valid and no error occurs. Otherwise, throws an error if
    /// current issued certificates counter of the ID plus `add` value exceeds [`u64::MAX`] bound.
    async fn increment_ctr_id_by(&self, id: u64, add: u64) -> Result<(), crate::Error>;
}

/// RevokedList is a public list containing the DGSP.pos values to show which signatures and issued
/// certificates are revoked.
#[async_trait]
pub trait RevokedListInterface {
    /// Open or create the RevokedList database, using the given `path`.
    async fn open<P: AsRef<Path> + Send>(path: P) -> Result<Self, crate::Error>
    where
        Self: Sized;

    /// Check if a given pos exists in the RevokedList
    async fn contains(&self, pos: &[u8]) -> Result<bool, crate::Error>;

    /// Insert a given pos into the RevokedList
    async fn insert(&self, pos: [u8; DGSP_POS_BYTES]) -> Result<(), crate::Error>;
}
