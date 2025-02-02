use crate::params::DGSP_NU_BYTES;
use crate::Result;
use std::fmt::Display;
use std::path::Path;

#[cfg(feature = "in-disk")]
pub mod in_disk;
#[cfg(feature = "in-memory")]
pub mod in_memory;

/// Private List of the Manager in the DGSP scheme. It is responsible for storing and updating
/// username of each user, user activity status, and the number of issued certificates created
/// for each user.
pub trait PLMInterface {
    /// Open or create the PLM database, using the given `path`.
    fn open<P>(path: P) -> Result<Self>
    where
        Self: Sized,
        P: AsRef<Path> + Send;

    /// Add a new user if it does not already exist.
    ///
    /// Returns `Ok(id)` if newly added. Otherwise, throws an error if given username already
    /// exists, or if other errors occur.
    fn add_new_user<S>(&self, username: S) -> Result<u64>
    where
        S: AsRef<str> + Display + Send;

    /// Deactivate a user by ID
    fn deactivate_id(&self, id: u64) -> Result<()>;

    /// Get counter of created certificates for a given user ID
    fn get_ctr_id(&self, id: u64) -> Result<u64>;

    /// Get username by ID
    fn get_username(&self, id: u64) -> Result<String>;

    /// Check if ID exists
    fn id_exists(&self, id: u64) -> Result<bool>;

    /// Check if ID is active
    fn id_is_active(&self, id: u64) -> Result<bool>;

    /// Increment number of created certificates of a user by `add` value.
    ///
    /// Returns `Ok(id)` if request is valid and no error occurs. Otherwise, throws an error if
    /// current issued certificates counter of the ID plus `add` value exceeds [`u64::MAX`] bound.
    fn increment_ctr_id_by(&self, id: u64, add: u64) -> Result<()>;
}

/// RevokedList is a public list containing the DGSP.pos values to show which signatures and issued
/// certificates are revoked.
pub trait RevokedListInterface {
    /// Open or create the RevokedList database, using the given `path`.
    fn open<P: AsRef<Path> + Send>(path: P) -> Result<Self>
    where
        Self: Sized;

    /// Check if a given pos exists in the RevokedList
    fn contains(&self, pos: &[u8]) -> Result<bool>;

    /// Insert a given pos into the RevokedList
    fn insert(&self, pos: [u8; DGSP_NU_BYTES]) -> Result<()>;
}
