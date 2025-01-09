mod db;
mod error;
mod hash;
mod utils;

pub mod dgsp;
pub mod params;
pub mod sphincs_plus;
pub mod wots_plus;

pub use crate::db::{PLMInterface, RevokedListInterface};
pub use crate::error::{Error, Result, VerificationError};

#[cfg(feature = "in-disk")]
pub use crate::db::in_disk::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
pub use crate::db::in_memory::{InMemoryPLM, InMemoryRevokedList};
