mod cipher;
mod db;
mod error;
mod hash;
mod utils;

pub mod params;
pub mod scheme;
pub mod sphincs_plus;
pub mod wots_plus;

// prelude:
pub use crate::db::{PLMInterface, RevokedListInterface};
pub use crate::error::{Error, Result, VerificationError};
pub use crate::scheme::DGSP;

#[cfg(feature = "in-disk")]
pub use crate::db::in_disk::{InDiskPLM, InDiskRevokedList};
#[cfg(feature = "in-memory")]
pub use crate::db::in_memory::{InMemoryPLM, InMemoryRevokedList};
