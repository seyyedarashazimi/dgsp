#[cfg(any(feature = "sphincs_sha2_128f", feature = "sphincs_sha2_128s",))]
mod sha2_128;
#[cfg(any(
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
mod sha2_192_256;

#[cfg(any(feature = "sphincs_sha2_128f", feature = "sphincs_sha2_128s",))]
pub(crate) use crate::hash::sha2::sha2_128::DGSPHasher;
#[cfg(any(
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
pub(crate) use crate::hash::sha2::sha2_192_256::DGSPHasher;
