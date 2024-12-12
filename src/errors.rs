use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid length: expected {0} bytes, found {1} bytes")]
    BadLength(usize, usize),
    #[error("Failed to convert into byte slice due to the bad length: {0}")]
    IntoBytesBadLength(#[from] std::array::TryFromSliceError),
    #[error("Failed to convert from byte slice due to the bad length: {0}")]
    FromBytesBadLength(#[from] pqcrypto_traits::Error),
    #[error("Signature verification failed: {0}")]
    SphincsPlusVerificationFailed(#[from] pqcrypto_traits::sign::VerificationError),
}

#[derive(Error, Debug)]
pub enum GroupSignatureError {
    #[error("Invalid key")]
    InvalidKey,
    #[error("Signature verification failed")]
    VerificationFailed,
    // Add more error variants as needed
}
