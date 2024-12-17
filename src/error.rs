use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid length: expected {0} bytes, found {1} bytes")]
    BadLength(usize, usize),
    #[error("Failed to convert into byte slice due to the bad length: {0}")]
    IntoBytesBadLength(String),
    #[error("Failed to convert from byte slice due to the bad length: {0}")]
    FromBytesBadLength(String),
    #[error("Signature verification failed: {0}")]
    VerificationFailed(#[from] VerificationError),
    #[error("Database internal error: {0}")]
    DbInternalError(String),
    #[error("User ID '{0}' not found")]
    IdNotFound(u64),
    #[error("Given username '{0}' already exists")]
    UsernameAlreadyExists(String),
    #[error("Invalid request for certificate generation")]
    InvalidCertReq,
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(e: std::array::TryFromSliceError) -> Self {
        Error::IntoBytesBadLength(e.to_string())
    }
}

impl From<pqcrypto_traits::Error> for Error {
    fn from(e: pqcrypto_traits::Error) -> Self {
        Error::FromBytesBadLength(e.to_string())
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VerificationError {
    #[error("SPHINCS+ verification failed: {0}")]
    SphincsPlusVerificationFailed(String),
    #[error("Signature is revoked")]
    RevokedSignature,
}

impl From<pqcrypto_traits::sign::VerificationError> for VerificationError {
    fn from(e: pqcrypto_traits::sign::VerificationError) -> Self {
        VerificationError::SphincsPlusVerificationFailed(e.to_string())
    }
}

impl From<pqcrypto_traits::sign::VerificationError> for Error {
    fn from(e: pqcrypto_traits::sign::VerificationError) -> Self {
        e.into()
    }
}
