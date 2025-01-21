use thiserror::Error;

/// Convenience wrapper for Result
pub type Result<T> = core::result::Result<T, Error>;

/// Represents the possible errors in the application.
///
/// This enum defines a variety of errors that can occur during the execution of
/// operations, such as validation errors, database errors, and signature verification issues.
///
/// # Variants
///
/// * `BadLength` - Indicates an invalid length for data. Contains the expected and found lengths.
/// * `IntoBytesBadLength` - Indicates a failure to convert an object into a byte slice due to an incorrect length.
/// * `FromBytesBadLength` - Indicates a failure to convert a byte slice into an object due to an incorrect length.
/// * `VerificationFailed` - Represents a signature verification failure. Wraps a `VerificationError`.
/// * `DbInternalError` - Represents an internal database error. Contains a descriptive message.
/// * `IdNotFound` - Indicates that a specific user ID was not found. Contains the missing user ID.
/// * `UsernameAlreadyExists` - Indicates that a given username already exists. Contains the conflicting username.
/// * `InvalidCertReq` - Indicates an invalid request for certificate generation.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// Indicates an invalid data length, specifying the expected and actual lengths.
    #[error("Invalid length: expected {0} bytes, found {1} bytes")]
    BadLength(usize, usize),
    /// Represents an error in converting an object into a byte slice due to an incorrect length.
    /// This error is mostly created by converting from `std::array::TryFromSliceError`.
    #[error("Failed to convert into byte slice due to the bad length: {0}")]
    IntoBytesBadLength(String),
    /// Represents an error in converting a byte slice into an object due to an incorrect length.
    /// This error is mostly created by converting from `pqcrypto_traits::Error`.
    #[error("Failed to convert from byte slice due to the bad length: {0}")]
    FromBytesBadLength(String),
    /// Indicates that a signature verification operation failed. Wraps a [`VerificationError`].
    #[error("Signature verification failed: {0}")]
    VerificationFailed(#[from] VerificationError),
    /// Represents an internal error in the database, with a descriptive error message.
    /// This can also be treated as user-provided error type that indicates any error caused by
    /// the implemented database.
    #[error("Database internal error: {0}")]
    DbInternalError(String),
    /// Indicates that a specific user ID could not be located.
    #[error("User ID '{0}' not found")]
    IdNotFound(u64),
    /// Represents a conflict where a username already exists in the system.
    #[error("Given username '{0}' already exists")]
    UsernameAlreadyExists(String),
    /// Indicates that a certificate generation request was invalid, mostly caused by revocation.
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

/// Represents errors related to signature verification.
///
/// This enum defines errors specific to the signature verification process, such as
/// issues with SPHINCS+ signature validation or revoked signatures.
///
/// # Variants
///
/// * `SphincsPlusVerificationFailed` - Indicates a failure in verifying a SPHINCS+ signature. Contains a descriptive error message.
/// * `RevokedSignature` - Indicates that the signature has been revoked.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// Represents an error in verifying a SPHINCS+ signature. Contains a descriptive error message.
    /// This error is mostly created by converting from `pqcrypto_traits::sign::VerificationError`.
    #[error("SPHINCS+ verification failed: {0}")]
    SphincsPlusVerificationFailed(String),
    /// Indicates that the signature has been revoked and is no longer valid.
    #[error("Signature is revoked")]
    RevokedSignature,
}

impl From<pqcrypto_traits::sign::VerificationError> for VerificationError {
    fn from(e: pqcrypto_traits::sign::VerificationError) -> Self {
        VerificationError::SphincsPlusVerificationFailed(e.to_string())
    }
}
