//! # SPHINCS+ Rust Wrapper for Post-Quantum Group Signatures
//!
//! This module provides a Rust wrapper for the SPHINCS+ digital signature scheme using the
//! [`pqcrypto-sphincsplus`](https://crates.io/crates/pqcrypto-sphincsplus) crate. This wrapper
//! simplifies the use of SPHINCS+ as part of a post-quantum group signature scheme, abstracting the
//! underlying C-based implementations provided by [PQClean](https://github.com/PQClean/PQClean/).
//!
//! The `SphincsPlus` struct is the main interface for generating keypairs, signing messages, and
//! verifying signatures. It supports a variety of parameter sets, each offering different
//! trade-offs between performance, signature size, and security level.
//!
//! ## Features
//!
//! - **Memory Safety**: Leverages Rust's memory safety features and the `Zeroize` trait to ensure
//!   that sensitive cryptographic materials are securely erased when no longer needed.
//! - **Parameterized Configurations**: Supports all SPHINCS+ variants, including different
//!   security levels (128, 192, and 256 bits) and optimizations for speed or signature size,
//!   as well as the choice of underlying hash function (SHA-2 or SHAKE).
//! - **Idiomatically Rust**: Provides high-level methods to manage keys and signatures using
//!   standard Rust data types, avoiding the need for low-level foreign function interface (FFI)
//!   interactions.
//!
//! ## SPHINCS+ Overview
//!
//! SPHINCS+ is a stateless hash-based post-quantum signature scheme designed to provide long-term
//! security against quantum computers. It is ideal for applications where resilience to both
//! classical and quantum adversaries is necessary.
//!
//! This wrapper includes SPHINCS+ variants with either SHAKE or SHA-2 hash functions, available
//! at security levels of 128, 192, and 256 bits. Each variant is additionally available in
//! `fast`(`F`) or `small`(`S`) configurations, depending on the optimization goal.
//!
//! ## Supported Variants
//!
//! The following SPHINCS+ variants are supported, each representing a combination of hash function
//! and optimization type:
//!
//! - **SHAKE (at 128, 192, 256-bit levels)**: `F` (Fast) or `S` (Small).
//! - **SHA-2 (at 128, 192, 256-bit levels)**: `F` (Fast) or `S` (Small).
//!
//! To specify a SPHINCS+ variant, enable the appropriate feature from the feature set provided by
//! the `dgsp` crate.
//!
//! ## Usage Example
//!
//! ### Generating a Keypair
//!
//! ```rust
//! use dgsp::sphincs_plus::SphincsPlus;
//!
//! let (public_key, secret_key) = SphincsPlus::keygen().expect("Key generation failed");
//! ```
//!
//! ### Signing a Message
//!
//! ```rust
//! use dgsp::sphincs_plus::SphincsPlus;
//!
//! let (_, secret_key) = SphincsPlus::keygen().expect("Key generation failed");
//!
//! let message = b"DGSP post-quantum group signature message.";
//! let signature = SphincsPlus::sign(message, &secret_key).expect("Signing failed");
//! ```
//!
//! ### Verifying a Signature
//!
//! ```rust
//! use dgsp::sphincs_plus::SphincsPlus;
//!
//! let (public_key, secret_key) = SphincsPlus::keygen().expect("Key generation failed");
//!
//! let message = b"DGSP post-quantum group signature message.";
//! let signature = SphincsPlus::sign(message, &secret_key).expect("Signing failed");
//!
//! let is_valid = SphincsPlus::verify(&signature, message, &public_key).is_ok();
//! assert!(is_valid);
//! ```
//!
//! ## API Overview
//!
//! - **`SphincsPlus`**: Main struct representing the SPHINCS+ scheme. Allows for generating
//!   keypairs, signing messages, and verifying signatures.
//! - **`SphincsPlusPublicKey`**: A wrapper around `[u8, SPX_PK_BYTES]` used for securely holding
//!   SPHINCS+ public-key with automatic memory zeroization when dropped.
//! - **`SphincsPlusSecretKey`**: A wrapper around `[u8, SPX_SK_BYTES]` used for securely holding
//!   SPHINCS+ secret-key with automatic memory zeroization when dropped.
//! - **`SphincsPlusSignature`**: A wrapper around `[u8, SPX_BYTES]` used for securely holding
//!   SPHINCS+ signature with automatic memory zeroization when dropped.
//!
//! ## Security Considerations
//!
//! - **Sensitive Data Handling**: The SPHINCS+ data types are used to hold sensitive information,
//!   such as secret key. It automatically zeroizes memory when instances are dropped to reduce
//!   the risk of exposing cryptographic material.
//! - **Cloning Sensitivity**: Cloning of SPHINCS+ data types is supported but should be done
//!   cautiously, as it duplicates sensitive information in memory.
//! - **Quantum Resistance**: SPHINCS+ is resistant against both classical and quantum computers,
//!   making it a good choice for future-proof cryptographic systems.
//!
//! ## Dependencies
//!
//! - **[`pqcrypto-sphincsplus`](https://crates.io/crates/pqcrypto-sphincsplus)**: Provides Rust
//!   bindings to the C implementations of SPHINCS+ from PQClean.
//! - **[`PQClean`](https://github.com/PQClean/PQClean/)**: Supplies the underlying C
//!   implementations of cryptographic algorithms, focusing on ensuring correctness and security
//!   through well-reviewed code.
//! - **`zeroize`**: Ensures sensitive cryptographic material is securely wiped from memory when no
//!   longer needed.
//! - **`serde`**: when `serialization` feature is active for dgsp crate, this wrapper uses `serde`,
//!   `serde_big_array`, and `bincode` to serialize the data types.
//!
//! ## Example Walkthrough
//!
//! To generate a keypair, sign a message, and verify a signature:
//!
//! 1. **Create an Instance**: Instantiate a `Sphincs` object for the desired SPHINCS+ variant.
//! 2. **Key Generation**: Use the `keygen()` method to generate a public and secret key.
//! 3. **Sign the Message**: Use the `sign()` method with the message and secret key.
//! 4. **Verify the Signature**: Use the `verify()` method with the signature, message, and public key.
//!
//! ## Acknowledgements
//!
//! This wrapper relies on the work of the PQClean project and the `pqcrypto` crate series for
//! providing robust, post-quantum cryptographic primitives in a safe and accessible manner.
//!
//! The abstractions provided in this wrapper are also inspired by the need for usability in
//! building complex cryptographic protocols, such as the DGSP post-quantum group signature scheme.

use crate::utils::array_struct;
use crate::{Error, Result, VerificationError};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::Zeroize;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

#[cfg(any(feature = "sphincs_shake_128f", feature = "sphincs_sha2_128f"))]
pub use crate::sphincs_plus::params_sphincs_128f::*;
#[cfg(any(feature = "sphincs_shake_128s", feature = "sphincs_sha2_128s"))]
pub use crate::sphincs_plus::params_sphincs_128s::*;
#[cfg(any(feature = "sphincs_shake_192f", feature = "sphincs_sha2_192f"))]
pub use crate::sphincs_plus::params_sphincs_192f::*;
#[cfg(any(feature = "sphincs_shake_192s", feature = "sphincs_sha2_192s"))]
pub use crate::sphincs_plus::params_sphincs_192s::*;
#[cfg(any(feature = "sphincs_shake_256f", feature = "sphincs_sha2_256f"))]
pub use crate::sphincs_plus::params_sphincs_256f::*;
#[cfg(any(feature = "sphincs_shake_256s", feature = "sphincs_sha2_256s"))]
pub use crate::sphincs_plus::params_sphincs_256s::*;

#[cfg(feature = "sphincs_sha2_128f")]
use pqcrypto_sphincsplus::sphincssha2128fsimple::*;
#[cfg(feature = "sphincs_sha2_128s")]
use pqcrypto_sphincsplus::sphincssha2128ssimple::*;
#[cfg(feature = "sphincs_sha2_192f")]
use pqcrypto_sphincsplus::sphincssha2192fsimple::*;
#[cfg(feature = "sphincs_sha2_192s")]
use pqcrypto_sphincsplus::sphincssha2192ssimple::*;
#[cfg(feature = "sphincs_sha2_256f")]
use pqcrypto_sphincsplus::sphincssha2256fsimple::*;
#[cfg(feature = "sphincs_sha2_256s")]
use pqcrypto_sphincsplus::sphincssha2256ssimple::*;
#[cfg(feature = "sphincs_shake_128f")]
use pqcrypto_sphincsplus::sphincsshake128fsimple::*;
#[cfg(feature = "sphincs_shake_128s")]
use pqcrypto_sphincsplus::sphincsshake128ssimple::*;
#[cfg(feature = "sphincs_shake_192f")]
use pqcrypto_sphincsplus::sphincsshake192fsimple::*;
#[cfg(feature = "sphincs_shake_192s")]
use pqcrypto_sphincsplus::sphincsshake192ssimple::*;
#[cfg(feature = "sphincs_shake_256f")]
use pqcrypto_sphincsplus::sphincsshake256fsimple::*;
#[cfg(feature = "sphincs_shake_256s")]
use pqcrypto_sphincsplus::sphincsshake256ssimple::*;

#[cfg(any(feature = "sphincs_shake_128f", feature = "sphincs_sha2_128f"))]
mod params_sphincs_128f;
#[cfg(any(feature = "sphincs_shake_128s", feature = "sphincs_sha2_128s"))]
mod params_sphincs_128s;
#[cfg(any(feature = "sphincs_shake_192f", feature = "sphincs_sha2_192f"))]
mod params_sphincs_192f;
#[cfg(any(feature = "sphincs_shake_192s", feature = "sphincs_sha2_192s"))]
mod params_sphincs_192s;
#[cfg(any(feature = "sphincs_shake_256f", feature = "sphincs_sha2_256f"))]
mod params_sphincs_256f;
#[cfg(any(feature = "sphincs_shake_256s", feature = "sphincs_sha2_256s"))]
mod params_sphincs_256s;

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
mod sha2_offsets;
#[cfg(any(
    feature = "sphincs_shake_128f",
    feature = "sphincs_shake_128s",
    feature = "sphincs_shake_192f",
    feature = "sphincs_shake_192s",
    feature = "sphincs_shake_256f",
    feature = "sphincs_shake_256s",
))]
mod shake_offsets;

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
pub use crate::sphincs_plus::sha2_offsets::*;
#[cfg(any(
    feature = "sphincs_shake_128f",
    feature = "sphincs_shake_128s",
    feature = "sphincs_shake_192f",
    feature = "sphincs_shake_192s",
    feature = "sphincs_shake_256f",
    feature = "sphincs_shake_256s",
))]
pub use crate::sphincs_plus::shake_offsets::*;

array_struct!(SphincsPlusPublicKey, SPX_PK_BYTES);
array_struct!(SphincsPlusSecretKey, SPX_SK_BYTES);
array_struct!(SphincsPlusSignature, SPX_BYTES);

/// `SphincsPlus` is a wrapper around the SPHINCS+ post-quantum signature scheme, providing an
/// easy-to-use API for generating keypairs, signing messages, and verifying signatures. It supports
/// multiple variants of the SPHINCS+ scheme, which offer different trade-offs between security,
/// speed, and signature size.
pub struct SphincsPlus;

impl SphincsPlus {
    /// Generates (public-key, secret-key) keypair for SPHINCS+ signature scheme.
    ///
    /// # Returns
    ///
    /// A `Result` containing:
    /// * `Ok((SphincsPlusPublicKey, SphincsPlusSecretKey))` - The generated keypair, consisting
    ///   of the public and secret keys.
    /// * `Err(Error)` - If an error occurs during key generation or conversion.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dgsp::sphincs_plus::{SphincsPlus, SphincsPlusPublicKey, SphincsPlusSecretKey};
    ///
    /// match SphincsPlus::keygen() {
    ///     Ok((public_key, secret_key)) => {
    ///         println!("Public Key: {:?}", public_key);
    ///         println!("Secret Key: {:?}", secret_key);
    ///     }
    ///     Err(e) => eprintln!("Key generation failed: {:?}", e),
    /// }
    /// ```
    pub fn keygen() -> Result<(SphincsPlusPublicKey, SphincsPlusSecretKey)> {
        let (pk, sk) = keypair();
        Ok((pk.as_bytes().try_into()?, sk.as_bytes().try_into()?))
    }

    /// Signs a message using the provided SPHINCS+ secret key.
    ///
    /// This function calculates the SPHINCS+ signature for the given message using
    /// the specified secret key. The signature is generated using the detached
    /// signing mechanism provided by the `detached_sign` function.
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice representing the message to be signed.
    /// * `sk` - A reference to the SPHINCS+ secret key used for signing.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// * `Ok(SphincsPlusSignature)` - If the signature generation is successful.
    /// * `Err(Error)` - If there is an error during the signing process, such as an
    ///   invalid key conversion because of incorrect length.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dgsp::sphincs_plus::{SphincsPlus, SphincsPlusSecretKey};
    ///
    /// let message = b"Hello, SPHINCS+!";
    /// let (_,secret_key) = SphincsPlus::keygen().unwrap();
    ///
    /// match SphincsPlus::sign(message, &secret_key) {
    ///     Ok(signature) => println!("Signature: {:?}", signature),
    ///     Err(e) => eprintln!("Signing failed: {:?}", e),
    /// }
    /// ```
    pub fn sign(message: &[u8], sk: &SphincsPlusSecretKey) -> Result<SphincsPlusSignature> {
        detached_sign(message, &SecretKey::from_bytes(sk.as_ref())?)
            .as_bytes()
            .try_into()
    }

    /// Verifies a SPHINCS+ signature for a given message and public key.
    ///
    /// This function checks the validity of a SPHINCS+ signature for the specified message
    /// using the provided public key. It uses the detached signature verification mechanism.
    ///
    /// # Arguments
    ///
    /// * `signature` - A reference to the SPHINCS+ signature to be verified.
    /// * `message` - A byte slice containing the message that was signed.
    /// * `pk` - A reference to the SPHINCS+ public key corresponding to the signature.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the outcome of the verification:
    /// * `Ok(())` - If the signature is valid for the given message and public key.
    /// * `Err(SphincsError)` - If the signature is invalid, or if an error occurs due to
    ///   incorrect data length or other issues during verification.
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// * The signature or public key has an incorrect length.
    /// * The signature is invalid for the given message and public key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dgsp::sphincs_plus::{SphincsPlus, SphincsPlusSignature, SphincsPlusPublicKey};
    ///
    /// let message = b"Hello, SPHINCS+!";
    /// let (public_key,secret_key) = SphincsPlus::keygen().unwrap();
    /// let signature = SphincsPlus::sign(message, &secret_key).unwrap();
    ///
    /// match SphincsPlus::verify(&signature, message, &public_key) {
    ///     Ok(()) => println!("Signature is valid."),
    ///     Err(e) => eprintln!("Signature verification failed: {:?}", e),
    /// }
    /// ```
    pub fn verify(
        signature: &SphincsPlusSignature,
        message: &[u8],
        pk: &SphincsPlusPublicKey,
    ) -> Result<()> {
        Ok(verify_detached_signature(
            &DetachedSignature::from_bytes(signature.as_ref())?,
            message,
            &PublicKey::from_bytes(pk.as_ref())?,
        )
        .map_err(|e| VerificationError::SphincsPlusVerificationFailed(e.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_sphincs_plus() {
        let kg = SphincsPlus::keygen();
        assert!(kg.is_ok());
        let (pk, sk) = kg.unwrap();

        let mut rng = thread_rng();
        let len: u8 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let signing = SphincsPlus::sign(&message, &sk);
        assert!(signing.is_ok());
        let signature = signing.unwrap();

        assert!(SphincsPlus::verify(&signature, &message, &pk).is_ok());

        let mut fake_signature = signature.clone();
        fake_signature.0[0] ^= 1;

        assert!(matches!(
            SphincsPlus::verify(&fake_signature, &message, &pk),
            Err(Error::VerificationFailed(_))
        ));
        println!("SPHINCS+ wrapper keygen, signing, and verify tests passed.");
    }
}
