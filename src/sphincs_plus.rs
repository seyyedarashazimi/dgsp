//! # SPHINCS+ Rust Wrapper for Post-Quantum Group Signatures
//!
//! This module provides a Rust wrapper for the SPHINCS+ digital signature scheme using the
//! [`pqcrypto-sphincsplus`](https://crates.io/crates/pqcrypto-sphincsplus) crate. This wrapper
//! simplifies the use of SPHINCS+ as part of a post-quantum group signature scheme, abstracting the
//! underlying C-based implementations provided by [PQClean](https://github.com/PQClean/PQClean/).
//!
//! The `Sphincs` struct is the main interface for generating keypairs, signing messages, and
//! verifying signatures. It supports a variety of parameter sets, each offering different
//! trade-offs between performance, signature size, and security level.
//!
//! ## Features
//!
//! - **Memory Safety**: Leverages Rust's memory safety features and the `Zeroize` trait to ensure
//!   that sensitive cryptographic materials are securely erased when no longer needed.
//! - **Parameterized Configurations**: Supports all SPHINCS+ variants, including different
//!   security levels (128, 192, and 256 bits) and optimizations for speed or signature size.
//! - **Idiomatically Rust**: Provides high-level methods to manage keys and signatures using
//!   standard Rust data types, avoiding the need for low-level foreign function interface (FFI)
//!   interactions.
//!
//! ## SPHINCS+ Overview
//!
//! SPHINCS+ is a stateless hash-based post-quantum signature scheme designed to provide long-term
//! security against attacks by quantum computers. It is ideal for applications where resilience to
//! both classical and quantum adversaries is necessary.
//!
//! This wrapper includes SPHINCS+ variants with either SHAKE or SHA-256 hash functions, available
//! at security levels of 128, 192, and 256 bits. Each variant is additionally available in `fast` (`F`)
//! or `small` (`S`) configurations, depending on the optimization goal.
//!
//! ## Supported Variants
//!
//! The following SPHINCS+ variants are supported, each representing a combination of hash function
//! and optimization type:
//!
//! - **SHAKE (at 128, 192, 256-bit levels)**: `F` (Fast) or `S` (Small).
//! - **SHA-256 (at 128, 192, 256-bit levels)**: `F` (Fast) or `S` (Small).
//!
//! The `SphincsType` enum captures these different variants, and users can select the desired
//! configuration based on specific requirements.
//!
//! ## Usage Example
//!
//! ### Generating a Keypair
//!
//! ```rust
//! use dgsp::sphincs_plus::SphincsPlus;
//!
//! // Instantiate a SPHINCS+ wrapper for SHAKE-128 with fast optimization.
//! let sphincs = SphincsPlus::default();
//!
//! // Generate a keypair (public and secret keys).
//! let (public_key, secret_key) = sphincs.keygen().expect("Key generation failed");
//! println!("Generated public key: {:?}", public_key);
//! ```
//!
//! ### Signing a Message
//!
//! ```rust
//! use dgsp::sphincs_plus::SphincsPlus;
//!
//! let sphincs = SphincsPlus::default();
//! let (_, secret_key) = sphincs.keygen().expect("Key generation failed");
//!
//! let message = b"DGSP post-quantum group signature message";
//! let signature = sphincs.sign(message, &secret_key).expect("Signing failed");
//! println!("Generated signature: {:?}", signature);
//! ```
//!
//! ### Verifying a Signature
//!
//! ```rust
//! use dgsp::sphincs_plus::SphincsPlus;
//!
//! let sphincs = SphincsPlus::default();
//! let (public_key, secret_key) = sphincs.keygen().expect("Key generation failed");
//!
//! let message = b"DGSP post-quantum group signature message";
//! let signature = sphincs.sign(message, &secret_key).expect("Signing failed");
//!
//! // Verify the generated signature.
//! let is_valid = sphincs.verify(&signature, message, &public_key).is_ok();
//! assert!(is_valid, "Signature verification failed");
//! println!("Signature is valid!");
//! ```
//!
//! ## API Overview
//!
//! - **`Sphincs`**: Main struct representing the SPHINCS+ scheme. Allows for generating keypairs,
//!   signing messages, and verifying signatures.
//! - **`SphincsType`**: Enum representing the supported SPHINCS+ variants, including different hash
//!   functions, security levels, and optimization options.
//! - **`SphincsData`**: A wrapper around `Vec<u8>` used for securely holding cryptographic data,
//!   with automatic memory zeroization when dropped.
//!
//! ## Security Considerations
//!
//! - **Sensitive Data Handling**: The `SphincsData` struct is used to hold sensitive information,
//!   such as secret keys. It automatically zeroizes memory when instances are dropped to reduce
//!   the risk of exposing cryptographic material.
//! - **Cloning Sensitivity**: Cloning of `SphincsData` is supported but should be done cautiously,
//!   as it duplicates sensitive information in memory.
//! - **Quantum Resistance**: SPHINCS+ is resistant to attacks from both classical and quantum computers,
//!   making it a good choice for future-proof cryptographic systems.
//!
//! ## Dependencies
//!
//! - **[`pqcrypto-sphincsplus`](https://crates.io/crates/pqcrypto-sphincsplus)**: Provides Rust bindings to
//!   the C implementations of SPHINCS+ from PQClean.
//! - **[`PQClean`](https://github.com/PQClean/PQClean/)**: Supplies the underlying C implementations
//!   of cryptographic algorithms, focusing on ensuring correctness and security through well-reviewed code.
//! - **`Zeroize`**: Ensures sensitive cryptographic material is securely wiped from memory when no
//!   longer needed.
//!
//! ## Custom Macros for Simplification
//!
//! This crate uses custom macros to simplify the implementation of keypair generation, signature creation,
//! and verification for each `SphincsType` variant. These macros (`gen_sphincs_keypair`, `gen_sphincs_detached_sign`,
//! and `gen_sphincs_verify_detached_signature`) reduce boilerplate code and ensure consistency across all variants.
//!
//! ## Errors
//!
//! - **`SphincsError`**: Custom error type that handles issues such as mismatched key sizes and signature
//!   verification failures. All functions that may fail return `Result` to facilitate idiomatic error handling in Rust.
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
//! ## License
//!
//! This module is distributed under the MIT License. See `LICENSE` for more information.
//!
//! ## Acknowledgements
//!
//! This wrapper relies on the work of the PQClean project and the `pqcrypto` crate series for providing
//! robust, post-quantum cryptographic primitives in a safe and accessible manner.
//!
//! The macros and abstractions provided in this wrapper are also inspired by the need for usability in
//! building complex cryptographic protocols, such as post-quantum group signature schemes.

use crate::errors::SphincsError;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::Zeroize;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

#[cfg(feature = "sphincs_sha2_128f")]
use crate::sphincs_plus::params_sphincs_sha2_128f::*;
#[cfg(feature = "sphincs_sha2_128s")]
use crate::sphincs_plus::params_sphincs_sha2_128s::*;
#[cfg(feature = "sphincs_sha2_192f")]
use crate::sphincs_plus::params_sphincs_sha2_192f::*;
#[cfg(feature = "sphincs_sha2_192s")]
use crate::sphincs_plus::params_sphincs_sha2_192s::*;
#[cfg(feature = "sphincs_sha2_256f")]
use crate::sphincs_plus::params_sphincs_sha2_256f::*;
#[cfg(feature = "sphincs_sha2_256s")]
use crate::sphincs_plus::params_sphincs_sha2_256s::*;
#[cfg(feature = "sphincs_shake_128f")]
use crate::sphincs_plus::params_sphincs_shake_128f::*;
#[cfg(feature = "sphincs_shake_128s")]
use crate::sphincs_plus::params_sphincs_shake_128s::*;
#[cfg(feature = "sphincs_shake_192f")]
use crate::sphincs_plus::params_sphincs_shake_192f::*;
#[cfg(feature = "sphincs_shake_192s")]
use crate::sphincs_plus::params_sphincs_shake_192s::*;
#[cfg(feature = "sphincs_shake_256f")]
use crate::sphincs_plus::params_sphincs_shake_256f::*;
#[cfg(feature = "sphincs_shake_256s")]
use crate::sphincs_plus::params_sphincs_shake_256s::*;

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

#[cfg(feature = "sphincs_sha2_128f")]
pub mod params_sphincs_sha2_128f;
#[cfg(feature = "sphincs_sha2_128s")]
pub mod params_sphincs_sha2_128s;
#[cfg(feature = "sphincs_sha2_192f")]
pub mod params_sphincs_sha2_192f;
#[cfg(feature = "sphincs_sha2_192s")]
pub mod params_sphincs_sha2_192s;
#[cfg(feature = "sphincs_sha2_256f")]
pub mod params_sphincs_sha2_256f;
#[cfg(feature = "sphincs_sha2_256s")]
pub mod params_sphincs_sha2_256s;
#[cfg(feature = "sphincs_shake_128f")]
pub mod params_sphincs_shake_128f;
#[cfg(feature = "sphincs_shake_128s")]
pub mod params_sphincs_shake_128s;
#[cfg(feature = "sphincs_shake_192f")]
pub mod params_sphincs_shake_192f;
#[cfg(feature = "sphincs_shake_192s")]
pub mod params_sphincs_shake_192s;
#[cfg(feature = "sphincs_shake_256f")]
pub mod params_sphincs_shake_256f;
#[cfg(feature = "sphincs_shake_256s")]
pub mod params_sphincs_shake_256s;

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
pub mod sha2_offsets;
#[cfg(any(
    feature = "sphincs_shake_128f",
    feature = "sphincs_shake_128s",
    feature = "sphincs_shake_192f",
    feature = "sphincs_shake_192s",
    feature = "sphincs_shake_256f",
    feature = "sphincs_shake_256s",
))]
pub mod shake_offsets;

const CRYPTO_PUBLICKEYBYTES: usize = SPX_PK_BYTES;
const CRYPTO_SECRETKEYBYTES: usize = SPX_SK_BYTES;
const CRYPTO_BYTES: usize = SPX_BYTES;
// const CRYPTO_SEEDBYTES: usize = 3 * SPX_N;

// #[derive(Copy, Clone, Default, Debug)]
// pub struct SphincsContext {
//     pub pub_seed: [u8; SPX_N],
//     pub sk_seed: [u8; SPX_N],
// }

/// `SphincsPlusPublicKey` securely holds public-key for the SPHINCS+ signature scheme, using a
/// `u8; CRYPTO_PUBLICKEYBYTES` internal field.
/// This struct implements `Zeroize`, ensuring the data is wiped from memory when dropped (`#[zeroize(drop)]`).
// Cloning is supported but should be done cautiously, as it duplicates sensitive information in memory.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct SphincsPlusPublicKey(
    #[cfg_attr(feature = "serialization", serde(with = "BigArray"))] [u8; CRYPTO_PUBLICKEYBYTES],
);

impl AsRef<[u8]> for SphincsPlusPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SphincsPlusPublicKey {
    type Error = SphincsError;
    fn try_from(data: &[u8]) -> Result<SphincsPlusPublicKey, SphincsError> {
        if data.len() != CRYPTO_PUBLICKEYBYTES {
            Err(SphincsError::BadLength(CRYPTO_PUBLICKEYBYTES, data.len()))
        } else {
            let mut array = [0u8; CRYPTO_PUBLICKEYBYTES];
            array.copy_from_slice(data);
            Ok(SphincsPlusPublicKey(array))
        }
    }
}

/// `SphincsPlusSecretKey` securely holds public-key for the SPHINCS+ signature scheme, using a
/// `u8; CRYPTO_SECRETKEYBYTES` internal field.
/// This struct implements `Zeroize`, ensuring the data is wiped from memory when dropped (`#[zeroize(drop)]`).
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct SphincsPlusSecretKey(
    #[cfg_attr(feature = "serialization", serde(with = "BigArray"))] [u8; CRYPTO_SECRETKEYBYTES],
);

impl AsRef<[u8]> for SphincsPlusSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SphincsPlusSecretKey {
    type Error = SphincsError;
    fn try_from(data: &[u8]) -> Result<SphincsPlusSecretKey, SphincsError> {
        if data.len() != CRYPTO_SECRETKEYBYTES {
            Err(SphincsError::BadLength(CRYPTO_SECRETKEYBYTES, data.len()))
        } else {
            let mut array = [0u8; CRYPTO_SECRETKEYBYTES];
            array.copy_from_slice(data);
            Ok(SphincsPlusSecretKey(array))
        }
    }
}

/// `SphincsPlusSignature` securely holds public-key for the SPHINCS+ signature scheme, using a
/// `u8; CRYPTO_BYTES` internal field.
/// This struct implements `Zeroize`, ensuring the data is wiped from memory when dropped (`#[zeroize(drop)]`).
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct SphincsPlusSignature(
    #[cfg_attr(feature = "serialization", serde(with = "BigArray"))] [u8; CRYPTO_BYTES],
);

impl AsRef<[u8]> for SphincsPlusSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SphincsPlusSignature {
    type Error = SphincsError;
    fn try_from(data: &[u8]) -> Result<SphincsPlusSignature, SphincsError> {
        if data.len() != CRYPTO_BYTES {
            Err(SphincsError::BadLength(CRYPTO_BYTES, data.len()))
        } else {
            let mut array = [0u8; CRYPTO_BYTES];
            array.copy_from_slice(data);
            Ok(SphincsPlusSignature(array))
        }
    }
}

/// `SphincsPlus` is a wrapper around the SPHINCS+ post-quantum signature scheme, providing an
/// easy-to-use API for generating keypairs, signing messages, and verifying signatures. It supports
/// multiple variants of the SPHINCS+ scheme, which offer different trade-offs between security,
/// speed, and signature size.
pub struct SphincsPlus;

impl Default for SphincsPlus {
    fn default() -> Self {
        Self::new()
    }
}

impl SphincsPlus {
    /// Creates `SphincsPlus` instance based on the active SPHINCS+ feature.
    /// It also sets the length of the public-key, secret-key, and signature byte sizes based on the
    /// given SPHINCS+ type.
    pub fn new() -> Self {
        SphincsPlus
    }

    /// Generate (pk, sk) keypair of SPHINCS+ for an instance of `SphincsPlus`.
    pub fn keygen(&self) -> Result<(SphincsPlusPublicKey, SphincsPlusSecretKey), SphincsError> {
        let (pk, sk) = keypair();
        Ok((pk.as_bytes().try_into()?, sk.as_bytes().try_into()?))
    }

    /// Calculate the SPHINCS+ signature for a given `SphincsPlus` instance, based on the given
    /// message and secret-key.
    pub fn sign(
        &self,
        message: &[u8],
        sk: &SphincsPlusSecretKey,
    ) -> Result<SphincsPlusSignature, SphincsError> {
        detached_sign(message, &SecretKey::from_bytes(sk.as_ref())?)
            .as_bytes()
            .try_into()
    }

    /// Verify the SPHINCS+ signature for a given `SphincsPlus` instance, based on the given message
    /// and public-key.
    ///
    /// It returns `Err(SphincsError)` if the there is an error either about wrong data length or if
    /// the signature is invalid. Otherwise, if the signature is valid for the given message, it
    /// returns `Ok(())`, showing the validity of the given signature.
    pub fn verify(
        &self,
        signature: &SphincsPlusSignature,
        message: &[u8],
        pk: &SphincsPlusPublicKey,
    ) -> Result<(), SphincsError> {
        Ok(verify_detached_signature(
            &DetachedSignature::from_bytes(signature.as_ref())?,
            message,
            &PublicKey::from_bytes(pk.as_ref())?,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_sphincs_plus() {
        let sp = SphincsPlus::new();

        let kg = sp.keygen();
        assert!(kg.is_ok());
        let (pk, sk) = kg.unwrap();

        let mut rng = thread_rng();
        let len: u16 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let signing = sp.sign(&message, &sk);
        assert!(signing.is_ok());
        let signature = signing.unwrap();

        assert!(sp.verify(&signature, &message, &pk).is_ok());

        let mut fake_signature = signature.clone();
        fake_signature.0[0] ^= 1;

        assert!(matches!(
            sp.verify(&fake_signature, &message, &pk),
            Err(SphincsError::VerificationFailed(_))
        ));
        println!("SPHINCS+ wrapper keygen, signing, and verify tests passed.");
    }
}
