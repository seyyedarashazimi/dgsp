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
//! use dgsp::sphincs_plus::{SphincsPlus, SphincsPlusType};
//!
//! // Instantiate a SPHINCS+ wrapper for SHAKE-128 with fast optimization.
//! let sphincs = SphincsPlus::new(SphincsPlusType::SPHINCSSHAKE128F);
//!
//! // Generate a keypair (public and secret keys).
//! let (public_key, secret_key) = sphincs.keygen().expect("Key generation failed");
//! println!("Generated public key: {:?}", public_key);
//! ```
//!
//! ### Signing a Message
//!
//! ```rust
//! use dgsp::sphincs_plus::{SphincsPlus, SphincsPlusType, SphincsPlusData};
//!
//! let sphincs = SphincsPlus::new(SphincsPlusType::SPHINCSSHAKE128F);
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
//! use dgsp::sphincs_plus::{SphincsPlus, SphincsPlusType, SphincsPlusData};
//!
//! let sphincs = SphincsPlus::new(SphincsPlusType::SPHINCSSHAKE128F);
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
use pqcrypto_sphincsplus::ffi::*;
use pqcrypto_sphincsplus::*;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::Zeroize;

/// The available hash functions provided by [PQClean](https://github.com/PQClean/PQClean/) project
/// for SPHINCS+.
/// Represents the available hash function variants for the SPHINCS+ signature scheme, as provided by
/// the [PQClean](https://github.com/PQClean/PQClean/) project.
///
/// # Overview
///
/// `SphincsType` enumerates the supported SPHINCS+ parameter sets, including different hash functions
/// and security levels such as `SHAKE` and `SHA2`. Each variant corresponds to a specific configuration
/// of the SPHINCS+ scheme with either `fast` (f) or `small` (s) optimizations, and different hash functions.
///
/// # Variants
///
/// - `SPHINCSSHAKE128F`, `SPHINCSSHAKE128S`: Uses the SHAKE-128 hash function with either `fast` or `small` settings.
/// - `SPHINCSSHAKE192F`, `SPHINCSSHAKE192S`: Uses the SHAKE-192 hash function with either `fast` or `small` settings.
/// - `SPHINCSSHAKE256F`, `SPHINCSSHAKE256S`: Uses the SHAKE-256 hash function with either `fast` or `small` settings.
/// - `SPHINCSSHA2128F`, `SPHINCSSHA2128S`: Uses the SHA-256 hash function at 128-bit security level with either `fast` or `small` settings.
/// - `SPHINCSSHA2192F`, `SPHINCSSHA2192S`: Uses the SHA-256 hash function at 192-bit security level with either `fast` or `small` settings.
/// - `SPHINCSSHA2256F`, `SPHINCSSHA2256S`: Uses the SHA-256 hash function at 256-bit security level with either `fast` or `small` settings.
///
/// The `F` (fast) and `S` (small) suffixes indicate whether the parameter set optimizes for speed
/// (`F` - fast) or memory efficiency (`S` - small).
///
/// # Methods
///
/// `SphincsType` provides methods to retrieve parameters related to each variant of the SPHINCS+ scheme, such as:
///
/// - **`crypto_publickey_bytes()`**: Returns the size of the public key in bytes.
/// - **`crypto_secretkey_bytes()`**: Returns the size of the secret key in bytes.
/// - **`crypto_bytes()`**: Returns the size of the signature in bytes.
///
/// # References
///
/// For more information about SPHINCS+, refer to:
/// - [PQClean GitHub Repository](https://github.com/PQClean/PQClean/)
/// - [SPHINCS+ Specification](https://sphincs.org/)
#[derive(Copy, Clone, Debug)]
#[repr(usize)]
pub enum SphincsPlusType {
    /// sphincs-shake-128f-simple - clean/avx2(if supported)
    SPHINCSSHAKE128F,
    /// sphincs-shake-128s-simple - clean/avx2(if supported)
    SPHINCSSHAKE128S,
    /// sphincs-shake-192f-simple - clean/avx2(if supported)
    SPHINCSSHAKE192F,
    /// sphincs-shake-192s-simple - clean/avx2(if supported)
    SPHINCSSHAKE192S,
    /// sphincs-shake-256f-simple - clean/avx2(if supported)
    SPHINCSSHAKE256F,
    /// sphincs-shake-256s-simple - clean/avx2(if supported)
    SPHINCSSHAKE256S,
    /// sphincs-sha2-128f-simple - clean/avx2(if supported)
    SPHINCSSHA2128F,
    /// sphincs-sha2-128s-simple - clean/avx2(if supported)
    SPHINCSSHA2128S,
    /// sphincs-sha2-192f-simple - clean/avx2(if supported)
    SPHINCSSHA2192F,
    /// sphincs-sha2-192s-simple - clean/avx2(if supported)
    SPHINCSSHA2192S,
    /// sphincs-sha2-256f-simple - clean/avx2(if supported)
    SPHINCSSHA2256F,
    /// sphincs-sha2-256s-simple - clean/avx2(if supported)
    SPHINCSSHA2256S,
}

impl SphincsPlusType {
    pub fn crypto_publickey_bytes(&self) -> usize {
        const PUBLICKEY_BYTES: [usize; 12] = [
            PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
        ];
        PUBLICKEY_BYTES[*self as usize]
    }

    pub fn crypto_secretkey_bytes(&self) -> usize {
        const SECRETKEY_BYTES: [usize; 12] = [
            PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
            PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
        ];
        SECRETKEY_BYTES[*self as usize]
    }

    pub fn crypto_bytes(&self) -> usize {
        const CRYPTO_BYTES: [usize; 12] = [
            PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES,
            PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES,
        ];
        CRYPTO_BYTES[*self as usize]
    }
}

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
/// `SphincsData` securely holds sensitive cryptographic data for the SPHINCS+ signature scheme, using a `Vec<u8>`.
/// This struct implements `Zeroize`, ensuring the data is wiped from memory when dropped (`#[zeroize(drop)]`).
/// Cloning is supported but should be done cautiously, as it duplicates sensitive information in memory.
pub struct SphincsPlusData(Vec<u8>);

impl AsRef<[u8]> for SphincsPlusData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Sphincs is a wrapper around the SPHINCS+ post-quantum signature scheme, providing an easy-to-use
/// API for generating keypairs, signing messages, and verifying signatures. It supports multiple
/// variants of the SPHINCS+ scheme, which offer different trade-offs between security, speed, and
/// signature size.
pub struct SphincsPlus {
    /// sphincs-plus type
    pub sphincs_plus_type: SphincsPlusType,
    /// Public-key bytes
    crypto_publickey_bytes: usize,
    /// Secret-key bytes
    crypto_secretkey_bytes: usize,
    /// Signature bytes
    crypto_bytes: usize,
}

macro_rules! gen_sphincs_keypair {
    ($variant:ident) => {{
        let (pk, sk) = $variant::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }};
}

macro_rules! gen_sphincs_verify_detached_signature {
    ($variant:ident, $sig:ident, $msg:ident, $pk:ident) => {{
        Ok($variant::verify_detached_signature(
            &$variant::DetachedSignature::from_bytes($sig)?,
            $msg,
            &$variant::PublicKey::from_bytes($pk)?,
        )?)
    }};
}

macro_rules! gen_sphincs_detached_sign {
    ($variant:ident, $msg:ident, $sk:ident) => {{
        Ok(
            $variant::detached_sign($msg, &$variant::SecretKey::from_bytes($sk.as_ref())?)
                .as_bytes()
                .to_vec(),
        )
    }};
}

impl SphincsPlus {
    /// Creates `Sphincs` instance based on the given `SphincsType`.
    /// It also sets the length of the public-key, secret-key, and signature byte sizes based on the
    /// given `SphincsType`.
    pub fn new(sphincs_type: SphincsPlusType) -> Self {
        SphincsPlus {
            crypto_publickey_bytes: sphincs_type.crypto_publickey_bytes(),
            crypto_secretkey_bytes: sphincs_type.crypto_secretkey_bytes(),
            crypto_bytes: sphincs_type.crypto_bytes(),
            sphincs_plus_type: sphincs_type,
        }
    }

    /// Generate (pk, sk) keypair of SPHINCS+ for an instance of `Sphincs`.
    ///
    /// It returns `Err(SphincsError)` if the secret-key length is not appropriate.
    /// Otherwise, the signature is return wrapped in `Ok(SphincsData)`.
    pub fn keygen(&self) -> Result<(SphincsPlusData, SphincsPlusData), SphincsError> {
        let (pk, sk) = self.sphincs_keypair();
        if self.crypto_publickey_bytes != pk.len() {
            return Err(SphincsError::BadLength(
                self.crypto_publickey_bytes,
                pk.len(),
            ));
        }
        if self.crypto_secretkey_bytes != sk.len() {
            return Err(SphincsError::BadLength(
                self.crypto_secretkey_bytes,
                sk.len(),
            ));
        }
        Ok((SphincsPlusData(pk), SphincsPlusData(sk)))
    }

    fn sphincs_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        match self.sphincs_plus_type {
            SphincsPlusType::SPHINCSSHAKE128F => gen_sphincs_keypair!(sphincsshake128fsimple),
            SphincsPlusType::SPHINCSSHAKE128S => gen_sphincs_keypair!(sphincsshake128ssimple),
            SphincsPlusType::SPHINCSSHAKE192F => gen_sphincs_keypair!(sphincsshake192fsimple),
            SphincsPlusType::SPHINCSSHAKE192S => gen_sphincs_keypair!(sphincsshake192ssimple),
            SphincsPlusType::SPHINCSSHAKE256F => gen_sphincs_keypair!(sphincsshake256fsimple),
            SphincsPlusType::SPHINCSSHAKE256S => gen_sphincs_keypair!(sphincsshake256ssimple),
            SphincsPlusType::SPHINCSSHA2128F => gen_sphincs_keypair!(sphincssha2128fsimple),
            SphincsPlusType::SPHINCSSHA2128S => gen_sphincs_keypair!(sphincssha2128ssimple),
            SphincsPlusType::SPHINCSSHA2192F => gen_sphincs_keypair!(sphincssha2192fsimple),
            SphincsPlusType::SPHINCSSHA2192S => gen_sphincs_keypair!(sphincssha2192ssimple),
            SphincsPlusType::SPHINCSSHA2256F => gen_sphincs_keypair!(sphincssha2256fsimple),
            SphincsPlusType::SPHINCSSHA2256S => gen_sphincs_keypair!(sphincssha2256ssimple),
        }
    }

    /// Calculate the SPHINCS+ signature for a given `Sphincs` instance, based on the given message
    /// and secret-key.
    ///
    /// It returns `Err(SphincsError)` if the secret-key length is not appropriate. Otherwise, the
    /// signature is return wrapped in `Ok(SphincsData)` without including the original message in
    /// its output.
    pub fn sign(
        &self,
        message: &[u8],
        sk: &SphincsPlusData,
    ) -> Result<SphincsPlusData, SphincsError> {
        let signature = self.sphincs_detached_sign(message, sk.as_ref())?;
        if self.crypto_bytes != signature.len() {
            return Err(SphincsError::BadLength(
                self.crypto_publickey_bytes,
                signature.len(),
            ));
        }
        Ok(SphincsPlusData(signature))
    }

    fn sphincs_detached_sign(
        &self,
        msg: &[u8],
        sk: &[u8],
    ) -> Result<Vec<u8>, pqcrypto_traits::Error> {
        match self.sphincs_plus_type {
            SphincsPlusType::SPHINCSSHAKE128F => {
                gen_sphincs_detached_sign!(sphincsshake128fsimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHAKE128S => {
                gen_sphincs_detached_sign!(sphincsshake128ssimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHAKE192F => {
                gen_sphincs_detached_sign!(sphincsshake192fsimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHAKE192S => {
                gen_sphincs_detached_sign!(sphincsshake192ssimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHAKE256F => {
                gen_sphincs_detached_sign!(sphincsshake256fsimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHAKE256S => {
                gen_sphincs_detached_sign!(sphincsshake256ssimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHA2128F => {
                gen_sphincs_detached_sign!(sphincssha2128fsimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHA2128S => {
                gen_sphincs_detached_sign!(sphincssha2128ssimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHA2192F => {
                gen_sphincs_detached_sign!(sphincssha2192fsimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHA2192S => {
                gen_sphincs_detached_sign!(sphincssha2192ssimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHA2256F => {
                gen_sphincs_detached_sign!(sphincssha2256fsimple, msg, sk)
            },
            SphincsPlusType::SPHINCSSHA2256S => {
                gen_sphincs_detached_sign!(sphincssha2256ssimple, msg, sk)
            },
        }
    }

    /// Verify the SPHINCS+ signature for a given `Sphincs` instance, based on the given message
    /// and public-key.
    ///
    /// It returns `Err(SphincsError)` if the there is an error either about wrong data length or if
    /// the signature is invalid. Otherwise, if the signature is valid for the given message, it
    /// returns `Ok(())`, showing the validity of the given signature.
    pub fn verify(
        &self,
        signature: &SphincsPlusData,
        message: &[u8],
        pk: &SphincsPlusData,
    ) -> Result<(), SphincsError> {
        self.sphincs_verify_detached_signature(signature.as_ref(), message, pk.as_ref())
    }

    fn sphincs_verify_detached_signature(
        &self,
        sig: &[u8],
        msg: &[u8],
        pk: &[u8],
    ) -> Result<(), SphincsError> {
        match self.sphincs_plus_type {
            SphincsPlusType::SPHINCSSHAKE128F => {
                gen_sphincs_verify_detached_signature!(sphincsshake128fsimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHAKE128S => {
                gen_sphincs_verify_detached_signature!(sphincsshake128ssimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHAKE192F => {
                gen_sphincs_verify_detached_signature!(sphincsshake192fsimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHAKE192S => {
                gen_sphincs_verify_detached_signature!(sphincsshake192ssimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHAKE256F => {
                gen_sphincs_verify_detached_signature!(sphincsshake256fsimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHAKE256S => {
                gen_sphincs_verify_detached_signature!(sphincsshake256ssimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHA2128F => {
                gen_sphincs_verify_detached_signature!(sphincssha2128fsimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHA2128S => {
                gen_sphincs_verify_detached_signature!(sphincssha2128ssimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHA2192F => {
                gen_sphincs_verify_detached_signature!(sphincssha2192fsimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHA2192S => {
                gen_sphincs_verify_detached_signature!(sphincssha2192ssimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHA2256F => {
                gen_sphincs_verify_detached_signature!(sphincssha2256fsimple, sig, msg, pk)
            },
            SphincsPlusType::SPHINCSSHA2256S => {
                gen_sphincs_verify_detached_signature!(sphincssha2256ssimple, sig, msg, pk)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    fn test_sphincs_plus(sphincs_type: SphincsPlusType) {
        let sphincs = SphincsPlus::new(sphincs_type);

        let kg = sphincs.keygen();
        assert!(kg.is_ok());
        let (pk, sk) = kg.unwrap();

        let mut rng = thread_rng();
        let len: u16 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let signing = sphincs.sign(&message, &sk);
        assert!(signing.is_ok());
        let signature = signing.unwrap();

        assert!(sphincs.verify(&signature, &message, &pk).is_ok());

        let fake_signature = SphincsPlusData(
            signature
                .as_ref()
                .iter()
                .enumerate()
                .map(|(i, &x)| if i == 0 { x ^ 1 } else { x })
                .collect(),
        );

        assert!(matches!(
            sphincs.verify(&fake_signature, &message, &pk),
            Err(SphincsError::VerificationFailed(_))
        ));
        println!(
            "{:?} keygen, signing, and verify tests passed.",
            sphincs.sphincs_plus_type
        );
    }

    #[test]
    fn test_sphincs_plus_shake128f() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHAKE128F);
    }

    #[test]
    fn test_sphincs_plus_shake128s() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHAKE128S);
    }

    #[test]
    fn test_sphincs_plus_shake192f() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHAKE192F);
    }

    #[test]
    fn test_sphincs_plus_shake192s() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHAKE192S);
    }

    #[test]
    fn test_sphincs_plus_shake256f() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHAKE256F);
    }

    #[test]
    fn test_sphincs_plus_shake256s() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHAKE256S);
    }

    #[test]
    fn test_sphincs_plus_sha2_128f() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHA2128F);
    }

    #[test]
    fn test_sphincs_plus_sha2_128s() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHA2128S);
    }

    #[test]
    fn test_sphincs_plus_sha2_192f() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHA2192F);
    }

    #[test]
    fn test_sphincs_plus_sha2_192s() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHA2192S);
    }

    #[test]
    fn test_sphincs_plus_sha2_256f() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHA2256F);
    }

    #[test]
    fn test_sphincs_plus_sha2_256s() {
        test_sphincs_plus(SphincsPlusType::SPHINCSSHA2256S);
    }
}
