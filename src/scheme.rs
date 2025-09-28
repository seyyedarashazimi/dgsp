//! # DGSP: A Post-quantum Fully Dynamic Group Signature Scheme Using SPHINCS+
//!
//! This module defines DGSP which has three main parties: a trusted manager
//! (with public and secret keys), multiple users (each with their own seed to
//! generate secret keys, and their credentials for requesting certificates),
//! and verifiers who verify group signatures. The bit-level security of DGSP,
//! i.e. λ or [`DGSP_N`], is either 128, 192, or 256 and determined by the
//! choice of the underlying SPHINCS+ feature and is set to λ=256 by default.
//!
//! ## Cryptographic Primitives
//! DGSP is designed based on SPHINCS+, a stateless hash-based signature scheme
//! standardized by NIST for post-quantum security. SPHINCS+ uses WOTS+ to sign
//! the root of subtrees using the corresponding leaf nodes as well as signing
//! the main messages using the lowest leaf nodes.
//!
//! DGSP also leverages the following symmetric primitives:
//! - AES which is mainly used for managing signature/user revocations.
//!   The choice of AES key-size is equal to λ.
//! - SHA2/SHAKE-256 to compute digests of messages and building Merkle trees.
//!   The choice of hash functions are based on the selected SPHINCS+ feature.
//!
//! ## Parties and Their Keys
//! 1) Manager: A "semi-trusted" manager with a pair of keys as follows:
//!     - `DGSPManagerPublicKey`: Consists of `SphincsPlusPublicKey` as the
//!       root of SPHINCS+ tree which is the public key of the SPHINCS+ scheme.
//!     - `DGSPManagerSecretKey`: Consists of `SphincsPlusSecretKey` which is
//!       the secret-key of the SPHINCS+ scheme, as well as a secret λ-bit
//!       value `DGSPMSK` called the manager secret key material.
//!
//!     Manager is responsible for:
//!     (i) joining new users,
//!     (ii) creating certificates,
//!     (iii) opening signatures to trace a signer once necessary alongside a
//!     proof, and
//!     (iv) revocation of a user, their signatures, and any provided
//!     certificates.
//!
//! 2. Users: Each user possess a secret seed (seed_user) which is used to
//!     generate WOTS+ keys when requesting certificates and signing a message.
//!     Also, the manager assigns an identifier id and a derived cryptographic
//!     credential (cid) to each user. These WOTS+ keys along with the pair
//!     identifier/credential (id, cid) are used for communicating with the
//!     manager through a secure channel. If the user authenticates with the
//!     manager successfully, the manager issues certificates to the user,
//!     enabling them to sign messages on behalf of the group at a later time.
//!
//!     Each user in DGSP can:
//!     (i) obtain a pair of (id, cid) by providing a unique username,
//!     (ii) request a batch of certificates and check their validity,
//!     (iii) sign a message using a new WOTS+ public key from a random
//!     seed as well as the corresponding certificate.
//!
//! 3. Verifier: A verifier in DGSP scheme uses publicly-known values to verify
//!     correctness of the scheme. The public knowledge includes the manager's
//!     public key, signatures, and a list called RevokedList.
//!
//!     A verifier in DGSP is provided with the following functionalities:
//!     (i) verification of a given signature for a message,
//!     (ii) judgement of the manager for opening a signature to the correct
//!     signer.
//!
//! ## DGSP's Algorithms
//! - **Key Generation:** Generates a manager keypair (public and secret). The
//!     scheme also provides users with a method to generate secret seeds as
//!     their secret keys to request certificates and signing messages.
//! - **User Join:** A user joins the group and is assigned a unique ID and a
//!     secret credential. Their username, activeness status, and the number
//!     of generated certificates are stored in the manager's private list,
//!     called PLM.
//! - **Certificate Generation:** A user creates a batch of WOTS+ public keys.
//!     The manager then creates certificates for a batch of user certificate
//!     signing requests (CSRs) for the WOTS+ public keys. Each certificate is
//!     a SPHINCS+ signature over a message pattern containing the given WOTS+
//!     public key, an encrypted user identity binding value, and a manager's
//!     commitment to the user's identity, used later for judging the manager.
//! - **Signing:** A user signs a message on behalf of the group by combining a
//!     WOTS+ signature with the corresponding pre-computed certificate given
//!     earlier by the manager.
//! - **Verification:** A verifier checks that the signature is valid and that
//!     it has not been revoked.
//! - **Opening:** The manager can “open” a signature to reveal the signer’s ID
//!     and produce a proof. This enables the manager to trace signatures to
//!     specific users, without compromising anonymity for other parties.
//! - **Revocation:** The manager can revoke a user, all provided certificates,
//!     and signatures associated with that user. The public revoked data are
//!     stored in the RevokedList, and the user is marked inactive permanently
//!     in the manager's private list PLM.
//! - **Judging:** The manager’s opening result can be verified (judged) to
//!     ensure it is correct.
//! ## Example
//!
//! The following example demonstrates a typical workflow in DGSP using
//! in‑memory databases:
//!
//! ```rust
//! #![cfg_attr(not(feature = "in-memory"), allow(dead_code))]
//! #[cfg(feature = "in-memory")]
//! {
//! use dgsp::{InMemoryPLM, InMemoryRevokedList, PLMInterface, RevokedListInterface, DGSP};
//!
//! // Create in-memory PLM and RevokedList
//! let plm = InMemoryPLM::open("").expect("Failed to open in-memory PLM");
//! let revoked_list = InMemoryRevokedList::open("")
//!     .expect("Failed to open in-memory RevokedList");
//!
//! // Manager generates keys
//! let (pkm, skm) = DGSP::keygen_manager().expect("Manager key generation failed");
//!
//! // A user joins the group (the PLM stores the username, a unique ID, status, and a
//! // certificate counter)
//! let username = "Alice";
//! let (user_id, cid) = DGSP::join(&skm.msk.hash_secret, username, &plm).expect("User join failed");
//!
//! // User generates a random seed and creates a certificate signing request (CSR)
//! let seed_user = DGSP::keygen_user();
//! let (wots_pks, wots_rands) = DGSP::csr(&seed_user, 1);
//!
//! // Manager generates a certificate for the user's CSR
//! let certs = DGSP::gen_cert(&skm, user_id, &cid, &wots_pks, &plm)
//!     .expect("Certificate generation failed");
//!
//! // User checks the certificate validity
//! DGSP::check_cert(user_id, &wots_pks, &certs, &pkm)
//!     .expect("Certificate check failed");
//!
//! // User signs a message using the certificate and corresponding randomness
//! let message = b"Hello DGSP!";
//! let sig = DGSP::sign(
//!     message,
//!     &seed_user,
//!     user_id,
//!     wots_rands.into_iter().next().unwrap(),
//!     certs.into_iter().next().unwrap(),
//! );
//!
//! // Verifier checks the signature using the manager's public key and the revoked list
//! DGSP::verify(message, &sig, &revoked_list, &pkm)
//!     .expect("Signature verification failed");
//!
//! // Manager opens the signature to reveal the signer
//! let (opened_id, opened_username, pi) = DGSP::open(&skm.msk, &plm, &sig, message)
//!     .expect("Signature opening failed");
//! assert_eq!(opened_id, user_id);
//! assert_eq!(opened_username, "Alice");
//!
//! // Judge the manager's correctness
//! DGSP::judge(&sig, message, user_id, &pi).expect("Manager judgment failed");
//!
//! // Revoke the user
//! DGSP::revoke(&skm.msk.aes_key, &plm, &[user_id], &revoked_list).unwrap();
//! }
//! ```
//!
//! ## Notes
//! The implementation provides interfaces for both in-memory and in-disk
//! databases, facilitating user management (`PLMInterface`) and certificate
//! revocation tracking (`RevokedListInterface`).
//!
//! This also leverages `rayon` for parallel operations when computation is
//! time-consuming (e.g. generating batch of certificates).
//!
//! All cryptographic operations use secure hash‑based primitives and AES
//! encryption (with a key derived from the manager’s secret key) for
//! confidentiality. Sensitive data is automatically zeroized when no longer
//! needed.

use crate::cipher::DGSPCipher;
use crate::db::{PLMInterface, RevokedListInterface};
use crate::hash::DGSPHasher;
use crate::params::{DGSP_N, DGSP_USER_BYTES, DGSP_ZETA_BYTES};
use crate::sphincs_plus::*;
use crate::utils::{array_struct, bytes_to_u64, u64_to_bytes};
use crate::wots_plus::WotsPlus;
use crate::{Error, Result, VerificationError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use zeroize::Zeroize;

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

// Holds the randomness used by the WOTS+ scheme within DGSP, i.e. rho.
// The internal array is the signing seed (i.e. public key seed) for WOTS+.
array_struct!(DGSPWotsRand, DGSP_N);

impl Default for DGSPWotsRand {
    fn default() -> Self {
        Self::new()
    }
}

impl DGSPWotsRand {
    /// Creates a new instance of `DGSPWotsRand` with cryptographically random seed.
    pub fn new() -> Self {
        let mut wots_sgn_seed = [0u8; DGSP_N];
        OsRng.fill_bytes(&mut wots_sgn_seed);
        Self(wots_sgn_seed)
    }
    /// Creates a new instance of `DGSPWotsRand` with random seeds
    /// derived from another secret seed given as input
    pub fn from_seed(seed: &[u8; DGSP_N]) -> Self {
        let mut input = [0u8; DGSP_N];
        input[..DGSP_N].copy_from_slice(seed);
        let mut wots_sgn_seed = [0u8; DGSP_N];
        DGSPHasher::hash_simple(&mut wots_sgn_seed, &input);
        Self(wots_sgn_seed)
    }
}

// Create a new type `DGSPSecret` as a wrapper around a fixed-size array.
array_struct!(DGSPSecret, DGSP_N);

/// The manager's secret key material, including the hash secret value and the AES key,
/// each of them being `DGSP_N` secret bytes.
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPMSK {
    /// The hashing secret part, mainly used to calculate cid for a user.
    pub hash_secret: DGSPSecret,
    /// The AES key, used to encrypt zeta.
    pub aes_key: DGSPSecret,
}

/// The manager's secret key, including the manager secret key material (`msk`)
/// and the SPHINCS+ secret key.
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPManagerSecretKey {
    /// The manager’s secret key material.
    pub msk: DGSPMSK,
    /// The SPHINCS+ secret key.
    pub spx_sk: SphincsPlusSecretKey,
}

/// The manager's public key, which consists solely of the SPHINCS+ public key.
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPManagerPublicKey {
    /// The SPHINCS+ public key (root of SPHINCS+ tree).
    pub spx_pk: SphincsPlusPublicKey,
}

/// A DGSP certificate produced by the manager. It contains an encrypted user
/// binding value (`zeta`), the proof used for opening (`pi`), and a SPHINCS+
/// signature (`spx_sig`) that authenticates the certificate for a given WOTS+
/// public key.
///
/// **Notes on the SPHINCS+ signature `spx_sig`:**
/// - The size of the SPHINCS+ signature depends on the selected parameter set
///   of the underlying SPHINCS+ scheme; it can roughly range from ~8KBytes to
///   ~50KBytes.
/// - Since `spx_sig` is stored on the stack, creating a big number of
///   certificates manually and storing them all on stack may lead to stack
///   overflow in memory‑constrained environments. If necessary, consider
///   wrapping them in a heap‑allocated container (e.g., using `Box<>` or
///   `Vec<>`). Note that the module stores the batch of certificates, created
///   by the manager, inside a `Vec<DGSPCert>`, so the batch size can be as big
///   as needed and cause no problem.
/// - Although cloning is implemented via the `Clone` trait, be cautious when
///   cloning this structure as duplicating large SPHINCS+ signature data can
///   incur significant performance and memory overhead.
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPCert {
    /// The encrypted value (zeta) used to bind the user identity.
    pub zeta: [u8; DGSP_ZETA_BYTES],
    /// The proof (pi) used to prove opening
    pub pi: [u8; DGSP_N],
    /// The SPHINCS+ signature that authenticates the certificate for a given
    /// WOTS+ public key.
    pub spx_sig: SphincsPlusSignature,
}

/// A DGSP signature that contains a WOTS+ signature and randomness, user Id
/// encryption, SPHINCS+ signature, and a binding value.
///
/// Although cloning is provided, be cautious when cloning this structure as
/// duplicating large certificates can incur significant performance and memory
/// overhead.
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Zeroize, Debug, PartialEq)]
pub struct DGSPSignature {
    /// The WOTS+ signature.
    #[cfg_attr(feature = "serialization", serde(with = "BigArray"))]
    pub wots_sig: [u8; SPX_WOTS_BYTES],
    /// The randomness used by WOTS+ as the sign seed.
    pub wots_rand: DGSPWotsRand,
    /// The encryption of the users ID
    pub zeta: [u8; DGSP_ZETA_BYTES],
    /// The SPHINCS+ signature to authenticate the user
    pub spx_sig: SphincsPlusSignature,
    /// The binding value (tau) that is computed from the WOTS+ public key and
    /// the user id.
    pub tau: [u8; DGSP_N],
}

/// The main DGSP structure, providing methods for key generation, joining,
/// certificate generation, certificate checking, signing, verification,
/// opening, judging, and revocation.
#[derive(Default)]
pub struct DGSP;

impl DGSP {
    /// Generates a new manager keypair.
    ///
    /// This function creates a new SPHINCS+ keypair and randomly initializes
    /// the manager secret key material (`msk`).
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple
    /// `(DGSPManagerPublicKey, DGSPManagerSecretKey)` on success.
    pub fn keygen_manager() -> Result<(DGSPManagerPublicKey, DGSPManagerSecretKey)> {
        let (spx_pk, spx_sk) = SphincsPlus::keygen()?;
        let mut hash_secret = DGSPSecret::from([0u8; DGSP_N]);
        let mut aes_key = DGSPSecret::from([0u8; DGSP_N]);
        OsRng.fill_bytes(&mut hash_secret.0);
        OsRng.fill_bytes(&mut aes_key.0);

        let msk = DGSPMSK {
            hash_secret,
            aes_key,
        };

        let sk = DGSPManagerSecretKey { msk, spx_sk };
        let pk = DGSPManagerPublicKey { spx_pk };

        Ok((pk, sk))
    }

    /// Registers a new user in the group.
    ///
    /// Given the manager secret key material (`msk`), a username, and a
    /// reference to a private list manager (PLM), this function assigns a
    /// unique user ID and computes a secret credential (`cid`) for the user.
    ///
    /// # Parameters
    ///
    /// - `hash_secret`: Reference to the manager's hash secret.
    /// - `username`: The username of the new user.
    /// - `plm`: A reference to an object implementing the `PLMInterface`.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple `(user_id, cid*)` on success.
    /// If the given username exists in the plm, this returns an error.
    pub fn join<P: PLMInterface>(
        hash_secret: &DGSPSecret,
        username: &str,
        plm: &P,
    ) -> Result<(u64, [u8; DGSP_N])> {
        let id = plm.add_new_user(username)?;
        let cid = Self::calculate_cid(hash_secret, id);
        let cid_star = Self::calculate_cid_star(id, cid);
        Ok((id, cid_star))
    }

    /// Generates a batch of certificates for a user.
    ///
    /// The manager uses this function to produce a set of certificates
    /// corresponding to a batch of WOTS+ public keys. It verifies that the
    /// user exists and that the provided user credential (`cid`) is correct.
    ///
    /// # Parameters
    ///
    /// - `manager_sk`: A reference to the manager secret key.
    /// - `id`: The user's identifier.
    /// - `cid*`: A reference to the user's credential identifier.
    /// - `wotsplus_public_keys`: A slice of WOTS+ public keys (each of size
    ///   `DGSP_N`).
    /// - `plm`: A reference to an object implementing `PLMInterface`.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `DGSPCert` objects on success.
    pub fn gen_cert<P: PLMInterface>(
        manager_sk: &DGSPManagerSecretKey,
        id: u64,
        cid_star: &[u8; DGSP_N],
        wotsplus_public_keys: &[[u8; DGSP_N]],
        plm: &P,
    ) -> Result<Vec<DGSPCert>> {
        Self::req_validity(&manager_sk.msk.hash_secret, id, cid_star, plm)?;
        let cid = Self::calculate_cid(&manager_sk.msk.hash_secret, id);

        let certs = Self::par_calculate_certificates(
            manager_sk,
            id,
            &cid,
            wotsplus_public_keys,
            plm.get_ctr_id(id)?,
        )?;

        plm.increment_ctr_id_by(id, wotsplus_public_keys.len() as u64)?;

        Ok(certs)
    }

    /// Internally calculates certificates in parallel for each WOTS+ public
    /// key.
    ///
    /// For each public key in `wotsplus_public_keys`, this function:
    /// - Computes a unique value `zeta` by combining the user ID and a counter
    ///   (encrypted by the manager `msk` using AES).
    /// - Calculates two binding values `pi` and `tau`.
    /// - Prepares a SPHINCS+ message from the WOTS+ public key, `zeta`, and
    ///   `tau`, then signs it.
    ///
    /// # Parameters
    ///
    /// - `msk`: A reference to the manager secret key material.
    /// - `sphincs_plus_sk`: A reference to the SPHINCS+ secret key.
    /// - `id`: The user’s identifier.
    /// - `cid`: A reference to the user's credential identifier.
    /// - `wotsplus_public_keys`: Slice of WOTS+ public keys.
    /// - `ctr_id`: The current counter value for the user.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `DGSPCert` objects.
    fn par_calculate_certificates(
        manager_sk: &DGSPManagerSecretKey,
        id: u64,
        cid: &[u8; DGSP_N],
        wotsplus_public_keys: &[[u8; DGSP_N]],
        ctr_id: u64,
    ) -> Result<Vec<DGSPCert>> {
        // Initialize the AES cipher using the manager secret key material.
        let cipher = DGSPCipher::cipher(&manager_sk.msk.aes_key);

        wotsplus_public_keys
            .par_iter()
            .enumerate()
            .map(|(i, wots_pk)| {
                let mut zeta = [0u8; DGSP_ZETA_BYTES];

                // Combine id and ctr + i into the input block
                zeta[..DGSP_USER_BYTES].copy_from_slice(&u64_to_bytes(id));
                zeta[DGSP_USER_BYTES..].copy_from_slice(&u64_to_bytes(ctr_id + (i as u64)));

                // Encrypt zeta in-position using AES
                let block_generic = GenericArray::from_mut_slice(&mut zeta);
                cipher.encrypt_block(block_generic);

                // Calculate binding values pi and tau
                let pi = Self::calculate_pi(wots_pk, cid);
                let tau = Self::calculate_tau(wots_pk, &pi, id);

                // Prepare the message to be signed with SPHINCS+.
                let spx_msg = Self::prepare_spx_msg(wots_pk, &zeta, &tau);
                let spx_sig = SphincsPlus::sign(&spx_msg, &manager_sk.spx_sk)?;

                let cert = DGSPCert { zeta, pi, spx_sig };

                Ok(cert)
            })
            .collect::<Result<Vec<DGSPCert>>>()
    }

    /// Revokes one or more users.
    ///
    /// For each user in `to_be_revoked`, if the user exists and is active,
    /// this function:
    /// - Calculates all associated `zeta` values from the counter.
    /// - Inserts each `zeta` into the revoked list.
    /// - Marks the user as deactivated in the PLM.
    ///
    /// # Parameters
    ///
    /// - `aes_key`: A reference to the manager's AES key.
    /// - `plm`: A reference to an object implementing `PLMInterface`.
    /// - `to_be_revoked`: A slice of user IDs to be revoked.
    /// - `revoked_list`: A reference to an object implementing
    ///   `RevokedListInterface`.
    ///
    /// # Returns
    ///
    /// A `Result<()>` equal to `Ok(())` indicating success, or an error
    /// `Err(dgsp::Error)`.
    pub fn revoke<P: PLMInterface, R: RevokedListInterface>(
        aes_key: &DGSPSecret,
        plm: &P,
        to_be_revoked: &[u64],
        revoked_list: &R,
    ) -> Result<()> {
        for &r in to_be_revoked {
            if plm.id_exists(r)? && plm.id_is_active(r)? {
                let zeta_list = Self::par_calculate_zeta(aes_key, r, 0, plm.get_ctr_id(r)?);
                for zeta in zeta_list {
                    revoked_list.insert(zeta)?;
                }
                plm.deactivate_id(r)?;
            }
        }
        Ok(())
    }

    /// Opens a signature to reveal the signer’s identity.
    ///
    /// This function decrypts the `zeta` value in the signature to recover the
    /// user ID, retrieves the username from the PLM, and recomputes the
    /// binding value (`pi`) from the WOTS+ public key and the user's
    /// certificate identifier.
    ///
    /// # Parameters
    ///
    /// - `msk`: A reference to the manager secret key material.
    /// - `plm`: A reference to an object implementing `PLMInterface`.
    /// - `sig`: A reference to the DGSP signature to be opened.
    /// - `message`: The message that was signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple `(user_id, username, pi)`.
    pub fn open<P: PLMInterface>(
        msk: &DGSPMSK,
        plm: &P,
        sig: &DGSPSignature,
        message: &[u8],
    ) -> Result<(u64, String, [u8; DGSP_N])> {
        let mut zeta = sig.zeta;
        let block = GenericArray::from_mut_slice(&mut zeta);

        let cipher = DGSPCipher::cipher(&msk.aes_key);
        cipher.decrypt_block(block);

        let id = bytes_to_u64(&zeta[..8]);
        plm.id_exists(id)?;

        // Recreate the WOTS+ public key from the signature.
        let wp = WotsPlus::new(sig.wots_rand.as_ref());
        let wots_pk = wp.pk_from_sig(&sig.wots_sig, message);

        // Calculate pi from msk, the WOTS+ public key. and the user's credential.
        let cid = Self::calculate_cid(&msk.hash_secret, id);
        let pi = Self::calculate_pi(&wots_pk, &cid);

        Ok((id, plm.get_username(id)?, pi))
    }

    /// Computes a simple hash of the input using the configured DGSPHasher.
    ///
    /// The actual hash function used by `DGSPHasher` depends on the active
    /// SPHINCS+ feature. When a particular SPHINCS+ parameter set is enabled,
    /// `DGSPHasher` may use SHA2 (SHA-256, SHA-512) or SHAKE-256. This allows
    /// the hash behavior (and output size) to adapt to the underlying SPHINCS+
    /// configuration.
    ///
    /// # Parameters
    ///
    /// - `input`: The data to be hashed.
    ///
    /// # Returns
    ///
    /// A `[u8; DGSP_N]` array containing the hash output.
    fn hash_simple(input: &[u8]) -> [u8; DGSP_N] {
        let mut output = [0u8; DGSP_N];
        DGSPHasher::hash_simple(&mut output, input);
        output
    }

    /// Calculates the binding value `pi` from a WOTS+ public key `pk` and a
    /// user credential `cid` as H(pk || cid).
    ///
    /// # Parameters
    ///
    /// - `pk`: The WOTS+ public key.
    /// - `cid`: The user credential.
    ///
    /// # Returns
    ///
    /// A `[u8; DGSP_N]` binding value.
    fn calculate_pi(pk: &[u8], cid: &[u8]) -> [u8; DGSP_N] {
        let mut input = [0u8; 2 * DGSP_N];
        input[..DGSP_N].copy_from_slice(pk);
        input[DGSP_N..].copy_from_slice(cid);
        Self::hash_simple(&input)
    }

    /// Calculates the binding value `tau` using the WOTS+ public key `pk`,
    /// binding value `pi`, and the user ID as H(pk || pi || id).
    ///
    /// # Parameters
    ///
    /// - `pk`: The WOTS+ public key.
    /// - `pi`: The binding value computed from the WOTS+ public key and `cid`.
    /// - `id`: The user’s identifier.
    ///
    /// # Returns
    ///
    /// A `[u8; DGSP_N]` array representing `tau`.
    fn calculate_tau(pk: &[u8], pi: &[u8], id: u64) -> [u8; DGSP_N] {
        let mut input = [0u8; 2 * DGSP_N + DGSP_USER_BYTES];
        input[..DGSP_N].copy_from_slice(pk);
        input[DGSP_N..2 * DGSP_N].copy_from_slice(pi);
        input[2 * DGSP_N..].copy_from_slice(u64_to_bytes(id).as_ref());
        Self::hash_simple(&input)
    }

    /// Calculates the user-specific secret `cid` for a given user.
    ///
    /// The `cid` is computed using the manager secret key material `msk` and
    /// the user ID `id` as H(msk || id).
    ///
    /// # Parameters
    ///
    /// - `hash_secret`: Reference to the manager's hash secret.
    /// - `id`: The user’s identifier.
    ///
    /// # Returns
    ///
    /// A `[u8; DGSP_N]` array representing the certificate identifier.
    fn calculate_cid(hash_secret: &DGSPSecret, id: u64) -> [u8; DGSP_N] {
        let mut input = [0u8; DGSP_N + DGSP_USER_BYTES];
        input[..DGSP_N].copy_from_slice(hash_secret.as_ref());
        input[DGSP_N..].copy_from_slice(u64_to_bytes(id).as_ref());
        Self::hash_simple(&input)
    }

    /// Calculates the user credential `cid*` for a given user.
    ///
    /// The `cid*` is computed using the user-specific secret `cid` and
    /// the user ID `id` as H(id || cid).
    ///
    /// # Parameters
    ///
    /// - `hash_secret`: Reference to the manager's hash secret.
    /// - `id`: The user’s identifier.
    ///
    /// # Returns
    ///
    /// A `[u8; DGSP_N]` array representing the certificate identifier.
    fn calculate_cid_star(id: u64, cid: [u8; DGSP_N]) -> [u8; DGSP_N] {
        let mut input = [0u8; DGSP_N + DGSP_USER_BYTES];
        input[..DGSP_N].copy_from_slice(cid.as_ref());
        input[DGSP_N..].copy_from_slice(u64_to_bytes(id).as_ref());
        Self::hash_simple(&input)
    }

    /// Prepares the SPHINCS+ message that is to be signed as part of
    /// certificate generation and verification.
    ///
    /// The message is the concatenation of the WOTS+ public key, the encrypted
    /// value `zeta`, and the binding value `tau` as (wots_pk || zeta || tau).
    ///
    /// # Parameters
    ///
    /// - `wots_pk`: The WOTS+ public key.
    /// - `zeta`: The encrypted binding value.
    /// - `tau`: The binding value.
    ///
    /// # Returns
    ///
    /// A byte array containing the concatenated message.
    fn prepare_spx_msg(
        wots_pk: &[u8; DGSP_N],
        zeta: &[u8; DGSP_ZETA_BYTES],
        tau: &[u8; DGSP_N],
    ) -> [u8; DGSP_N + DGSP_ZETA_BYTES + DGSP_N] {
        let mut spx_msg = [0u8; DGSP_N + DGSP_ZETA_BYTES + DGSP_N];
        spx_msg[..DGSP_N].copy_from_slice(wots_pk);
        spx_msg[DGSP_N..DGSP_N + DGSP_ZETA_BYTES].copy_from_slice(zeta);
        spx_msg[DGSP_N + DGSP_ZETA_BYTES..].copy_from_slice(tau);
        spx_msg
    }

    /// Validates that the certificate generation request from a user is
    /// correct.
    ///
    /// It checks that the user exists, is active, and that the provided user
    /// credential matches the one computed from the manager secret key
    /// material and user ID.
    ///
    /// # Parameters
    ///
    /// - `hash_secret`: Reference to the manager's hash secret.
    /// - `id`: The user’s identifier.
    /// - `cid*`: The provided user credential.
    /// - `plm`: A reference to an object implementing `PLMInterface`.
    ///
    /// # Returns
    ///
    /// An empty `Result` on success or an error if the request is invalid.
    fn req_validity<P: PLMInterface>(
        hash_secret: &DGSPSecret,
        id: u64,
        cid_star: &[u8; DGSP_N],
        plm: &P,
    ) -> Result<()> {
        // check if user exists and is active
        if !plm.id_exists(id)? || !plm.id_is_active(id)? {
            return Err(Error::InvalidCertReq);
        }

        // check if user cid is correct
        if *cid_star != Self::calculate_cid_star(id, Self::calculate_cid(hash_secret, id)) {
            return Err(Error::InvalidCertReq);
        }
        Ok(())
    }

    /// Calculates an array of encrypted `zeta` values in parallel.
    ///
    /// For a given user, this function encrypts a series of blocks (using AES)
    /// where each block is formed by concatenating the user ID and an
    /// increasing counter.
    ///
    /// # Parameters
    ///
    /// - `aes_key`: A reference to the manager's AES key.
    /// - `id`: The user’s identifier.
    /// - `ctr_id`: The starting counter value.
    /// - `b`: The number of blocks to compute.
    ///
    /// # Returns
    ///
    /// A vector of `[u8; DGSP_ZETA_BYTES]` arrays.
    fn par_calculate_zeta(
        aes_key: &DGSPSecret,
        id: u64,
        ctr_id: u64,
        b: u64,
    ) -> Vec<[u8; DGSP_ZETA_BYTES]> {
        let cipher = DGSPCipher::cipher(aes_key);

        // Perform parallel encryption
        (0..b)
            .into_par_iter()
            .map(|i| {
                let mut block = [0u8; DGSP_ZETA_BYTES];

                // Combine pk and ctr + i into the input block
                block[..8].copy_from_slice(&u64_to_bytes(id));
                block[8..].copy_from_slice(&u64_to_bytes(ctr_id + i));

                // Encrypt the block using AES
                let block_generic = GenericArray::from_mut_slice(&mut block);
                cipher.encrypt_block(block_generic);

                block
            })
            .collect()
    }

    /// Generates a random user seed.
    ///
    /// This seed is used by a user for generating WOTS+ keys and signing
    /// messages.
    ///
    /// # Returns
    ///
    /// A `[u8; DGSP_N]` array containing the user seed.
    pub fn keygen_user() -> [u8; DGSP_N] {
        let mut seed_user: [u8; DGSP_N] = [0; DGSP_N];
        OsRng.fill_bytes(&mut seed_user);
        seed_user
    }

    /// Generates the "salted" key to be input directly to WOTS
    ///
    /// This means each WOTS secret key is randomized in a
    /// forgettable way
    ///
    /// # Parameters
    ///
    /// - `seed_user`: The (long-term) user seed
    /// - `wots_seed`: A single-use secret WOTS seed
    ///
    /// # Returns
    ///
    /// A byte array to be used as the secret key seed in WOTS
    pub fn wots_key(seed_user: &[u8; DGSP_N], wots_seed: &[u8; DGSP_N]) -> [u8; DGSP_N] {
        let mut input: [u8; DGSP_N + DGSP_N] = [0; DGSP_N + DGSP_N];
        input[..DGSP_N].copy_from_slice(seed_user);
        input[DGSP_N..].copy_from_slice(wots_seed);
        Self::hash_simple(&input)
    }

    /// Creates a batch of certificate signing requests (CSRs).
    ///
    /// For a given user seed and a specified batch size, this function
    /// generates a vector of WOTS+ public keys and a vector of corresponding
    /// randomness objects (`DGSPWotsRand`), one for each request.
    ///
    /// # Parameters
    ///
    /// - `seed_user`: The user seed.
    /// - `b`: The number of CSRs to generate.
    ///
    /// # Returns
    ///
    /// A tuple `(Vec<[u8; DGSP_N]>, Vec<DGSP_N>)`
    /// containing the public keys and randomness seeds.
    pub fn csr(seed_user: &[u8; DGSP_N], b: usize) -> (Vec<[u8; DGSP_N]>, Vec<[u8; DGSP_N]>) {
        (0..b)
            .into_par_iter()
            .map(|_| {
                let mut wots_seed: [u8; DGSP_N] = [0; DGSP_N];
                OsRng.fill_bytes(&mut wots_seed);
                let wots_rand = DGSPWotsRand::from_seed(&wots_seed);
                let wp = WotsPlus::new(wots_rand.as_ref());
                let (pk_wots, _) = wp.keygen(&DGSP::wots_key(seed_user, &wots_seed));
                (pk_wots, wots_seed)
            })
            .unzip()
    }

    /// Signs a message using the DGSP scheme.
    ///
    /// The signing process involves:
    /// 1. Recreating the WOTS+ public key and signature using the user seed
    ///    and provided randomness.
    /// 2. Computing the binding values `pi` and `tau`.
    /// 3. Combining a WOTS+ signature with a SPHINCS+ signature from the
    ///    certificate.
    ///
    /// Note that the given `wots_rand` and `cert` are consumed by this
    /// function, enforcing the property of WOTS+ as a "one-time" signature
    /// scheme.
    ///
    /// # Parameters
    ///
    /// - `message`: The message to sign.
    /// - `seed_user`: A reference to the user seed.
    /// - `id`: The user’s identifier.
    /// - `wots_seed`: The given WOTS+ randomness seed used for signing, consumed by
    ///   this function.
    /// - `cert`: The given certificate issued by the manager, consumed by this
    ///   function.
    ///
    /// # Returns
    ///
    /// A `DGSPSignature` structure containing the complete signature.
    pub fn sign(
        message: &[u8],
        seed_user: &[u8; DGSP_N],
        id: u64,
        wots_seed: [u8; DGSP_N],
        cert: DGSPCert,
    ) -> DGSPSignature {
        let wots_rand = DGSPWotsRand::from_seed(&wots_seed);
        let wp = WotsPlus::new(wots_rand.as_ref());
        let (wots_pk, wots_sig) =
            wp.pk_sign_from_sk_seed(message, &DGSP::wots_key(seed_user, &wots_seed));

        let pi = cert.pi;
        let tau = Self::calculate_tau(&wots_pk, &pi, id);
        let zeta = cert.zeta;
        let spx_sig = cert.spx_sig;

        DGSPSignature {
            wots_sig,
            wots_rand,
            zeta,
            spx_sig,
            tau,
        }
    }

    /// Verifies a DGSP signature.
    ///
    /// This function checks that:
    /// 1. The signature has not been revoked.
    /// 2. The WOTS+ public key derived from the signature matches the SPHINCS+
    ///    signature over the constructed message.
    ///
    /// # Parameters
    ///
    /// - `message`: The message that was signed.
    /// - `sig`: A reference to the DGSP signature.
    /// - `revoked_list`: A reference to an object implementing
    ///   `RevokedListInterface`.
    /// - `pk`: A reference to the manager's public key (i.e. SPHINCS+ tree
    ///   root).
    ///
    /// # Returns
    ///
    /// returns `Ok(())` indicating successful verification, or returns
    /// `Err(dgsp::Error)` if verification fails.
    pub fn verify<R: RevokedListInterface>(
        message: &[u8],
        sig: &DGSPSignature,
        revoked_list: &R,
        pk: &DGSPManagerPublicKey,
    ) -> Result<()> {
        if revoked_list.contains(&sig.zeta)? {
            return Err(VerificationError::RevokedSignature)?;
        }
        let wp = WotsPlus::new(sig.wots_rand.as_ref());
        let wots_pk = wp.pk_from_sig(&sig.wots_sig, message);
        let spx_msg = Self::prepare_spx_msg(&wots_pk, &sig.zeta, &sig.tau);
        SphincsPlus::verify(&sig.spx_sig, &spx_msg, &pk.spx_pk)
    }

    /// Checks the validity of a set of certificates.
    ///
    /// For a given user, this function verifies that all the given
    /// certificates are correctly signing their corresponding WOTS+ public
    /// keys. If any certificate fails to pass the check, this function returns
    /// an error.
    ///
    /// # Parameters
    ///
    /// - `id`: The user’s identifier.
    /// - `wotsplus_public_keys`: A slice of WOTS+ public keys.
    /// - `certs`: A vector of certificates references.
    /// - `pk`: The manager's public key reference.
    ///
    /// # Returns
    ///
    /// `Ok(())` indicating that all certificates are valid, or
    /// `Err(dgsp::Error)` otherwise.
    pub fn check_cert(
        id: u64,
        wotsplus_public_keys: &[[u8; DGSP_N]],
        certs: &Vec<DGSPCert>,
        pk: &DGSPManagerPublicKey,
    ) -> Result<()> {
        if wotsplus_public_keys.len() != certs.len() {
            return Err(Error::SizeMismatch);
        }

        wotsplus_public_keys
            .into_par_iter()
            .zip(certs.into_par_iter())
            .try_for_each(|(wots_pk, cert)| {
                let pi = cert.pi;
                let tau = Self::calculate_tau(wots_pk, &pi, id);
                let spx_msg = Self::prepare_spx_msg(wots_pk, &cert.zeta, &tau);
                SphincsPlus::verify(&cert.spx_sig, &spx_msg, &pk.spx_pk)
            })
    }

    /// Judges the manager by checking that the opened signature correctly maps
    /// to the given user ID.
    ///
    /// Recomputes `tau` from the signature's WOTS+ public key and the provided
    /// `pi`. If the computed `tau` does not match the one in the signature, it
    /// returns an error indicating that the wrong ID was opened.
    ///
    /// # Parameters
    ///
    /// - `sig`: The DGSP signature.
    /// - `message`: The signed message.
    /// - `id`: The expected user ID.
    /// - `pi`: The binding value computed during the opening process.
    ///
    /// # Returns
    ///
    /// `Ok(())` indicating success if the judge check passes, otherwise
    /// returns `Err(dgsp::Error::WrongIDOpened(id))`.
    pub fn judge(sig: &DGSPSignature, message: &[u8], id: u64, pi: &[u8; DGSP_N]) -> Result<()> {
        let wp = WotsPlus::new(sig.wots_rand.as_ref());
        let wots_pk = wp.pk_from_sig(&sig.wots_sig, message);
        if sig.tau != Self::calculate_tau(&wots_pk, pi, id) {
            return Err(Error::WrongIDOpened(id));
        }
        Ok(())
    }
}

#[cfg(all(test, any(feature = "in-disk", feature = "in-memory")))]
mod tests {
    use super::*;
    use crate::VerificationError::SphincsPlusVerificationFailed;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    #[cfg(feature = "in-disk")]
    use crate::db::in_disk::{InDiskPLM, InDiskRevokedList};
    #[cfg(feature = "in-memory")]
    use crate::db::in_memory::{InMemoryPLM, InMemoryRevokedList};

    #[cfg(feature = "in-disk")]
    use std::path::PathBuf;

    #[cfg(feature = "in-disk")]
    use tempfile::Builder;

    fn random_str(length: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    fn random_message() -> Vec<u8> {
        let mut rng = OsRng;
        let length: usize = rng.gen_range(1..=20);
        let mut message = vec![0u8; length];
        rng.fill_bytes(&mut message);
        message
    }

    #[cfg(feature = "in-disk")]
    fn in_disk() -> Result<(InDiskPLM, InDiskRevokedList)> {
        // Create a temporary directory for test in the project root
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let temp_dir = Builder::new()
            .prefix("temp_example_db_")
            .tempdir_in(&project_root)
            .map_err(|_| {
                Error::Custom("Failed to create temporary directory in project root".to_string())
            })?;

        // Create PL_M
        let plm = InDiskPLM::open(temp_dir.path().join("dgsp"))?;
        // Create Revoked List:
        let revoked_list = InDiskRevokedList::open(temp_dir.path().join("dgsp"))?;
        Ok((plm, revoked_list))
    }

    #[cfg(feature = "in-memory")]
    fn in_memory() -> Result<(InMemoryPLM, InMemoryRevokedList)> {
        // Create PL_M
        let plm = InMemoryPLM::open("")?;
        // Create manager keys
        let revoked_list = InMemoryRevokedList::open("")?;
        Ok((plm, revoked_list))
    }

    fn test_dgsp_full<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        // Create manager keys
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        // Create a user and join to DGSP
        let seed = DGSP::keygen_user();
        let username = random_str(10);
        let (id, cid_star) = DGSP::join(&skm.msk.hash_secret, username.as_str(), &plm).unwrap();

        // Create a batch of CSR
        const B: usize = 3;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed, B);

        // Obtain certificates for the given csr batch
        let mut certs = DGSP::gen_cert(&skm, id, &cid_star, &wots_pks, &plm).unwrap();

        // Make sure the given certificates are correctly created by the manager.
        DGSP::check_cert(id, &wots_pks, &certs, &pkm).unwrap();

        // Sign a single message
        let message = random_message();

        let wots_rand = wots_rands.pop().unwrap();
        let cert = certs.pop().unwrap();
        let wots_pk = wots_pks.pop().unwrap();
        let sig = DGSP::sign(&message, &seed, id, wots_rand, cert);

        // Verify the signature
        DGSP::verify(&message, &sig, &revoked_list, &pkm).unwrap();

        // Obtain id, username, and proof from sig
        let cid = DGSP::calculate_cid(&skm.msk.hash_secret, id);
        let pi = DGSP::calculate_pi(&wots_pk, &cid);
        assert_eq!(
            DGSP::open(&skm.msk, &plm, &sig, &message).unwrap(),
            (id, username, pi)
        );

        // Judge the manager and make sure it is following the protocol
        DGSP::judge(&sig, &message, id, &pi).unwrap();

        // Revoke a user and its certificates
        DGSP::revoke(&skm.msk.aes_key, &plm, &[id], &revoked_list).unwrap();
        assert!(revoked_list.contains(&sig.zeta).unwrap());

        for cert in &certs {
            assert!(revoked_list.contains(&cert.zeta).unwrap());
        }

        // Make sure no cert will be created for that id from now on.
        let (wots_pks_new, _) = DGSP::csr(&seed, 1);
        assert_eq!(
            DGSP::gen_cert(&skm, id, &cid, &wots_pks_new, &plm),
            Err(Error::InvalidCertReq)
        );

        // Make sure no signatures created by the revoked user will verify
        let wots_rand_new = wots_rands.pop().unwrap();
        let cert_new = certs.pop().unwrap();
        let message_new = random_message();
        let sig_new = DGSP::sign(&message_new, &seed, id, wots_rand_new, cert_new);
        assert_eq!(
            DGSP::verify(&message_new, &sig_new, &revoked_list, &pkm),
            Err(Error::VerificationFailed(
                VerificationError::RevokedSignature
            ))
        );
    }

    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_full_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_full(plm, revoked_list);
    }

    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_full_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_full(plm, revoked_list);
    }

    fn test_dgsp_manager_trust<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_star_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);

        // Test manager with fake credentials:
        let fake_id = 6u64;
        let mut fake_cid = cid_star_u0;
        fake_cid[0] ^= 1;
        assert!(DGSP::gen_cert(&skm, fake_id, &cid_star_u0, &wots_pks, &plm).is_err());
        assert_eq!(
            DGSP::gen_cert(&skm, id_u0, &fake_cid, &wots_pks, &plm),
            Err(Error::InvalidCertReq)
        );
        assert!(DGSP::gen_cert(&skm, fake_id, &fake_cid, &wots_pks, &plm).is_err());

        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_star_u0, &wots_pks, &plm).unwrap();
        DGSP::check_cert(id_u0, &wots_pks, &certs, &pkm).unwrap();

        let wots_pk = wots_pks.pop().unwrap();
        let cert = certs.pop().unwrap();
        let cid_u0 = DGSP::calculate_cid(&skm.msk.hash_secret, id_u0);
        let pi = DGSP::calculate_pi(&wots_pk, &cid_u0);
        let mut fake_tau = DGSP::calculate_tau(&wots_pk, &pi, id_u0);
        fake_tau[0] ^= 1;

        // Prepare a fake certificate
        let spx_msg_fake = DGSP::prepare_spx_msg(&wots_pk, &cert.zeta, &fake_tau);
        let spx_sig_fake = SphincsPlus::sign(&spx_msg_fake, &skm.spx_sk).unwrap();
        let fake_cert = DGSPCert {
            zeta: cert.zeta,
            pi,
            spx_sig: spx_sig_fake,
        };
        assert!(matches!(
            DGSP::check_cert(id_u0, &[wots_pk], &vec!(fake_cert.clone()), &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));

        // Even signing without checking it should never be verified
        let message = random_message();
        let wots_rand = wots_rands.pop().unwrap();
        let sig_fake = DGSP::sign(&message, &seed_u0, id_u0, wots_rand.clone(), fake_cert);
        assert!(matches!(
            DGSP::verify(&message, &sig_fake, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));

        // Now let's create a valid signature with the correct cert
        let sig = DGSP::sign(&message, &seed_u0, id_u0, wots_rand, cert);
        DGSP::verify(&message, &sig, &revoked_list, &pkm).unwrap();

        // A new user joins the group
        let username_u1 = "dgsp user 1";
        let (id_u1, _) = DGSP::join(&skm.msk.hash_secret, username_u1, &plm).unwrap();

        assert_eq!(
            DGSP::open(&skm.msk, &plm, &sig, &message).unwrap(),
            (id_u0, username_u0.to_string(), pi)
        );

        DGSP::judge(&sig, &message, id_u0, &pi).unwrap();

        // Assume manager returning a wrong id after opening the signature
        assert_eq!(
            DGSP::judge(&sig, &message, id_u1, &pi),
            Err(Error::WrongIDOpened(id_u1))
        );
    }

    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_manager_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_manager_trust(plm, revoked_list);
    }

    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_manager_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_manager_trust(plm, revoked_list);
    }

    fn test_dgsp_join<P: PLMInterface>(plm: P) {
        let (_, skm) = DGSP::keygen_manager().unwrap();

        let username = random_str(10);
        DGSP::join(&skm.msk.hash_secret, username.as_str(), &plm).unwrap();
        assert_eq!(
            DGSP::join(&skm.msk.hash_secret, username.as_str(), &plm),
            Err(Error::UsernameAlreadyExists(username))
        );
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_join_in_disk() {
        let (plm, _) = in_disk().unwrap();
        test_dgsp_join(plm);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_join_in_memory() {
        let (plm, _) = in_memory().unwrap();
        test_dgsp_join(plm);
    }

    fn test_dgsp_gen_cert<P: PLMInterface>(plm: P) {
        let (_, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, _) = DGSP::csr(&seed_u0, B);
        DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        // Test manager with fake credentials:
        let fake_id = id_u0 ^ 1u64;
        let mut fake_cid = cid_u0;
        fake_cid[0] ^= 1u8;
        assert!(DGSP::gen_cert(&skm, fake_id, &cid_u0, &wots_pks, &plm).is_err());
        assert_eq!(
            DGSP::gen_cert(&skm, id_u0, &fake_cid, &wots_pks, &plm),
            Err(Error::InvalidCertReq)
        );
        assert!(DGSP::gen_cert(&skm, fake_id, &fake_cid, &wots_pks, &plm).is_err());

        let username_u1 = "dgsp user 1";
        let (id_u1, cid_u1) = DGSP::join(&skm.msk.hash_secret, username_u1, &plm).unwrap();

        // Test manager with incorrect credentials:
        assert_eq!(
            DGSP::gen_cert(&skm, id_u0, &cid_u1, &wots_pks, &plm),
            Err(Error::InvalidCertReq)
        );
        assert_eq!(
            DGSP::gen_cert(&skm, id_u1, &cid_u0, &wots_pks, &plm),
            Err(Error::InvalidCertReq)
        );
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_gen_cert_in_disk() {
        let (plm, _) = in_disk().unwrap();
        test_dgsp_gen_cert(plm);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_gen_cert_in_memory() {
        let (plm, _) = in_memory().unwrap();
        test_dgsp_gen_cert(plm);
    }

    fn test_dgsp_check_cert<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed = DGSP::keygen_user();
        let username = "dgsp user";
        let (id, cid) = DGSP::join(&skm.msk.hash_secret, username, &plm).unwrap();

        const B: usize = 2;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed, B);

        let mut certs = DGSP::gen_cert(&skm, id, &cid, &wots_pks, &plm).unwrap();
        DGSP::check_cert(id, &wots_pks, &certs, &pkm).unwrap();

        // Unequal lengths of WOTS+ pk list and certificate list
        let wots_pk = wots_pks.pop().unwrap();
        assert_eq!(
            DGSP::check_cert(id, &wots_pks, &certs, &pkm),
            Err(Error::SizeMismatch)
        );

        // Prepare a fake certificate
        let pi = DGSP::calculate_pi(&wots_pk, &cid);
        let mut fake_tau = DGSP::calculate_tau(&wots_pk, &pi, id);
        fake_tau[0] ^= 1;

        let cert = certs.pop().unwrap();

        let spx_msg_fake = DGSP::prepare_spx_msg(&wots_pk, &cert.zeta, &fake_tau);
        let spx_sig_fake = SphincsPlus::sign(&spx_msg_fake, &skm.spx_sk).unwrap();

        let fake_cert = DGSPCert {
            zeta: cert.zeta,
            pi,
            spx_sig: spx_sig_fake,
        };

        assert!(matches!(
            DGSP::check_cert(id, &[wots_pk], &vec!(fake_cert.clone()), &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));

        // Even signing without checking it should never be verified
        let message = random_message();
        let wots_rand = wots_rands.pop().unwrap();
        let sig_fake = DGSP::sign(&message, &seed, id, wots_rand, fake_cert);
        assert!(matches!(
            DGSP::verify(&message, &sig_fake, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_check_cert_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_check_cert(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_check_cert_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_check_cert(plm, revoked_list);
    }

    fn test_dgsp_sign<P: PLMInterface, R: RevokedListInterface>(plm: P, revoked_list: R) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        let sig_wrong_seed = DGSP::sign(&m, &seed_u0, id_u0, wr, c);
        DGSP::verify(&m, &sig_wrong_seed, &revoked_list, &pkm).unwrap();
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_seed<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        let mut seed_u1 = seed_u0;
        seed_u1[0] ^= 1;

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect seed:
        let sig_wrong_seed = DGSP::sign(&m, &seed_u1, id_u0, wr, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_seed, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_seed_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_seed(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_seed_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_seed(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_id<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        let username_u1 = "dgsp user 1";
        let (id_u1, _) = DGSP::join(&skm.msk.hash_secret, username_u1, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect id:
        let sig_wrong_id = DGSP::sign(&m, &seed_u0, id_u1, wr, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_id, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_id_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_id(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_id_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_id(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_tau<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        let username_u1 = "dgsp user 1";
        let (_, _) = DGSP::join(&skm.msk.hash_secret, username_u1, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let mut c = certs.pop().unwrap();
        c.zeta[0] ^= 1;

        // Sign with incorrect cid:
        let sig_wrong_tau = DGSP::sign(&m, &seed_u0, id_u0, wr, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_tau, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_tau_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_tau(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_tau_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_tau(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_wots_sgn_seed<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        let mut wrong_wr_seed = wr;
        wrong_wr_seed[0] ^= 1;

        let sig_wrong_wr_seed = DGSP::sign(&m, &seed_u0, id_u0, wrong_wr_seed, c);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_wr_seed, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_wots_sgn_seed_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_wots_sgn_seed(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_wots_sgn_seed_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_wots_sgn_seed(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_cert_zeta<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect certificate zeta :
        let wrong_c_zeta = DGSPCert {
            zeta: {
                let mut fake_zeta = c.zeta;
                fake_zeta[0] ^= 1;
                fake_zeta
            },
            ..c
        };
        let sig_wrong_cert_zeta = DGSP::sign(&m, &seed_u0, id_u0, wr, wrong_c_zeta);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_cert_zeta, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_cert_zeta_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_cert_zeta(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_cert_zeta_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_cert_zeta(plm, revoked_list);
    }

    fn test_dgsp_sign_with_wrong_cert_spx_sig<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();

        // Sign with incorrect certificate SPHINCS+ signature :
        let wrong_c_spx = DGSPCert {
            spx_sig: {
                let mut fake_spx_sig = [0u8; SPX_BYTES];
                fake_spx_sig.copy_from_slice(c.spx_sig.as_ref());
                fake_spx_sig[0] ^= 1;
                fake_spx_sig.into()
            },
            ..c
        };
        let sig_wrong_cert_spx = DGSP::sign(&m, &seed_u0, id_u0, wr, wrong_c_spx);
        assert!(matches!(
            DGSP::verify(&m, &sig_wrong_cert_spx, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_sign_with_wrong_cert_spx_sig_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_sign_with_wrong_cert_spx_sig(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_sign_with_wrong_cert_spx_sig_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_sign_with_wrong_cert_spx_sig(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_message<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, wr, c);

        // Try to forge signature with fake message
        let mut fake_message = m.clone();
        fake_message[0] ^= 1;
        assert!(matches!(
            DGSP::verify(&fake_message, &sig, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_message_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_message(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_message_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_message(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_wots_sig<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, wr, c);

        // Try to forge signature with fake WOTS+ signature
        let sig_fake_wots_sig = DGSPSignature {
            wots_sig: {
                let mut fake_wots_sig = sig.wots_sig;
                fake_wots_sig[0] ^= 1;
                fake_wots_sig
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_wots_sig, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_wots_sig_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_wots_sig(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_wots_sig_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_wots_sig(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_zeta<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, wr, c);

        // Try to forge signature with fake certificate zeta
        let sig_fake_zeta = DGSPSignature {
            zeta: {
                let mut fake_zeta = sig.zeta;
                fake_zeta[0] ^= 1;
                fake_zeta
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_zeta, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_zeta_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_zeta(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_zeta_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_zeta(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_spx_sig<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, wr, c);

        // Try to forge signature with fake SPHINCS+ signature
        let sig_fake_spx_sig = DGSPSignature {
            spx_sig: {
                let mut fake_spx_sig = [0u8; SPX_BYTES];
                fake_spx_sig.copy_from_slice(sig.spx_sig.as_ref());
                fake_spx_sig[0] ^= 1;
                fake_spx_sig.into()
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_spx_sig, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_spx_sig_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_spx_sig(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_spx_sig_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_spx_sig(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_wots_sgn_seed<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, wr, c);

        // Try to forge signature with fake WOTS+ SGN seed
        let sig_fake_wots_sgn_seed = DGSPSignature {
            wots_rand: DGSPWotsRand({
                let mut fake_wots_sgn_seed = sig.wots_rand.0;
                fake_wots_sgn_seed[0] ^= 1;
                fake_wots_sgn_seed
            }),
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_wots_sgn_seed, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_wots_sgn_seed_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_wots_sgn_seed(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_wots_sgn_seed_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_wots_sgn_seed(plm, revoked_list);
    }

    fn test_dgsp_verify_fake_tau<P: PLMInterface, R: RevokedListInterface>(
        plm: P,
        revoked_list: R,
    ) {
        let (pkm, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);
        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_u0, &wots_pks, &plm).unwrap();

        let m = random_message();
        let wr = wots_rands.pop().unwrap();
        let c = certs.pop().unwrap();
        let sig = DGSP::sign(&m, &seed_u0, id_u0, wr, c);

        // Try to forge signature with fake tau
        let sig_fake_tau = DGSPSignature {
            tau: {
                let mut fake_tau = sig.tau;
                fake_tau[0] ^= 1;
                fake_tau
            },
            ..sig
        };
        assert!(matches!(
            DGSP::verify(&m, &sig_fake_tau, &revoked_list, &pkm),
            Err(Error::VerificationFailed(SphincsPlusVerificationFailed(_)))
        ));
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_verify_fake_tau_in_disk() {
        let (plm, revoked_list) = in_disk().unwrap();
        test_dgsp_verify_fake_tau(plm, revoked_list);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_verify_fake_tau_in_memory() {
        let (plm, revoked_list) = in_memory().unwrap();
        test_dgsp_verify_fake_tau(plm, revoked_list);
    }

    fn test_dgsp_open<P: PLMInterface>(plm: P) {
        let (_, skm) = DGSP::keygen_manager().unwrap();

        let seed_u0 = DGSP::keygen_user();
        let username_u0 = "dgsp user 0";
        let (id_u0, cid_star_u0) = DGSP::join(&skm.msk.hash_secret, username_u0, &plm).unwrap();

        const B: usize = 1;
        let (mut wots_pks, mut wots_rands) = DGSP::csr(&seed_u0, B);

        let mut certs = DGSP::gen_cert(&skm, id_u0, &cid_star_u0, &wots_pks, &plm).unwrap();

        let wots_pk = wots_pks.pop().unwrap();
        let cert = certs.pop().unwrap();
        let cid_u0 = DGSP::calculate_cid(&skm.msk.hash_secret, id_u0);
        let pi = DGSP::calculate_pi(&wots_pk, &cid_u0);

        let message = random_message();
        let wots_rand = wots_rands.pop().unwrap();
        let sig = DGSP::sign(&message, &seed_u0, id_u0, wots_rand, cert);

        // A new user joins the group
        let username_u1 = "dgsp user 1";
        let (id_u1, _) = DGSP::join(&skm.msk.hash_secret, username_u1, &plm).unwrap();

        assert_eq!(
            DGSP::open(&skm.msk, &plm, &sig, &message).unwrap(),
            (id_u0, username_u0.to_string(), pi)
        );
        DGSP::judge(&sig, &message, id_u0, &pi).unwrap();

        // If a wrong id is given for an opened signature, it won't be accepted.
        assert_eq!(
            DGSP::judge(&sig, &message, id_u1, &pi),
            Err(Error::WrongIDOpened(id_u1))
        );
    }
    #[test]
    #[cfg(feature = "in-disk")]
    fn test_dgsp_open_in_disk() {
        let (plm, _) = in_disk().unwrap();
        test_dgsp_open(plm);
    }
    #[test]
    #[cfg(feature = "in-memory")]
    fn test_dgsp_open_in_memory() {
        let (plm, _) = in_memory().unwrap();
        test_dgsp_open(plm);
    }
}
