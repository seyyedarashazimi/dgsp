//! # Winternitz One-Time Signature Scheme Plus (W-OTS+)
//!
//! This module implements the W-OTS+ scheme, a crucial part of DGSP hash-based group signature.
//! W-OTS+ provides one-time signature functionality with efficient key generation, signing, and
//! verification processes. It conforms to SPHINCS+ definition of W-OTS+.
//!
//! To incorporates `WOTS-T` safety principles to ensure the security of derived keys and
//! signatures against multi-target, a proper [`Adrs`] is set per each keypair and generated
//! signature. The `Adrs` alongside the random seeds, makes the scheme secure.
//!
//! ## W-OTS+ and DGSP
//!
//! This implementation supports DGSP parameter sets for SHA2 and SHAKE hash functions, which are
//! derived by the choice of the parameters of SPHINCS+ scheme.
//! The associated parameter sets and hasher variants are selected at compile time using feature
//! flags.
//!
//! ## Important Note
//!
//! This W-OTS+ implementation is provided to be used in a bigger signature scheme like DGSP and
//! optimized for that use. Therefore, it is not suggested to be used as a standalone signature
//! scheme.

use crate::hash::DGSPHasher;
use crate::sphincs_plus::{
    SPX_N, SPX_WOTS_BYTES, SPX_WOTS_LEN, SPX_WOTS_LEN1, SPX_WOTS_LEN2, SPX_WOTS_LOGW, SPX_WOTS_W,
};
use crate::utils::u64_to_bytes;
use crate::wots_plus::adrs::Adrs;
use crate::wots_plus::adrs::AdrsType::{WotsHash, WotsPk, WotsPrf};

pub mod adrs;

/// Encapsulates the W-OTS+ operations and maintains state for the hasher and address randomness.
#[derive(Clone, Debug)]
pub struct WotsPlus {
    hasher: DGSPHasher,
}

impl WotsPlus {
    /// Creates a new `WotsPlus` instance with the specified public seed.
    ///
    /// This constructor initializes the WOTS+ state using the provided public seed.
    /// The public seed is used for hashing operations and is crucial for the security
    /// of the scheme.
    ///
    /// # Arguments
    ///
    /// * `pub_seed` - A `SPX_N`-byte public seed used for the hashing operations in WOTS+.
    ///
    /// # Returns
    ///
    /// A new instance of `WotsPlus` initialized with the given public seed.
    pub fn new(pub_seed: &[u8]) -> Self {
        let hasher = DGSPHasher::new(pub_seed);
        Self { hasher }
    }

    /// Generates a WOTS+ keypair.
    ///
    /// This method generates a private key (`sk`) and the corresponding public key (`pk`)
    /// based on the given secret key seed (`sk_seed`).
    ///
    /// # Arguments
    ///
    /// * `sk_seed` - A byte slice used as the seed for generating the public and private keys,
    ///   expecting to be `SPX_N` bytes.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `[u8; SPX_N]` - The generated compressed public key.
    /// * `[u8; SPX_WOTS_BYTES]` - The corresponding secret key.
    pub fn keygen(&self, sk_seed: &[u8]) -> ([u8; SPX_N], [u8; SPX_WOTS_BYTES]) {
        let mut adrs = Adrs::from(WotsHash);
        self.gen_pk_sk(sk_seed, 0, &mut adrs)
    }

    /// Signs a message using the provided WOTS+ private key.
    ///
    /// This method generates a WOTS+ signature for the given message using the provided
    /// private key (`sk`).
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice representing the message to be signed.
    /// * `sk` - A byte slice containing the WOTS+ private key, expecting to be SPX_WOTS_BYTES bytes.
    ///
    /// # Returns
    ///
    /// A `[u8; SPX_WOTS_BYTES]` array containing the generated signature.
    pub fn sign(&self, message: &[u8], sk: &[u8]) -> [u8; SPX_WOTS_BYTES] {
        let mut hm = [0u8; SPX_N];
        self.hash_m(&mut hm, message);
        let mut adrs = Adrs::from(WotsHash);
        self.gen_sig(sk, 0, &mut adrs, &hm)
    }

    /// Signs a message using the secret key seed (`sk_seed`).
    ///
    /// This method generates a WOTS+ signature for the given message by deriving
    /// the private key from the provided secret key seed.
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice representing the message to be signed.
    /// * `sk_seed` - A `SPX_N`-byte array containing the secret key seed.
    ///
    /// # Returns
    ///
    /// A `[u8; SPX_WOTS_BYTES]` array containing the generated signature.
    pub fn sign_from_sk_seed(&self, message: &[u8], sk_seed: &[u8; SPX_N]) -> [u8; SPX_WOTS_BYTES] {
        let mut hm = [0u8; SPX_N];
        self.hash_m(&mut hm, message);
        let mut adrs = Adrs::from(WotsPrf);
        self.gen_sig_from_sk_seed(sk_seed, 0, &mut adrs, &hm)
    }

    pub fn pk_sign_from_sk_seed(
        &self,
        message: &[u8],
        sk_seed: &[u8; SPX_N],
    ) -> ([u8; SPX_N], [u8; SPX_WOTS_BYTES]) {
        let mut hm = [0u8; SPX_N];
        self.hash_m(&mut hm, message);
        let mut adrs = Adrs::from(WotsPrf);
        self.gen_pk_and_sig_from_sk_seed(sk_seed, 0, &mut adrs, &hm)
    }

    /// Verifies a WOTS+ signature for a given message and public key.
    ///
    /// This method checks the validity of a WOTS+ signature for the specified message
    /// using the provided public key. It computes the expected public key from the
    /// signature and compares it to the provided public key.
    ///
    /// # Arguments
    ///
    /// * `signature` - A byte slice containing the WOTS+ signature to verify.
    /// * `message` - A byte slice representing the message associated with the signature.
    /// * `pk` - A byte slice containing the WOTS+ public key.
    ///
    /// # Returns
    ///
    /// A `bool` indicating whether the signature is valid:
    /// * `true` - The signature is valid.
    /// * `false` - The signature is invalid.
    pub fn verify(&self, signature: &[u8], message: &[u8], pk: &[u8]) -> bool {
        let mut hm = [0u8; SPX_N];
        self.hash_m(&mut hm, message);
        let mut adrs = Adrs::from(WotsHash);
        let calculated_pk = self.wots_pk_from_sig(signature, &hm, 0, &mut adrs);
        calculated_pk == pk
    }

    /// Computes the public key from a WOTS+ signature and message.
    ///
    /// This method derives the WOTS+ public key from the given signature and message.
    /// It can be used to verify that the derived public key matches an expected public key.
    ///
    /// # Arguments
    ///
    /// * `signature` - A byte slice containing the WOTS+ signature.
    /// * `message` - A byte slice representing the message associated with the signature.
    ///
    /// # Returns
    ///
    /// A `[u8; SPX_N]` array containing the computed compressed public key.
    pub fn pk_from_sig(&self, signature: &[u8], message: &[u8]) -> [u8; SPX_N] {
        let mut hm = [0u8; SPX_N];
        self.hash_m(&mut hm, message);
        let mut adrs = Adrs::from(WotsHash);
        self.wots_pk_from_sig(signature, &hm, 0, &mut adrs)
    }

    /// Calculates hash of message, i.e. out = HASH(pub_seed || message).
    /// Normally, pub_seed is sgn_seed in DGSP. The output is `SPX_N` bytes.
    pub fn hash_m(&self, output: &mut [u8], m: &[u8]) {
        self.hasher.hash_m(output, m);
    }

    /// Computes the chaining function.
    /// out and in have to be n-byte arrays.
    ///
    /// Interprets in as start-th value of the chain.
    /// addr has to contain the address of the chain.
    fn gen_chain(
        &self,
        output: &mut [u8],
        input: &[u8],
        start: usize,
        steps: usize,
        adrs: &mut Adrs,
    ) {
        // Initialize buf value at position 'start'.
        output[..SPX_N].copy_from_slice(input[..SPX_N].as_ref());

        // Iterate 'steps' calls to the hash function F.
        for i in start..(start + steps) {
            if i >= SPX_WOTS_W {
                break;
            }
            adrs.set_hash_addr(i as u32);
            self.hasher.spx_f_inplace(output[..SPX_N].as_mut(), 1, adrs);
        }
    }

    /// Converts an array of bytes into integers in base `w`.
    fn base_w(output: &mut [u32], out_len: usize, input: &[u8]) {
        let mut bits = 0;
        let mut total: u8 = 0;
        let mut input_index = 0;

        for out in output[..out_len].iter_mut() {
            if bits == 0 {
                // Load a new byte from input
                total = input[input_index];
                input_index += 1;
                bits += 8;
            }

            bits -= SPX_WOTS_LOGW;
            // Extract SPX_WOTS_LOGW bits and convert to u32
            *out = ((total >> bits) & ((SPX_WOTS_W - 1) as u8)) as u32;
        }
    }

    /// Computes the WOTS+ checksum over a message (in base_w).
    fn wots_checksum(csum_base_w: &mut [u32], msg_base_w: &[u32]) {
        let mut csum: u32 = 0;

        // Compute the checksum
        for &msg in msg_base_w.iter().take(SPX_WOTS_LEN1) {
            csum += (SPX_WOTS_W as u32) - 1 - msg;
        }

        // Make sure expected empty zero bits are the least significant bits.
        // Prepare the checksum for conversion to base_w
        let shift = (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8;
        csum <<= shift;

        // Convert the checksum to bytes
        let csum_bytes = u64_to_bytes(csum as u64);

        // Convert checksum bytes to base_w
        Self::base_w(csum_base_w, SPX_WOTS_LEN2, &csum_bytes);
    }

    /// Takes a message and derives the matching chain lengths.
    fn chain_lengths(lengths: &mut [u32], msg: &[u8]) {
        Self::base_w(lengths, SPX_WOTS_LEN1, msg);
        let lengths_msg = lengths[..SPX_WOTS_LEN1].to_vec();
        Self::wots_checksum(lengths[SPX_WOTS_LEN1..].as_mut(), &lengths_msg);
    }

    /// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
    ///
    /// Writes the computed public key to 'pk'.
    fn wots_pk_from_sig(
        &self,
        sig: &[u8],
        hm: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
    ) -> [u8; SPX_N] {
        let mut pk_buf = [0_u8; SPX_WOTS_BYTES];
        let mut pk_adrs = *adrs;

        let mut lengths = [0_u32; SPX_WOTS_LEN];
        Self::chain_lengths(lengths.as_mut(), hm);

        adrs.set_type(WotsHash);
        for i in 0..SPX_WOTS_LEN {
            adrs.set_chain_addr(i as u32);
            self.gen_chain(
                pk_buf[i * SPX_N..(i + 1) * SPX_N].as_mut(),
                sig[i * SPX_N..(i + 1) * SPX_N].as_ref(),
                lengths[i] as usize,
                SPX_WOTS_W - 1 - (lengths[i] as usize),
                adrs,
            );
        }

        pk_adrs.set_type(WotsPk);
        pk_adrs.set_keypair_addr(leaf_idx);
        // Do the final thash to generate the public keys
        let mut pk = [0u8; SPX_N];
        self.hasher
            .spx_f(pk.as_mut(), &pk_buf, SPX_WOTS_LEN, &pk_adrs);

        pk
    }

    fn gen_pk_sk(
        &self,
        sk_seed: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
    ) -> ([u8; SPX_N], [u8; SPX_WOTS_BYTES]) {
        let mut pk_buf = [0_u8; SPX_WOTS_BYTES];
        let mut sk_buf = [0_u8; SPX_WOTS_BYTES];
        let mut buf_index: usize;

        let mut pk_adrs = *adrs;
        let mut sk_adrs = *adrs;
        sk_adrs.set_type(WotsPrf);
        sk_adrs.set_keypair_addr(leaf_idx);

        for i in 0..SPX_WOTS_LEN {
            buf_index = i * SPX_N;

            // Start with the secret seed
            sk_adrs.set_chain_addr(i as u32);
            sk_adrs.set_hash_addr(0_u32);
            sk_adrs.set_type(WotsPrf);
            self.hasher.spx_prf(
                sk_buf[buf_index..buf_index + SPX_N].as_mut(),
                sk_seed,
                &sk_adrs,
            );

            sk_adrs.set_type(WotsHash);
            self.gen_chain(
                pk_buf[buf_index..buf_index + SPX_N].as_mut(),
                sk_buf[buf_index..buf_index + SPX_N].as_ref(),
                0,
                SPX_WOTS_W - 1,
                &mut sk_adrs,
            );
        }

        pk_adrs.set_type(WotsPk);
        pk_adrs.set_keypair_addr(leaf_idx);

        // Do the final thash to generate the public keys
        let mut pk = [0u8; SPX_N];
        self.hasher
            .spx_f(pk.as_mut(), &pk_buf, SPX_WOTS_LEN, &pk_adrs);

        (pk, sk_buf)
    }

    fn gen_sig(
        &self,
        sk: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
        hm: &[u8],
    ) -> [u8; SPX_WOTS_BYTES] {
        let mut sig_buf = [0_u8; SPX_WOTS_BYTES];
        let mut buf_index: usize;

        // Calculate chain steps for the given message
        let mut steps = [0_u32; SPX_WOTS_LEN];
        Self::chain_lengths(steps.as_mut(), hm);

        adrs.set_keypair_addr(leaf_idx);
        adrs.set_type(WotsHash);
        for i in 0..SPX_WOTS_LEN {
            buf_index = i * SPX_N;

            // Calculate signature from sk, based on the steps
            self.gen_chain(
                sig_buf[buf_index..buf_index + SPX_N].as_mut(),
                sk[buf_index..buf_index + SPX_N].as_ref(),
                0,
                steps[i] as usize,
                adrs,
            );
        }
        sig_buf
    }

    fn gen_pk_and_sig_from_sk_seed(
        &self,
        sk_seed: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
        message: &[u8],
    ) -> ([u8; SPX_N], [u8; SPX_WOTS_BYTES]) {
        let mut sk_buf = [0_u8; SPX_N];
        let mut sig_buf = [0_u8; SPX_WOTS_BYTES];
        let mut pk_buf = [0_u8; SPX_WOTS_BYTES];
        let mut buf_index: usize;

        // Calculate chain steps for the given message
        let mut steps = [0_u32; SPX_WOTS_LEN];
        Self::chain_lengths(steps.as_mut(), message);

        let mut pk_adrs = *adrs;
        let mut sk_adrs = *adrs;
        sk_adrs.set_type(WotsPrf);
        sk_adrs.set_keypair_addr(leaf_idx);

        for i in 0..SPX_WOTS_LEN {
            buf_index = i * SPX_N;

            // Start with the secret seed
            sk_adrs.set_chain_addr(i as u32);
            sk_adrs.set_hash_addr(0_u32);
            sk_adrs.set_type(WotsPrf);
            self.hasher.spx_prf(sk_buf.as_mut(), sk_seed, &sk_adrs);

            pk_buf[buf_index..buf_index + SPX_N].copy_from_slice(&sk_buf);

            sk_adrs.set_type(WotsHash);
            for j in 0.. {
                if j == steps[i] as usize {
                    sig_buf[buf_index..buf_index + SPX_N]
                        .copy_from_slice(pk_buf[buf_index..buf_index + SPX_N].as_ref());
                }

                if j == SPX_WOTS_W - 1 {
                    break;
                }

                sk_adrs.set_hash_addr(j as u32);
                self.hasher.spx_f_inplace(
                    pk_buf[buf_index..buf_index + SPX_N].as_mut(),
                    1,
                    &sk_adrs,
                );
            }
        }

        pk_adrs.set_type(WotsPk);
        pk_adrs.set_keypair_addr(leaf_idx);

        // Do the final thash to generate the public keys
        let mut pk = [0u8; SPX_N];
        self.hasher
            .spx_f(pk.as_mut(), &pk_buf, SPX_WOTS_LEN, &pk_adrs);

        (pk, sig_buf)
    }

    fn gen_sig_from_sk_seed(
        &self,
        sk_seed: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
        hm: &[u8],
    ) -> [u8; SPX_WOTS_BYTES] {
        let mut sk_buf = [0_u8; SPX_N];
        let mut sig_buf = [0_u8; SPX_WOTS_BYTES];
        let mut buf_index: usize;

        // Calculate chain steps for the given message
        let mut steps = [0_u32; SPX_WOTS_LEN];
        Self::chain_lengths(steps.as_mut(), hm);

        let mut sk_adrs = *adrs;

        sk_adrs.set_type(WotsPrf);
        sk_adrs.set_keypair_addr(leaf_idx);
        for i in 0..SPX_WOTS_LEN {
            buf_index = i * SPX_N;

            // Start with the secret seed
            sk_adrs.set_chain_addr(i as u32);
            sk_adrs.set_hash_addr(0_u32);
            sk_adrs.set_type(WotsPrf);
            self.hasher.spx_prf(sk_buf.as_mut(), sk_seed, &sk_adrs);

            adrs.set_keypair_addr(leaf_idx);
            adrs.set_type(WotsHash);
            // Calculate signature from sk, based on the steps
            self.gen_chain(
                sig_buf[buf_index..buf_index + SPX_N].as_mut(),
                sk_buf.as_ref(),
                0,
                steps[i] as usize,
                adrs,
            );
        }

        sig_buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_wots_plus() {
        let mut pub_seed = [0; SPX_N];
        let mut sk_seed = [0; SPX_N];
        OsRng.fill_bytes(&mut pub_seed);
        OsRng.fill_bytes(&mut sk_seed);

        let wp = WotsPlus::new(&pub_seed);

        let (pk, sk) = wp.keygen(&sk_seed);

        let mut rng = OsRng;
        let length: usize = rng.gen_range(1..=20);
        let mut message = vec![0u8; length];
        rng.fill_bytes(&mut message);

        let signature = wp.sign(&message, &sk);
        assert!(wp.verify(&signature, &message, &pk));

        let mut fake_signature = signature;
        fake_signature[0] ^= 1;
        assert!(!wp.verify(&fake_signature, &message, &pk));

        let wp_same = WotsPlus::new(&pub_seed);
        let (pk_same, _) = wp_same.keygen(&sk_seed);
        assert_eq!(pk, pk_same);

        let sig_same = wp.sign_from_sk_seed(&message, &sk_seed);
        assert_eq!(sig_same, signature);
        assert!(wp_same.verify(&sig_same, &message, &pk_same));
        assert_eq!(wp_same.pk_from_sig(&sig_same, &message), pk);

        let (pk_same2, sig_same2) = wp_same.pk_sign_from_sk_seed(&message, &sk_seed);
        assert_eq!(pk_same2, pk);
        assert_eq!(sig_same2, signature);

        println!("WOTS+ keygen, signing, and verify tests passed.");
    }
}
