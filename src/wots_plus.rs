//! # Winternitz One-Time Signature Scheme Plus (W-OTS+)
//!
//! This module implements the W-OTS+ scheme, a crucial part of DGSP hash-based group signature.
//! W-OTS+ provides one-time signature functionality with efficient key generation, signing, and
//! verification processes. It conforms to SPHINCS+ definition of W-OTS+.
//!
//! To incorporates `WOTS-T` safety principles to ensure the security of derived keys and
//! signatures against multi-target, a proper [`Adrs`] is set per each keypair and generated
//! signature. The `Adrs` contains a 64-bit random value, which alongside the random seeds, makes
//! the scheme secure.
//!
//! ## W-OTS+ and DGSP
//!
//! This implementation supports DGSP parameter sets for SHA2 and SHAKE hash functions, which are
//! derived by the choice of the parameters of SPHINCS+ scheme.
//! The associated parameter sets and hasher variants are selected at compile time using feature
//! flags.
//!
//! ## Important
//!
//! This W-OTS+ implementation is provided to be used in a bigger signature scheme like DGSP and
//! optimized for that use. Therefore, it is not suggested to be used as an standalone signature
//! scheme.
//!
//! ## Tests
//!
//! Comprehensive tests are provided to validate key generation, signing, verification, and consistency of derived public keys.

use crate::hash::DGSPHasher;
use crate::sphincs_plus::{
    SPX_N, SPX_WOTS_BYTES, SPX_WOTS_LEN, SPX_WOTS_LEN1, SPX_WOTS_LEN2, SPX_WOTS_LOGW,
    SPX_WOTS_PK_BYTES, SPX_WOTS_W,
};
use crate::utils::u64_to_bytes;
use crate::wots_plus::adrs::Adrs;
use crate::wots_plus::adrs::AdrsType::{WotsHash, WotsPk, WotsPrf};

pub mod adrs;

/// Length of random bytes used for address derivation in W-OTS+ operations.
pub const WTS_ADRS_RAND_BYTES: usize = 8;

/// Encapsulates the W-OTS+ operations and maintains state for the hasher and address randomness.
/// It
#[derive(Clone, Debug)]
pub struct WotsPlus {
    pub adrs_rand: [u8; WTS_ADRS_RAND_BYTES],
    hasher: DGSPHasher,
}

impl WotsPlus {
    pub fn new(pub_seed: &[u8; SPX_N]) -> Self {
        let hasher = DGSPHasher::new(pub_seed);
        Self {
            adrs_rand: [0_u8; WTS_ADRS_RAND_BYTES],
            hasher,
        }
    }

    pub fn new_from_rand(adrs_rand: &[u8], pub_seed: &[u8; SPX_N]) -> Self {
        let hasher = DGSPHasher::new(pub_seed);
        Self {
            adrs_rand: adrs_rand.try_into().unwrap(),
            hasher,
        }
    }

    /// Generate private and public keys.
    pub fn keygen(&self, sk_seed: &[u8]) -> ([u8; SPX_WOTS_BYTES], [u8; SPX_WOTS_BYTES]) {
        let mut adrs = Adrs::new_full_from_rand(WotsHash, &self.adrs_rand);
        self.gen_pk_sk(sk_seed, 0, &mut adrs)
    }

    /// Sign a message with a private key.
    pub fn sign(&self, message: &[u8], sk: &[u8]) -> [u8; SPX_WOTS_BYTES] {
        let mut adrs = Adrs::new_full_from_rand(WotsHash, &self.adrs_rand);
        self.gen_sig(sk, 0, &mut adrs, message)
    }

    pub fn sign_from_sk_seed(&self, message: &[u8], sk_seed: &[u8; SPX_N]) -> [u8; SPX_WOTS_BYTES] {
        let mut adrs = Adrs::new_full_from_rand(WotsPrf, &self.adrs_rand);
        self.gen_sig_from_sk_seed(sk_seed, 0, &mut adrs, message)
    }

    /// Verify a signature.
    pub fn verify(&self, signature: &[u8], message: &[u8], pk: &[u8]) -> bool {
        let mut adrs = Adrs::new_full_from_rand(WotsHash, &self.adrs_rand);
        let calculated_pk = self.wots_pk_from_sig(signature, message, 0, &mut adrs);
        if calculated_pk != pk {
            return false;
        }
        true
    }

    /// Compute the public key from a signature and message.
    pub fn pk_from_sig(&self, signature: &[u8], message: &[u8]) -> [u8; SPX_WOTS_PK_BYTES] {
        let mut adrs = Adrs::new_full_from_rand(WotsHash, &self.adrs_rand);
        self.wots_pk_from_sig(signature, message, 0, &mut adrs)
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
        msg: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
    ) -> [u8; SPX_WOTS_BYTES] {
        let mut pk_buf = [0_u8; SPX_WOTS_BYTES];
        let mut pk_adrs = *adrs;

        let mut lengths = [0_u32; SPX_WOTS_LEN];
        Self::chain_lengths(lengths.as_mut(), msg);

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
        self.hasher
            .spx_t_l_inplace(pk_buf.as_mut(), SPX_WOTS_LEN, &pk_adrs);

        pk_buf
    }

    fn gen_pk_sk(
        &self,
        sk_seed: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
    ) -> ([u8; SPX_WOTS_BYTES], [u8; SPX_WOTS_BYTES]) {
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
        self.hasher
            .spx_t_l_inplace(pk_buf.as_mut(), SPX_WOTS_LEN, &pk_adrs);

        (pk_buf, sk_buf)
    }

    fn gen_sig(
        &self,
        sk: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
        message: &[u8],
    ) -> [u8; SPX_WOTS_BYTES] {
        let mut sig_buf = [0_u8; SPX_WOTS_BYTES];
        let mut buf_index: usize;

        // Calculate chain steps for the given message
        let mut steps = [0_u32; SPX_WOTS_LEN];
        Self::chain_lengths(steps.as_mut(), message);

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

    fn gen_sig_from_sk_seed(
        &self,
        sk_seed: &[u8],
        leaf_idx: u32,
        adrs: &mut Adrs,
        message: &[u8],
    ) -> [u8; SPX_WOTS_BYTES] {
        let mut sk_buf = [0_u8; SPX_N];
        let mut sig_buf = [0_u8; SPX_WOTS_BYTES];
        let mut buf_index: usize;

        // Calculate chain steps for the given message
        let mut steps = [0_u32; SPX_WOTS_LEN];
        Self::chain_lengths(steps.as_mut(), message);

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

        let mut rng = thread_rng();
        let len: u16 = rng.gen();
        let message = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let signature = wp.sign(&message, &sk);

        assert!(wp.verify(&signature, &message, &pk));

        let mut fake_signature = signature;
        fake_signature[0] ^= 1;

        assert!(!wp.verify(&fake_signature, &message, &pk));

        let wp_same = WotsPlus::new_from_rand(&wp.adrs_rand, &pub_seed);
        let (pk_same, _) = wp_same.keygen(&sk_seed);

        assert_eq!(pk, pk_same);

        let sig_same = wp.sign_from_sk_seed(&message, &sk_seed);

        assert_eq!(sig_same, signature);

        assert!(wp_same.verify(&sig_same, &message, &pk_same));
        assert_eq!(wp_same.pk_from_sig(&sig_same, &message), pk);

        println!("WOTS+ keygen, signing, and verify tests passed.");
    }
}
