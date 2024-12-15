#![allow(dead_code)]
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

use crate::params::{DGSP_N, DGSP_POS_BYTES, DGSP_USER_BYTES};
use crate::sphincs_plus::sha2_offsets::*;
use crate::wots_plus::adrs::Adrs;
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Debug)]
pub struct DGSPHasher {
    pub pub_seed: [u8; SPX_N],
    sha256: Sha256,
    sha512: Sha512,
}

impl DGSPHasher {
    pub fn new(pub_seed: &[u8; SPX_N]) -> Self {
        // block-pad and initialize sha256 and sha512 with pub_seed
        let mut block256 = [0_u8; SPX_SHA256_BLOCK_BYTES];
        block256[..SPX_N].copy_from_slice(pub_seed.as_ref());
        let mut sha256 = Sha256::new();
        sha256.update(block256);

        let mut block512 = [0_u8; SPX_SHA512_BLOCK_BYTES];
        block512[..SPX_N].copy_from_slice(pub_seed.as_ref());
        let mut sha512 = Sha512::new();
        sha512.update(block512);

        Self {
            pub_seed: pub_seed.as_ref().try_into().unwrap(),
            sha256,
            sha512,
        }
    }

    fn sha2_256(output: &mut [u8], input: &[u8], in_byte_len: usize) {
        let mut hasher = Sha256::default();
        hasher.update(input[..in_byte_len].as_ref());
        output.copy_from_slice(hasher.finalize().as_slice());
    }

    fn sha2_512(output: &mut [u8], input: &[u8], in_byte_len: usize) {
        let mut hasher = Sha512::default();
        hasher.update(input[..in_byte_len].as_ref());
        output.copy_from_slice(hasher.finalize().as_slice());
    }

    fn simple_hash(output: &mut [u8], input: &[u8], in_byte_len: usize) {
        #[cfg(any(feature = "sphincs_sha2_128f", feature = "sphincs_sha2_128s",))]
        Self::sha2_256(output, input, in_byte_len);

        #[cfg(any(
            feature = "sphincs_sha2_192f",
            feature = "sphincs_sha2_192s",
            feature = "sphincs_sha2_256f",
            feature = "sphincs_sha2_256s",
        ))]
        Self::sha2_512(output, input, in_byte_len);
    }

    pub fn calc_cid(output: &mut [u8], msk: &[u8], id_bytes: &[u8]) {
        let mut hasher = Sha256::default();
        hasher.update(msk[..DGSP_N].as_ref());
        hasher.update(id_bytes[..DGSP_USER_BYTES].as_ref());
        output[..DGSP_N].copy_from_slice(&hasher.finalize()[..DGSP_N]);
    }

    // pub fn hasher() -> Sha256 {
    //     Sha256::default()
    // }

    #[cfg(any(feature = "sphincs_sha2_128f", feature = "sphincs_sha2_128s",))]
    pub fn hash_m(
        output: &mut [u8],
        spx_r: &[u8],
        sgn_seed: &[u8],
        dgsp_pos: &[u8],
        message: &[u8],
    ) {
        let mut hasher = Sha256::default();
        hasher.update(spx_r[..SPX_N].as_ref());
        hasher.update(sgn_seed[..SPX_N].as_ref());
        hasher.update(dgsp_pos[..DGSP_POS_BYTES].as_ref());
        hasher.update(message);
        output[..SPX_N].copy_from_slice(&hasher.finalize()[..SPX_N]);
    }

    #[cfg(any(
        feature = "sphincs_sha2_192f",
        feature = "sphincs_sha2_192s",
        feature = "sphincs_sha2_256f",
        feature = "sphincs_sha2_256s",
    ))]
    pub fn hash_m(
        output: &mut [u8],
        spx_r: &[u8],
        sgn_seed: &[u8],
        dgsp_pos: &[u8],
        message: &[u8],
    ) {
        let mut hasher = Sha512::default();
        hasher.update(spx_r[..SPX_N].as_ref());
        hasher.update(sgn_seed[..SPX_N].as_ref());
        hasher.update(dgsp_pos[..DGSP_POS_BYTES].as_ref());
        hasher.update(message);
        output[..SPX_N].copy_from_slice(&hasher.finalize()[..SPX_N]);
    }

    /// Takes an array of inblocks concatenated arrays of SPX_N bytes. outlen=SP_X
    /// (thash)
    ///
    /// F(PK.seed, ADRS, M1 ) = SHA2-256(BlockPad(PK.seed)||ADRSc ||M1 )
    pub fn spx_f(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = self.sha256.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(input[..in_blocks * SPX_N].as_ref());
        output[..SPX_N].copy_from_slice(hasher.finalize()[..SPX_N].as_ref());
    }

    /// Applies [`spx_f`] function, but modifies the given input in place.
    pub fn spx_f_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = self.sha256.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(inout[..in_blocks * SPX_N].as_ref());
        inout[..SPX_N].copy_from_slice(hasher.finalize()[..SPX_N].as_ref());
    }

    /// H(PK.seed, ADRS, M1 ||M2 ) = SHA-X(BlockPad(PK.seed)||ADRSc ||M1 ||M2 ),
    #[cfg(any(feature = "sphincs_sha2_128f", feature = "sphincs_sha2_128s",))]
    pub fn spx_h(
        &self,
        output: &mut [u8],
        input1: &[u8],
        in_blocks1: usize,
        input2: &[u8],
        in_blocks2: usize,
        adrs: &Adrs,
    ) {
        let mut hasher = self.sha256.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(input1[..in_blocks1 * SPX_N].as_ref());
        hasher.update(input2[..in_blocks2 * SPX_N].as_ref());
        output[..SPX_N].copy_from_slice(hasher.finalize()[..SPX_N].as_ref());
    }
    #[cfg(any(
        feature = "sphincs_sha2_192f",
        feature = "sphincs_sha2_192s",
        feature = "sphincs_sha2_256f",
        feature = "sphincs_sha2_256s",
    ))]
    pub fn spx_h(
        &self,
        output: &mut [u8],
        input1: &[u8],
        in_blocks1: usize,
        input2: &[u8],
        in_blocks2: usize,
        adrs: &Adrs,
    ) {
        let mut hasher = self.sha512.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(input1[..in_blocks1 * SPX_N].as_ref());
        hasher.update(input2[..in_blocks2 * SPX_N].as_ref());
        output[..SPX_N].copy_from_slice(hasher.finalize()[..SPX_N].as_ref());
    }

    /// T` (PK.seed, ADRS, M ) = SHA-X(BlockPad(PK.seed)||ADRS ||M ),
    #[cfg(any(feature = "sphincs_sha2_128f", feature = "sphincs_sha2_128s",))]
    pub fn spx_t_l(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        self.spx_f(output, input, in_blocks, adrs);
    }
    #[cfg(any(
        feature = "sphincs_sha2_192f",
        feature = "sphincs_sha2_192s",
        feature = "sphincs_sha2_256f",
        feature = "sphincs_sha2_256s",
    ))]
    pub fn spx_t_l(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = self.sha512.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(input[..in_blocks * SPX_N].as_ref());
        output[..SPX_N].copy_from_slice(hasher.finalize()[..SPX_N].as_ref());
    }

    #[cfg(any(feature = "sphincs_sha2_128f", feature = "sphincs_sha2_128s",))]
    pub fn spx_t_l_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        self.spx_f_inplace(inout, in_blocks, adrs);
    }
    #[cfg(any(
        feature = "sphincs_sha2_192f",
        feature = "sphincs_sha2_192s",
        feature = "sphincs_sha2_256f",
        feature = "sphincs_sha2_256s",
    ))]
    pub fn spx_t_l_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = self.sha512.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(inout[..in_blocks * SPX_N].as_ref());
        inout[..SPX_N].copy_from_slice(hasher.finalize()[..SPX_N].as_ref());
    }

    /// PRF(PK.seed, SK.seed, ADRS) = SHA2-256(BlockPad(PK.seed)||ADRSc ||SK.seed),
    ///
    /// (prf_addr)
    pub fn spx_prf(&self, output: &mut [u8], sk_seed: &[u8], adrs: &Adrs) {
        self.spx_f(output, sk_seed[..SPX_N].as_ref(), 1, adrs);
    }
}
