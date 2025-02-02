use crate::params::{DGSP_N, DGSP_USER_BYTES};
use crate::sphincs_plus::SPX_SHA256_BLOCK_BYTES;
use crate::wots_plus::adrs::Adrs;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub(crate) struct DGSPHasher {
    sha256: Sha256,
}

impl DGSPHasher {
    pub(crate) fn new(pub_seed: &[u8; DGSP_N]) -> Self {
        // block-pad and initialize sha256 and sha512 with pub_seed
        let mut block256 = [0_u8; SPX_SHA256_BLOCK_BYTES];
        block256[..DGSP_N].copy_from_slice(pub_seed.as_ref());
        let mut sha256 = Sha256::new();
        sha256.update(block256);

        Self { sha256 }
    }

    pub(crate) fn calc_cid(output: &mut [u8], msk: &[u8], id_bytes: &[u8]) {
        let mut hasher = Sha256::default();
        hasher.update(msk[..DGSP_N].as_ref());
        hasher.update(id_bytes[..DGSP_USER_BYTES].as_ref());
        output[..DGSP_N].copy_from_slice(&hasher.finalize()[..DGSP_N]);
    }

    pub(crate) fn hash_simple(output: &mut [u8], input: &[u8]) {
        let mut hasher = Sha256::default();
        hasher.update(input);
        output[..DGSP_N].copy_from_slice(&hasher.finalize()[..DGSP_N]);
    }

    /// Calculates hash of message, i.e. out = SHA2-256(pub_seed || message).
    /// Normally, pub_seed is sgn_seed in DGSP.
    pub(crate) fn hash_m(&self, output: &mut [u8], message: &[u8]) {
        let mut hasher = self.sha256.clone();
        hasher.update(message);
        output[..DGSP_N].copy_from_slice(&hasher.finalize()[..DGSP_N]);
    }

    /// Takes an array of inblocks concatenated arrays of SPX_N bytes. outlen=SPX_N
    /// (thash)
    ///
    /// F(PK.seed, ADRS, M1 ) = SHA2-256(BlockPad(PK.seed)||ADRSc ||M1 )
    pub(crate) fn spx_f(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = self.sha256.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(input[..in_blocks * DGSP_N].as_ref());
        output[..DGSP_N].copy_from_slice(hasher.finalize()[..DGSP_N].as_ref());
    }

    /// Applies [`spx_f`] function, but modifies the given input in place.
    pub(crate) fn spx_f_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = self.sha256.clone();
        hasher.update(adrs.compressed_as_ref());
        hasher.update(inout[..in_blocks * DGSP_N].as_ref());
        inout[..DGSP_N].copy_from_slice(hasher.finalize()[..DGSP_N].as_ref());
    }

    /// PRF(PK.seed, SK.seed, ADRS) = SHA2-256(BlockPad(PK.seed)||ADRSc ||SK.seed),
    ///
    /// (prf_addr)
    pub(crate) fn spx_prf(&self, output: &mut [u8], sk_seed: &[u8], adrs: &Adrs) {
        self.spx_f(output, sk_seed[..DGSP_N].as_ref(), 1, adrs);
    }
}
