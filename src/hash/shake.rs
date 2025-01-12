use crate::params::{DGSP_N, DGSP_USER_BYTES};
use crate::sphincs_plus::SPX_N;
use crate::wots_plus::adrs::Adrs;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[derive(Clone, Debug)]
pub(crate) struct DGSPHasher {
    pub pub_seed: [u8; SPX_N],
}

impl DGSPHasher {
    pub(crate) fn new(pub_seed: &[u8; SPX_N]) -> Self {
        Self {
            pub_seed: pub_seed.as_ref().try_into().unwrap(),
        }
    }

    pub(crate) fn calc_cid(output: &mut [u8], msk: &[u8], id_bytes: &[u8]) {
        let mut hasher = Shake256::default();
        hasher.update(msk[..DGSP_N].as_ref());
        hasher.update(id_bytes[..DGSP_USER_BYTES].as_ref());
        let mut reader = hasher.finalize_xof();
        reader.read(output[..DGSP_N].as_mut());
    }

    /// Calculates hash of message, i.e. out = SHAKE256(pub_seed || message).
    /// Normally, pub_seed is sgn_seed in DGSP.
    pub(crate) fn hash_m(&self, output: &mut [u8], message: &[u8]) {
        let mut hasher = Shake256::default();
        hasher.update(self.pub_seed.as_ref());
        hasher.update(message);
        let mut reader = hasher.finalize_xof();
        reader.read(output[..SPX_N].as_mut());
    }

    /// Takes an array of inblocks concatenated arrays of SPX_N bytes. outlen=SP_X
    /// (thash)
    ///
    /// F(PK.seed, ADRS, M1 ) = SHAKE256(PK.seed||ADRS||M1 , 8n)
    pub(crate) fn spx_f(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = Shake256::default();
        hasher.update(self.pub_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(input[..in_blocks * SPX_N].as_ref());
        let mut reader = hasher.finalize_xof();
        reader.read(output[..SPX_N].as_mut());
    }

    /// Applies [`spx_f`] function, but modifies the given input in place.
    pub(crate) fn spx_f_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = Shake256::default();
        hasher.update(self.pub_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(inout[..in_blocks * SPX_N].as_ref());
        let mut reader = hasher.finalize_xof();
        reader.read(inout[..SPX_N].as_mut());
    }

    /// T_l(PK.seed, ADRS, M ) = SHAKE256(PK.seed||ADRS||M, 8n),
    pub(crate) fn spx_t_l_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        self.spx_f_inplace(inout, in_blocks, adrs);
    }

    /// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed||ADRS||SK.seed, 8n),
    ///
    /// (prf_addr)
    pub(crate) fn spx_prf(&self, output: &mut [u8], sk_seed: &[u8], adrs: &Adrs) {
        self.spx_f(output, sk_seed[..SPX_N].as_ref(), 1, adrs);
    }
}
