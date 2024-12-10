use crate::utils::{bytes_to_u32, bytes_to_u64};
use crate::wots_plus::adrs::Adrs;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

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

#[derive(Clone, Debug)]
pub(crate) struct DgspHasher {
    pub pub_seed: [u8; SPX_N],
}

impl DgspHasher {
    pub(crate) fn new(pub_seed: [u8; SPX_N]) -> Self {
        Self { pub_seed }
    }
    pub(crate) fn shake256(output: &mut [u8], input: &[u8]) {
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(output);
    }

    /// Computes the message hash using R, the public key, and the message.
    /// Outputs the message digest and the index of the leaf. The index is split in
    /// the tree index and the leaf index, for convenient copying to an address.
    ///
    /// H_msg(R, PK.seed, PK.root, M ) = SHAKE256(R||PK.seed||PK.root||M, 8m),
    pub fn h_msg(
        digest: &mut [u8],
        tree: &mut [u64],
        leaf_idx: &mut [u32],
        r: &[u8],
        pk: &[u8],
        m: &[u8],
        m_len: usize,
    ) {
        const SPX_TREE_BITS: usize = SPX_TREE_HEIGHT * (SPX_D - 1);
        const SPX_TREE_BYTES: usize = (SPX_TREE_BITS + 7) / 8;
        const SPX_LEAF_BITS: usize = SPX_TREE_HEIGHT;
        const SPX_LEAF_BYTES: usize = (SPX_LEAF_BITS + 7) / 8;
        const SPX_DGST_BYTES: usize = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES;

        let mut hasher = Shake256::default();
        hasher.update(r[..SPX_N].as_ref());
        hasher.update(pk[..SPX_PK_BYTES].as_ref());
        hasher.update(m[..m_len].as_ref());
        let mut reader = hasher.finalize_xof();

        reader.read(digest[..SPX_FORS_MSG_BYTES].as_mut());

        let mut buf_tree = [0_u8; SPX_TREE_BYTES];
        reader.read(buf_tree.as_mut());
        let mut t = bytes_to_u64(&buf_tree);
        t &= (!0_u64) >> (64 - SPX_TREE_BITS);
        tree[0] = t;

        let mut buf_lead_idx = [0_u8; SPX_LEAF_BYTES];
        reader.read(buf_lead_idx.as_mut());
        let mut l = bytes_to_u32(&buf_lead_idx);
        l &= (!0_u32) >> (32 - SPX_LEAF_BITS);
        leaf_idx[0] = l;
    }

    /// Takes an array of inblocks concatenated arrays of SPX_N bytes. outlen=SP_X
    /// (thash)
    ///
    /// F(PK.seed, ADRS, M1 ) = SHAKE256(PK.seed||ADRS||M1 , 8n)
    pub fn spx_f(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = Shake256::default();
        hasher.update(self.pub_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(input[..in_blocks * SPX_N].as_ref());
        let mut reader = hasher.finalize_xof();
        reader.read(output[..SPX_N].as_mut());
    }

    /// Applies [`spx_f`] function, but modifies the given input in place.
    pub fn spx_f_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = Shake256::default();
        hasher.update(self.pub_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(inout[..in_blocks * SPX_N].as_ref());
        let mut reader = hasher.finalize_xof();
        reader.read(inout[..SPX_N].as_mut());
    }

    /// H(PK.seed, ADRS, M1 ||M2 ) = SHAKE256(PK.seed||ADRS||M1 ||M2 , 8n),
    pub fn spx_h(
        &self,
        output: &mut [u8],
        input1: &[u8],
        in_blocks1: usize,
        input2: &[u8],
        in_blocks2: usize,
        adrs: &Adrs,
    ) {
        let mut hasher = Shake256::default();
        hasher.update(self.pub_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(input1[..in_blocks1 * SPX_N].as_ref());
        hasher.update(input2[..in_blocks2 * SPX_N].as_ref());
        let mut reader = hasher.finalize_xof();
        reader.read(output[..SPX_N].as_mut());
    }

    /// T_l(PK.seed, ADRS, M ) = SHAKE256(PK.seed||ADRS||M, 8n),
    pub fn spx_t_l(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        self.spx_f(output, input, in_blocks, adrs);
    }

    pub fn spx_t_l_inplace(&self, inout: &mut [u8], in_blocks: usize, adrs: &Adrs) {
        self.spx_f_inplace(inout, in_blocks, adrs);
    }

    /// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed||ADRS||SK.seed, 8n),
    ///
    /// (prf_addr)
    pub fn spx_prf(&self, output: &mut [u8], sk_seed: &[u8], adrs: &Adrs) {
        self.spx_f(output, sk_seed[..SPX_N].as_ref(), 1, adrs);
    }

    pub fn spx_prf_msg(&self, output: &mut [u8], input: &[u8], in_blocks: usize, adrs: &Adrs) {
        let mut hasher = Shake256::default();
        hasher.update(self.pub_seed.as_ref());
        hasher.update(adrs.as_ref());
        hasher.update(input[..in_blocks * SPX_N].as_ref());
        let mut reader = hasher.finalize_xof();
        reader.read(output[..SPX_N].as_mut());
    }
}
