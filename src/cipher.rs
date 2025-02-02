use crate::dgsp::DGSPMSK;
use aes::cipher::{generic_array::GenericArray, KeyInit};

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_shake_128f",
    feature = "sphincs_shake_128s",
))]
use aes::Aes128;
#[cfg(any(
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_shake_192f",
    feature = "sphincs_shake_192s",
))]
use aes::Aes192;
#[cfg(any(
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
    feature = "sphincs_shake_256f",
    feature = "sphincs_shake_256s",
))]
use aes::Aes256;

pub(crate) struct DGSPCipher;

impl DGSPCipher {
    #[cfg(any(
        feature = "sphincs_sha2_128f",
        feature = "sphincs_sha2_128s",
        feature = "sphincs_shake_128f",
        feature = "sphincs_shake_128s",
    ))]
    pub(crate) fn cipher(msk: &DGSPMSK) -> Aes128 {
        Aes128::new(GenericArray::from_slice(msk.as_ref()))
    }
    #[cfg(any(
        feature = "sphincs_sha2_192f",
        feature = "sphincs_sha2_192s",
        feature = "sphincs_shake_192f",
        feature = "sphincs_shake_192s",
    ))]
    pub(crate) fn cipher(msk: &DGSPMSK) -> Aes192 {
        Aes192::new(GenericArray::from_slice(msk.as_ref()))
    }
    #[cfg(any(
        feature = "sphincs_sha2_256f",
        feature = "sphincs_sha2_256s",
        feature = "sphincs_shake_256f",
        feature = "sphincs_shake_256s",
    ))]
    pub(crate) fn cipher(msk: &DGSPMSK) -> Aes256 {
        Aes256::new(GenericArray::from_slice(msk.as_ref()))
    }
}
