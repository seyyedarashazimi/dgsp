#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
pub mod sha2;

#[cfg(any(
    feature = "sphincs_shake_128f",
    feature = "sphincs_shake_128s",
    feature = "sphincs_shake_192f",
    feature = "sphincs_shake_192s",
    feature = "sphincs_shake_256f",
    feature = "sphincs_shake_256s",
))]
pub mod shake;
