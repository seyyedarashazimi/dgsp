//! Here are the parameters used for SPHINCS+ shake_192f and sha2_192f schemes.
//!
//! The main purpose of these parameters is to allow DGSP to work properly
//! with the underlying SPHINCS+.
//!
//! Note that these values are not open for configuration since they do not
//! affect the underlying call to the PQClean's SPHINCS+ calls.

/// SPHINCS+ hash output length in bytes.
pub const SPX_N: usize = 24;

/// SPHINCS+ height of the hypertree.
const SPX_FULL_HEIGHT: usize = 66;

/// SPHINCS+ number of subtree layer.
const SPX_D: usize = 22;

/// SPHINCS+ FORS tree dimensions.
const SPX_FORS_HEIGHT: usize = 8;

/// SPHINCS+ number of FORS trees.
const SPX_FORS_TREES: usize = 33;

/// SPHINCS+ Winternitz parameter.
pub const SPX_WOTS_W: usize = 16;

/// SPHINCS+ WOTS+ binary logarithm of Winternitz parameter.
pub const SPX_WOTS_LOGW: usize = 4;

/// SPHINCS+ WOTS+ len1.
pub const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW;

/// SPHINCS+ WOTS+ len2.
pub const SPX_WOTS_LEN2: usize = 3;

/// SPHINCS+ WOTS+ len.
pub const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2;

/// SPHINCS+ WOTS+ signature byte size.
pub const SPX_WOTS_BYTES: usize = SPX_WOTS_LEN * SPX_N;

/// SPHINCS+ WOTS+ public-key byte size.
pub const SPX_WOTS_PK_BYTES: usize = SPX_WOTS_BYTES;

/// SPHINCS+ FORS byte size.
const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;

/// SPHINCS+ signature byte size.
pub const SPX_BYTES: usize =
    SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;

/// SPHINCS+ public-key byte size.
pub const SPX_PK_BYTES: usize = 2 * SPX_N;

/// SPHINCS+ secret-key byte size.
pub const SPX_SK_BYTES: usize = 2 * SPX_N + SPX_PK_BYTES;
