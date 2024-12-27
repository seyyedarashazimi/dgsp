//! Here are the parameters used for SPHINCS+ shake_128s scheme.
//!
//! The main purpose of these parameters is to allow DGSP to work properly
//! with the underlying SPHINCS+.
//!
//! Note that these values are not open for configuration since they do not
//! affect the underlying call to the PQClean's SPHINCS+ calls.

/// Hash output length in bytes.
pub const SPX_N: usize = 16;

/// Height of the hypertree.
pub const SPX_FULL_HEIGHT: usize = 63;
/// Number of subtree layer.
pub const SPX_D: usize = 7;

/// FORS tree dimensions.
pub const SPX_FORS_HEIGHT: usize = 12;
pub const SPX_FORS_TREES: usize = 14;

/// Winternitz parameter.
pub const SPX_WOTS_W: usize = 16;

/* For clarity */
pub const SPX_ADDR_BYTES: usize = 32;

/* WOTS parameters. */
pub const SPX_WOTS_LOGW: usize = 4;
pub const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW;
pub const SPX_WOTS_LEN2: usize = 3;

pub const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2;
pub const SPX_WOTS_BYTES: usize = SPX_WOTS_LEN * SPX_N;
pub const SPX_WOTS_PK_BYTES: usize = SPX_WOTS_BYTES;

/* Subtree size. */
pub const SPX_TREE_HEIGHT: usize = SPX_FULL_HEIGHT / SPX_D;

/* FORS parameters. */
pub const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8;
pub const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;
pub const SPX_FORS_PK_BYTES: usize = SPX_N;

/* Resulting SPX sizes. */
pub const SPX_BYTES: usize =
    SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;
pub const SPX_PK_BYTES: usize = 2 * SPX_N;
pub const SPX_SK_BYTES: usize = 2 * SPX_N + SPX_PK_BYTES;
