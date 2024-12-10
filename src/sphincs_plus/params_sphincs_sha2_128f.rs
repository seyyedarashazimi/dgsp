//! Here are the parameters used for SPHINCS+ sha2_128f scheme.
//!
//! The main purpose of these parameters is to allow DGSP to work properly
//! with the underlying SPHINCS+.
//!
//! Note that these values are not open for configuration since they do not
//! affect the underlying call to the PQClean's SPHINCS+ calls.
#![allow(dead_code)]

/// Hash output length in bytes.
pub const SPX_N: usize = 16;

/// Height of the hypertree.
pub const SPX_FULL_HEIGHT: usize = 66;
/// Number of subtree layer.
pub const SPX_D: usize = 22;

/// FORS tree dimensions.
pub const SPX_FORS_HEIGHT: usize = 6;
pub const SPX_FORS_TREES: usize = 33;

/// Winternitz parameter.
pub const SPX_WOTS_W: usize = 16;

/// This is a SHA2-based parameter set, hence whether we use SHA-256
/// exclusively or we use both SHA-256 and SHA-512 is controlled by
/// the following constant.
pub const SPX_SHA512: usize = 0; /* Use SHA-256 for all hashes */

/* For clarity */
pub const SPX_ADDR_BYTES: usize = 32;

/* WOTS parameters. */
// pub const SPX_WOTS_LOGW: usize = if SPX_WOTS_W == 256 {
//     8
// } else if SPX_WOTS_W == 16 {
//     4
// } else {
//     [][0] // raise an error since SPX_WOTS_W assumed to be 16 or 256.
// };
pub const SPX_WOTS_LOGW: usize = 4;

pub const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW;

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
// pub const SPX_WOTS_LEN2: usize = if SPX_WOTS_W == 256 {
//     if SPX_N <= 1 {
//         1
//     } else if SPX_N <= 256 {
//         2
//     } else {
//         [][0] // raise an error: Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
//     }
// } else if SPX_WOTS_W == 16 {
//     if SPX_N <= 8 {
//         2
//     } else if SPX_N <= 136 {
//         3
//     } else if SPX_N <= 256 {
//         4
//     } else {
//         [][0] // raise an error: Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
//     }
// } else {
//     [][0] // raise an error since SPX_WOTS_W assumed to be 16 or 256.
// };
pub const SPX_WOTS_LEN2: usize = 3;

pub const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2;
pub const SPX_WOTS_BYTES: usize = SPX_WOTS_LEN * SPX_N;
pub const SPX_WOTS_PK_BYTES: usize = SPX_WOTS_BYTES;

/* Subtree size. */
pub const SPX_TREE_HEIGHT: usize = SPX_FULL_HEIGHT / SPX_D;

/* FORS parameters. */
 // 25 + 8 + 1
pub const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8;
pub const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;
pub const SPX_FORS_PK_BYTES: usize = SPX_N;

/* Resulting SPX sizes. */
pub const SPX_BYTES: usize =
    SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;
pub const SPX_PK_BYTES: usize = 2 * SPX_N;
pub const SPX_SK_BYTES: usize = 2 * SPX_N + SPX_PK_BYTES;
