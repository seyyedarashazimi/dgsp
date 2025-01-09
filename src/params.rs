use crate::sphincs_plus::{SPX_BYTES, SPX_PK_BYTES, SPX_SK_BYTES, SPX_WOTS_BYTES};
use crate::wots_plus::WTS_ADRS_RAND_BYTES;

/// Security level of DGSP in bit-level.
pub const DGSP_LAMBDA: usize = 256;

/// Security level of DGSP in byte-level.
pub const DGSP_N: usize = DGSP_LAMBDA / 8;

/// Layer address set in ADRS. It is chosen to be unique from the layer addresses present
/// in SPHINCS+. Therefore, any value bigger than or equal to 22 is acceptable, but once
/// set, it should not be changed for consistency. max = 255.
pub const WOTSPLUS_ADRS_LAYER: u32 = 73;

/// DGSP position byte size.
pub const DGSP_POS_BYTES: usize = 16;

/// DGSP signature byte size.
pub const DGSP_BYTES: usize = SPX_WOTS_BYTES + DGSP_POS_BYTES + SPX_BYTES + WTS_ADRS_RAND_BYTES;

/// DGSP public-key byte size.
pub const DGSP_PK_BYTES: usize = SPX_PK_BYTES;

/// DGSP secret-key byte size.
pub const DGSP_SK_BYTES: usize = DGSP_N + SPX_SK_BYTES;

/// DGSP user byte size.
pub const DGSP_USER_BYTES: usize = 8;
