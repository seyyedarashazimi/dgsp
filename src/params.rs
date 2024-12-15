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
use crate::wots_plus::WTS_ADRS_RAND_BYTES;

pub const DGSP_LAMBDA: usize = 256;
pub const DGSP_N: usize = DGSP_LAMBDA / 8;

/// Layer address set in ADRS. It is chosen to be unique from the layer addresses present
/// in SPHINCS+. Therefore, any value bigger than or equal to 22 is acceptable, but once
/// set, it should not be changed for consistency.
pub const WOTSPLUS_ADRS_LAYER: u32 = 73;

// pub const DGSP_BYTES: usize =
//     SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;

pub const DGSP_POS_BYTES: usize = 16;

pub const DGSP_BYTES: usize = SPX_WOTS_BYTES + DGSP_POS_BYTES + SPX_BYTES + WTS_ADRS_RAND_BYTES;
pub const DGSP_PK_BYTES: usize = SPX_PK_BYTES;
pub const DGSP_SK_BYTES: usize = DGSP_N + SPX_SK_BYTES;
pub const DGSP_USER_BYTES: usize = 8;
