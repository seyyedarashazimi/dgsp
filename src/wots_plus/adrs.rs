#![allow(dead_code)]

use crate::params::WOTSPLUS_ADRS_LAYER;
use crate::utils::{get_byte_at, set_byte_at, set_u32_at, set_u64_at};
use rand::rngs::OsRng;
use rand::RngCore;
use std::convert::TryInto;

#[cfg(any(
    feature = "sphincs_sha2_128f",
    feature = "sphincs_sha2_128s",
    feature = "sphincs_sha2_192f",
    feature = "sphincs_sha2_192s",
    feature = "sphincs_sha2_256f",
    feature = "sphincs_sha2_256s",
))]
use crate::sphincs_plus::sha2_offsets::*;

#[cfg(any(
    feature = "sphincs_shake_128f",
    feature = "sphincs_shake_128s",
    feature = "sphincs_shake_192f",
    feature = "sphincs_shake_192s",
    feature = "sphincs_shake_256f",
    feature = "sphincs_shake_256s",
))]
use crate::sphincs_plus::shake_offsets::*;

// layer in WOTS+ for user is SPX_D
// tree_addr: choose a "secure" random 64-bit value

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum AdrsType {
    /// SPX_ADDR_TYPE_WOTS: 0
    WotsHash,
    /// SPX_ADDR_TYPE_WOTSPK: 1
    WotsPk,
    /// SPX_ADDR_TYPE_HASHTREE: 2, won't be used.
    Tree,
    /// SPX_ADDR_TYPE_FORSTREE: 3, won't be used.
    ForsTree,
    /// SPX_ADDR_TYPE_FORSPK: 4, won't be used.
    ForsRoots,
    /// SPX_ADDR_TYPE_WOTSPRF: 5
    WotsPrf,
    /// SPX_ADDR_TYPE_FORSPRF: 6, won't be used.
    ForsPrf,
}

/// The address `Adrs` is a 32-byte value and follows the structure of WOTS+ described in
/// [SPHINCS+ latest submission](https://sphincs.org/data/sphincs+-r3.1-specification.pdf),
/// but with a few changes to make it suitable for a standalone WOTS+.
///
/// The 32-bytes values of `Adrs` consists of at most 6 parts in general, determined by
/// `AdrsType`. Among possible cases of `AdrsType` for WOTS+, `Adrs` contains the following
/// parts:
/// * `layer address`:  A single byte set to [`WOTSPLUS_ADRS_LAYER`] to be distinct from ADRS of
///                     SPHINCS+,
/// * `tree address`:   An 8-byte random value to make it unique among per use of each user to be
///                     secure against multi-target attack.
/// * `type`:           A single byte set by [`AdrsType`] which will be either
///                     [`AdrsType::WotsHash`], [`AdrsType::WotsPk`], or [`AdrsType::WotsPRF`].
///                     Other types are still defined for [`AdrsType`] only to be compatible with
///                     ADRS defined in SPHINCS+ but will not be used here.
/// * `key pair address`: TODO: it is currently 0 but needs to be changed
/// * `chain address`:  a single byte, corresponding to each chain of WOTS+.
/// * `hash address`:   a single byte, corresponding to each height in a chain in WOTS+.
#[derive(Copy, Clone, Default, Debug)]
pub struct Adrs([u8; 32]);

impl AsRef<[u8]> for Adrs {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Adrs {
    /// Returns an `(adrs, r)`, where `r` is an 8-byte random value
    /// which is set as the 64-bit tree address inside the `adrs`.
    /// The `adrs` is an instance of [`Adrs`] where the random `r`
    /// is set inside it, the layer address is initialized with
    /// the constant [`WOTSPLUS_ADRS_LAYER`], and the type is set
    /// from the `adrs_type` input.
    pub fn new_full(adrs_type: AdrsType) -> (Self, [u8; 8]) {
        let mut adrs = Self([0; 32]);
        adrs.set_type(adrs_type);
        adrs.set_layer_addr(WOTSPLUS_ADRS_LAYER);
        let r = adrs.assign_rand();
        (adrs, r)
    }

    pub fn new_full_from_rand(adrs_type: AdrsType, r: &[u8; 8]) -> Self {
        let mut adrs = Self([0; 32]);
        adrs.set_type(adrs_type);
        adrs.set_layer_addr(WOTSPLUS_ADRS_LAYER);
        adrs.set_rand(r);
        adrs
    }

    #[cfg(any(
        feature = "sphincs_sha2_128f",
        feature = "sphincs_sha2_128s",
        feature = "sphincs_sha2_192f",
        feature = "sphincs_sha2_192s",
        feature = "sphincs_sha2_256f",
        feature = "sphincs_sha2_256s",
    ))]
    pub fn compressed_as_ref(&self) -> &[u8] {
        self.0[..SPX_SHA256_ADDR_BYTES].as_ref()
    }

    fn set_rand(&mut self, rand: &[u8; 8]) {
        self.set_tree_addr(u64::from_be_bytes(*rand))
    }

    fn create_rand(&self) -> [u8; 8] {
        let mut r: [u8; 8] = [0; 8];
        OsRng.fill_bytes(&mut r);
        r
    }

    fn assign_rand(&mut self) -> [u8; 8] {
        let r = self.create_rand();
        self.set_rand(&r);
        r
    }

    pub fn get_rand(&self) -> [u8; 8] {
        self.0[SPX_OFFSET_TREE..SPX_OFFSET_TREE + 8]
            .try_into()
            .unwrap()
    }

    /// Specify which level of Merkle tree (the "layer") we're working on.
    pub fn set_layer_addr(&mut self, layer: u32) {
        set_byte_at(self.0.as_mut(), layer as u8, SPX_OFFSET_LAYER);
    }

    /// Specify which Merkle tree within the level (the "tree address") we're working on.
    pub fn set_tree_addr(&mut self, tree: u64) {
        set_u64_at(self.0.as_mut(), tree, SPX_OFFSET_TREE);
    }

    /// Specify the reason we'll use this address structure for, that is, what
    /// hash will we compute with it.  This is used so that unrelated types of
    /// hashes don't accidentally get the same address structure. The type will
    /// be one of the SPX_ADDR_TYPE constants.
    pub fn set_type(&mut self, adrs_type: AdrsType) {
        set_byte_at(self.0.as_mut(), adrs_type as u8, SPX_OFFSET_TYPE);
    }

    /// Copy the layer and tree fields of the address structure.  This is used
    /// when we're doing multiple types of hashes within the same Merkle tree.
    pub fn copy_subtree_addr(&self, dst: &mut [u8; 32]) {
        dst[0..SPX_OFFSET_TREE + 8].copy_from_slice(&self.0[0..SPX_OFFSET_TREE + 8]);
    }

    /// Specify which Merkle leaf we're working on; that is, which OTS keypair
    /// we're talking about.
    pub fn set_keypair_addr(&mut self, keypair: u32) {
        set_byte_at(self.0.as_mut(), keypair as u8, SPX_OFFSET_KP_ADDR1);
    }

    /// Copy the layer, tree and keypair fields of the address structure.  This is
    /// used when we're doing multiple things within the same OTS keypair.
    pub fn copy_keypair_addr(&self, dst: &mut [u8; 32]) {
        self.copy_subtree_addr(dst);
        dst[SPX_OFFSET_KP_ADDR1] = get_byte_at(self.0.as_slice(), SPX_OFFSET_KP_ADDR1);
    }

    /// Specify which Merkle chain within the OTS we're working with
    /// (the chain address).
    pub fn set_chain_addr(mut self, chain: u32) {
        set_byte_at(self.0.as_mut(), chain as u8, SPX_OFFSET_CHAIN_ADDR);
    }

    /// Specify where in the Merkle chain we are
    /// (the hash address).
    pub fn set_hash_addr(mut self, hash: u32) {
        set_byte_at(self.0.as_mut(), hash as u8, SPX_OFFSET_HASH_ADDR);
    }

    /// Specify the height of the node in the Merkle/FORS tree we are in
    /// (the tree height).
    pub fn set_tree_height(mut self, tree_height: u32) {
        set_byte_at(self.0.as_mut(), tree_height as u8, SPX_OFFSET_TREE_HGT);
    }

    /// Specify the distance from the left edge of the node in the Merkle/FORS tree
    /// (the tree index).
    pub fn set_tree_index(&mut self, tree_index: u32) {
        set_u32_at(self.0.as_mut(), tree_index, SPX_OFFSET_TREE_INDEX);
    }
}
