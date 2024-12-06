use crate::params::WOTSPLUS_ADRS_LAYER;
use crate::sha2_offsets::*;
use rand::rngs::OsRng;
use rand::RngCore;
// layer in WOTS+ for user is SPX_D
// tree_addr: choose a "secure" random 64-bit value

#[derive(Copy, Clone, Debug)]
#[repr(usize)]
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
impl Adrs {
    pub fn new_full(adrs_type: AdrsType) -> Self {
        let mut adrs = Self([0; 32]);
        adrs.set_type(adrs_type as usize as u32);
        adrs.set_layer_addr(WOTSPLUS_ADRS_LAYER);
        adrs.assign_rand();
        adrs
    }

    pub fn set_rand(&mut self, rand: [u8; 8]) {
        self.set_tree_addr(u64::from_be_bytes(rand))
    }

    fn create_rand(&self) -> [u8; 8] {
        let mut r: [u8; 8] = [0; 8];
        OsRng.fill_bytes(&mut r);
        r
    }

    pub fn assign_rand(&mut self) {
        self.set_rand(self.create_rand());
    }

    pub fn get_rand(&self) -> [u8; 8] {
        self.0[SPX_OFFSET_TREE..SPX_OFFSET_TREE + 8]
            .try_into()
            .unwrap()
    }

    /// Specify which level of Merkle tree (the "layer") we're working on.
    pub fn set_layer_addr(&mut self, layer: u32) {
        self.set_byte_at(layer as u8, SPX_OFFSET_LAYER);
    }

    /// Specify which Merkle tree within the level (the "tree address") we're working on.
    pub fn set_tree_addr(&mut self, tree: u64) {
        self.set_u64_at(tree, SPX_OFFSET_TREE);
    }

    /// Specify the reason we'll use this address structure for, that is, what
    /// hash will we compute with it.  This is used so that unrelated types of
    /// hashes don't accidentally get the same address structure. The type will
    /// be one of the SPX_ADDR_TYPE constants.
    pub fn set_type(&mut self, adrs_type: u32) {
        self.set_byte_at(adrs_type as u8, SPX_OFFSET_TYPE);
    }

    /// Copy the layer and tree fields of the address structure.  This is used
    /// when we're doing multiple types of hashes within the same Merkle tree.
    pub fn copy_subtree_addr(&self, dst: &mut [u8; 32]) {
        dst[0..SPX_OFFSET_TREE + 8].copy_from_slice(&self.0[0..SPX_OFFSET_TREE + 8]);
    }

    /// Specify which Merkle leaf we're working on; that is, which OTS keypair
    /// we're talking about.
    pub fn set_keypair_addr(&mut self, keypair: u32) {
        self.set_byte_at(keypair as u8, SPX_OFFSET_KP_ADDR1);
    }

    /// Copy the layer, tree and keypair fields of the address structure.  This is
    /// used when we're doing multiple things within the same OTS keypair.
    pub fn copy_keypair_addr(&self, dst: &mut [u8; 32]) {
        self.copy_subtree_addr(dst);
        dst[SPX_OFFSET_KP_ADDR1] = self.get_byte_at(SPX_OFFSET_KP_ADDR1);
    }

    /// Specify which Merkle chain within the OTS we're working with
    /// (the chain address).
    pub fn set_chain_addr(mut self, chain: u32) {
        self.set_byte_at(chain as u8, SPX_OFFSET_CHAIN_ADDR);
    }

    /// Specify where in the Merkle chain we are
    /// (the hash address).
    pub fn set_hash_addr(mut self, hash: u32) {
        self.set_byte_at(hash as u8, SPX_OFFSET_HASH_ADDR);
    }

    /// Specify the height of the node in the Merkle/FORS tree we are in
    /// (the tree height).
    pub fn set_tree_height(mut self, tree_height: u32) {
        self.set_byte_at(tree_height as u8, SPX_OFFSET_TREE_HGT);
    }

    /// Specify the distance from the left edge of the node in the Merkle/FORS tree
    /// (the tree index).
    pub fn set_tree_index(&mut self, tree_index: u32) {
        self.set_u32_at(tree_index, SPX_OFFSET_TREE_INDEX);
    }

    fn set_byte_at(&mut self, value: u8, index: usize) {
        self.0[index] = value;
    }

    fn get_byte_at(&self, index: usize) -> u8 {
        self.0[index]
    }

    fn set_u32_at(&mut self, value: u32, start_index: usize) {
        self.0[start_index..start_index + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn get_u32_at(&self, start_index: usize) -> u32 {
        let bytes: [u8; 4] = self.0[start_index..start_index + 4]
            .try_into()
            .expect("Index out of bounds or incorrect length");

        u32::from_be_bytes(bytes)
    }

    fn set_u64_at(&mut self, value: u64, start_index: usize) {
        self.0[start_index..start_index + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn get_u64_at(&self, start_index: usize) -> u64 {
        let bytes: [u8; 8] = self.0[start_index..start_index + 8]
            .try_into()
            .expect("Index out of bounds or incorrect length");

        u64::from_be_bytes(bytes)
    }
}

pub struct WotsPlus;

impl WotsPlus {
    // pub fn keygen(adrs_type: AdrsType) -> Adrs {}

    fn gen_chain(out: &mut , const unsigned char *in,
    unsigned int start, unsigned int steps,
    const spx_ctx *ctx, uint32_t addr[8])
}
