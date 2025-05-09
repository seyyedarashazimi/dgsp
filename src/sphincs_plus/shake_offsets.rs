//! Here are the adrs offset parameters used for SPHINCS+ SHAKE-based schemes.
//!
//! The main purpose of these parameters is to allow DGSP to work properly
//! with the underlying SPHINCS+.
//!
//! It represents offsets of various fields in the address structure when we use SHAKE as
//! the Sphincs+ hash function.

/// The byte used to specify the Merkle tree layer.
pub const SPX_OFFSET_LAYER: usize = 3;

/// The start of the 8 byte field used to specify the tree.
pub const SPX_OFFSET_TREE: usize = 8;

/// The byte used to specify the hash type (reason).
pub const SPX_OFFSET_TYPE: usize = 19;

/// The high byte used to specify the key pair (which one-time signature).
pub const SPX_OFFSET_KP_ADDR2: usize = 22;

/// The low byte used to specify the key pair.
pub const SPX_OFFSET_KP_ADDR1: usize = 23;

/// The byte used to specify the chain address (which Winternitz chain).
pub const SPX_OFFSET_CHAIN_ADDR: usize = 27;

/// The byte used to specify the hash address (where in the Winternitz chain).
pub const SPX_OFFSET_HASH_ADDR: usize = 31;

/// The byte used to specify the height of this node in the FORS or Merkle tree.
pub const SPX_OFFSET_TREE_HGT: usize = 27;

/// The start of the 4 byte field used to specify the node in the FORS or Merkle tree.
pub const SPX_OFFSET_TREE_INDEX: usize = 28;
