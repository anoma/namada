//! Tools for accessing the storage subspaces of the Ethereum
//! bridge pool

use namada_core::eth_bridge_pool::Segments;
pub use namada_core::eth_bridge_pool::{
    get_key_from_hash, get_pending_key, is_pending_transfer_key,
    BRIDGE_POOL_ADDRESS,
};
use namada_core::storage::{DbKeySeg, Key};
pub use namada_state::merkle_tree::eth_bridge_pool::BridgePoolTree;

/// Get the storage key for the root of the Merkle tree
/// containing the transfers in the pool
pub fn get_signed_root_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            DbKeySeg::StringSeg(Segments::VALUES.signed_root.into()),
        ],
    }
}

/// Get the storage key for the batch nonce of
/// the bridge pool. Used for replay protection.
pub fn get_nonce_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            DbKeySeg::StringSeg(Segments::VALUES.bridge_pool_nonce.into()),
        ],
    }
}

/// Check if a key belongs to the bridge pools sub-storage
pub fn is_bridge_pool_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &BRIDGE_POOL_ADDRESS)
}
