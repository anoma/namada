//! Tools for accessing the storage subspaces of the Ethereum
//! bridge pool

use namada_core::types::eth_abi::Encode;
pub use namada_core::types::eth_bridge_pool::{
    is_pending_transfer_key, BRIDGE_POOL_ADDRESS,
};
use namada_core::types::eth_bridge_pool::{PendingTransfer, Segments};
use namada_core::types::keccak::KeccakHash;
use namada_core::types::storage::{DbKeySeg, Key, KeySeg};
pub use namada_state::merkle_tree::eth_bridge_pool::BridgePoolTree;

/// Get the storage key for the transfers in the pool
pub fn get_pending_key(transfer: &PendingTransfer) -> Key {
    get_key_from_hash(&transfer.keccak256())
}

/// Get the storage key for the transfers using the hash
pub fn get_key_from_hash(hash: &KeccakHash) -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            hash.to_db_key(),
        ],
    }
}

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
