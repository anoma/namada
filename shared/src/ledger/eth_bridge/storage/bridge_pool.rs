//! Tools for accessing the storage subspaces of the Ethereum
//! bridge pool

use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{DbKeySeg, Key};

/// The main address of the Ethereum bridge pool
pub const BRIDGE_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::EthBridgePool);
/// Sub-segmnet for getting the contents of the pool
const PENDING_TRANSFERS_SEG: &str = "pending_transfers";
/// Sub-segment for getting the latest signed
const SIGNED_ROOT_SEG: &str = "signed_root";

/// Get the storage key for the transfers in the pool
pub fn get_pending_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            DbKeySeg::StringSeg(PENDING_TRANSFERS_SEG.into()),
        ],
    }
}

/// Get the storage key for the root of the Merkle tree
/// containing the transfers in the pool
pub fn get_signed_root_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            DbKeySeg::StringSeg(SIGNED_ROOT_SEG.into()),
        ],
    }
}

/// Check if a key belongs to the bridge pools sub-storage
pub fn is_bridge_pool_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &BRIDGE_POOL_ADDRESS)
}

/// Check if a key belongs to the bridge pool but is not
/// the key for the pending transaction pool. Such keys
/// may not be modified via transactions.
pub fn is_protected_storage(key: &Key) -> bool {
    is_bridge_pool_key(key) && *key != get_pending_key()
}
