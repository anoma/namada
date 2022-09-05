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
