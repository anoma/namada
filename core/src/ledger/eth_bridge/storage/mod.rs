//! Functionality for accessing the storage subspace
pub mod bridge_pool;
pub mod wrapped_erc20s;

use super::ADDRESS;
use crate::types::address::nam;
use crate::types::storage::{DbKeySeg, Key, KeySeg};
use crate::types::token::balance_key;

/// Sub-key for storing the minimum confirmations parameter
pub const MIN_CONFIRMATIONS_SUBKEY: &str = "min_confirmations";
/// Sub-key for storing the Ethereum address for wNam.
pub const NATIVE_ERC20_SUBKEY: &str = "native_erc20";
/// Sub-lkey for storing the Ethereum address of the bridge contract.
pub const BRIDGE_CONTRACT_SUBKEY: &str = "bridge_contract_address";
/// Sub-key for storing the Ethereum address of the governance contract.
pub const GOVERNANCE_CONTRACT_SUBKEY: &str = "governance_contract_address";

/// Key prefix for the storage subspace
pub fn prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
}

/// The key to the escrow of the VP.
pub fn escrow_key() -> Key {
    balance_key(&nam(), &ADDRESS)
}

/// Returns whether a key belongs to this account or not
pub fn is_eth_bridge_key(key: &Key) -> bool {
    key == &escrow_key()
        || matches!(key.segments.get(0), Some(first_segment) if first_segment == &ADDRESS.to_db_key())
}

/// Storage key for the minimum confirmations parameter.
pub fn min_confirmations_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(MIN_CONFIRMATIONS_SUBKEY.into()),
        ],
    }
}

/// Storage key for the Ethereum address of wNam.
pub fn native_erc20_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(NATIVE_ERC20_SUBKEY.into()),
        ],
    }
}

/// Storage key for the Ethereum address of the bridge contract.
pub fn bridge_contract_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(BRIDGE_CONTRACT_SUBKEY.into()),
        ],
    }
}

/// Storage key for the Ethereum address of the governance contract.
pub fn governance_contract_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(GOVERNANCE_CONTRACT_SUBKEY.into()),
        ],
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::address;

    #[test]
    fn test_is_eth_bridge_key_returns_true_for_eth_bridge_address() {
        let key = Key::from(super::ADDRESS.to_db_key());
        assert!(is_eth_bridge_key(&key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_true_for_eth_bridge_subkey() {
        let key = Key::from(super::ADDRESS.to_db_key())
            .push(&"arbitrary key segment".to_owned())
            .expect("Could not set up test");
        assert!(is_eth_bridge_key(&key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_false_for_different_address() {
        let key =
            Key::from(address::testing::established_address_1().to_db_key());
        assert!(!is_eth_bridge_key(&key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_false_for_different_address_subkey() {
        let key =
            Key::from(address::testing::established_address_1().to_db_key())
                .push(&"arbitrary key segment".to_owned())
                .expect("Could not set up test");
        assert!(!is_eth_bridge_key(&key));
    }
}
