//! Functionality for accessing the storage subspace

pub mod bridge_pool;
pub mod eth_bridge_queries;
pub mod parameters;
pub mod proof;
pub mod vote_tallies;
pub mod vp;
pub mod whitelist;
pub mod wrapped_erc20s;

use namada_core::address::Address;
use namada_core::storage::{DbKeySeg, Key, KeySeg};
pub use namada_parameters::native_erc20_key;
use namada_parameters::storage::*;
use namada_parameters::ADDRESS as PARAM_ADDRESS;
use namada_trans_token::storage_key::balance_key;

use crate::ADDRESS;

/// Key prefix for the storage subspace
pub fn prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
}

/// Key for storing the initial Ethereum block height when
/// events will first be extracted from.
pub fn eth_start_height_key() -> Key {
    get_eth_start_height_key_at_addr(PARAM_ADDRESS)
}

/// The key to the escrow of the VP.
pub fn escrow_key(nam_addr: &Address) -> Key {
    balance_key(nam_addr, &ADDRESS)
}

/// Check if the given `key` contains an Ethereum
/// bridge address segment.
#[inline]
pub fn has_eth_addr_segment(key: &Key) -> bool {
    key.segments
        .iter()
        .any(|s| matches!(s, DbKeySeg::AddressSeg(ADDRESS)))
}

/// Returns whether a key belongs to this account or not
pub fn is_eth_bridge_key(nam_addr: &Address, key: &Key) -> bool {
    key == &escrow_key(nam_addr)
        || matches!(key.segments.first(), Some(first_segment) if first_segment == &ADDRESS.to_db_key())
        || wrapped_erc20s::has_erc20_segment(key)
}

/// A key for storing the active / inactive status
/// of the Ethereum bridge.
pub fn active_key() -> Key {
    get_active_status_key_at_addr(PARAM_ADDRESS)
}

/// Storage key for the minimum confirmations parameter.
pub fn min_confirmations_key() -> Key {
    get_min_confirmations_key_at_addr(PARAM_ADDRESS)
}

/// Storage key for the Ethereum address of the bridge contract.
pub fn bridge_contract_key() -> Key {
    get_bridge_contract_address_key_at_addr(PARAM_ADDRESS)
}

#[cfg(test)]
mod test {
    use namada_core::address;
    use namada_core::address::testing::nam;
    use namada_core::ethereum_events::testing::arbitrary_eth_address;

    use super::*;

    #[test]
    fn test_is_eth_bridge_key_returns_true_for_eth_bridge_address() {
        let key = Key::from(super::ADDRESS.to_db_key());
        assert!(is_eth_bridge_key(&nam(), &key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_true_for_eth_bridge_subkey() {
        let key = Key::from(super::ADDRESS.to_db_key())
            .push(&"arbitrary key segment".to_owned())
            .expect("Could not set up test");
        assert!(is_eth_bridge_key(&nam(), &key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_true_for_eth_bridge_balance_key() {
        let eth_addr = arbitrary_eth_address();
        let token = address::Address::Internal(
            address::InternalAddress::Erc20(eth_addr),
        );
        let key =
            balance_key(&token, &address::testing::established_address_1());
        assert!(is_eth_bridge_key(&nam(), &key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_false_for_different_address() {
        let key =
            Key::from(address::testing::established_address_1().to_db_key());
        assert!(!is_eth_bridge_key(&nam(), &key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_false_for_different_address_subkey() {
        let key =
            Key::from(address::testing::established_address_1().to_db_key())
                .push(&"arbitrary key segment".to_owned())
                .expect("Could not set up test");
        assert!(!is_eth_bridge_key(&nam(), &key));
    }

    #[test]
    fn test_is_eth_bridge_key_returns_false_for_non_eth_bridge_balance_key() {
        let key =
            balance_key(&nam(), &address::testing::established_address_1());
        assert!(!is_eth_bridge_key(&nam(), &key));
    }
}
