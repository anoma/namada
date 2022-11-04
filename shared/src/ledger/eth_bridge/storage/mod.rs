//! Functionality for accessing the storage subspace
pub mod bridge_pool;
pub mod vote_tallies;
pub mod wrapped_erc20s;

use super::ADDRESS;
use crate::types::address::xan;
use crate::types::storage::{Key, KeySeg};
use crate::types::token::balance_key;

/// Key prefix for the storage subspace
pub fn prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
}

/// The key to the escrow of the VP.
pub fn escrow_key() -> Key {
    balance_key(&xan(), &ADDRESS)
}

/// Returns whether a key belongs to this account or not
pub fn is_eth_bridge_key(key: &Key) -> bool {
    key == &escrow_key()
        || matches!(key.segments.get(0), Some(first_segment) if first_segment == &ADDRESS.to_db_key())
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
