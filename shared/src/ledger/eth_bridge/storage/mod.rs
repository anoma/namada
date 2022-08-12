//! Functionality for accessing the storage subspace
use super::ADDRESS;
use crate::types::storage::{Key, KeySeg};

pub mod eth_msgs;
pub mod wrapped_erc20s;

/// Key prefix for the storage subspace
pub fn prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
}

/// Returns whether a key belongs to this account or not
pub fn is_eth_bridge_key(key: &Key) -> bool {
    key.segments[0] == ADDRESS.to_db_key()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_eth_bridge_key() {
        let key = Key::from(super::ADDRESS.to_db_key());
        assert!(is_eth_bridge_key(&key));

        let key = Key::from(super::ADDRESS.to_db_key())
            .push(&"arbitrary key segment".to_owned())
            .expect("Could not set up test");
        assert!(is_eth_bridge_key(&key));
    }
}
