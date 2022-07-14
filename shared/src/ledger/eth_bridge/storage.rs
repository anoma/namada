//! storage helpers
use super::vp::ADDRESS;
use crate::types::storage::{DbKeySeg, Key, KeySeg};

const QUEUE_STORAGE_KEY: &str = "queue";

/// Get the key corresponding to @EthBridge/queue
pub fn queue_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&QUEUE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

const ETH_MSGS_STORAGE_KEY: &str = "eth_msgs";

/// Get the key corresponding to the /eth_msgs storage subspace
pub fn eth_msgs_key() -> Key {
    Key::from(DbKeySeg::StringSeg(ETH_MSGS_STORAGE_KEY.to_owned()))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_eth_msgs_key() {
        assert!(
            matches!(&eth_msgs_key().segments[..], [DbKeySeg::StringSeg(s)] if s == ETH_MSGS_STORAGE_KEY)
        )
    }
}
