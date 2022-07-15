//! storage helpers
use super::vp::ADDRESS;
use crate::types::hash::Hash;
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

/// Convenient way to generate /eth_msgs keys
pub struct EthMsgKeys {
    /// The prefix under which the keys for the EthMsg are stored
    pub prefix: Key,
}

impl EthMsgKeys {
    /// Create a new [`EthMsgKeys`] based on the hash
    pub fn new(msg_hash: Hash) -> Self {
        let hex = format!("{}", msg_hash);
        let prefix = eth_msgs_key().push(&hex).expect(
            "should always be able to construct prefix, given hex-encoded hash",
        );
        Self { prefix }
    }

    /// Get the `body` key for the given EthMsg
    pub fn body(&self) -> Key {
        self.prefix.push(&"body".to_owned()).unwrap()
    }

    /// Get the `seen` key for the given EthMsg
    pub fn seen(&self) -> Key {
        self.prefix.push(&"seen".to_owned()).unwrap()
    }

    /// Get the `seen_by` key for the given EthMsg
    pub fn seen_by(&self) -> Key {
        self.prefix.push(&"seen_by".to_owned()).unwrap()
    }

    /// Get the `voting_power` key for the given EthMsg
    pub fn voting_power(&self) -> Key {
        self.prefix.push(&"voting_power".to_owned()).unwrap()
    }
}

// TODO: tests for EthMsgKeys

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
