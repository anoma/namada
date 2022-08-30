//! Functionality for accessing the `eth_msgs/...` subspace
use crate::types::ethereum_events::EthereumEvent;
use crate::types::hash::Hash;
use crate::types::storage::Key;

#[allow(missing_docs)]
pub const PREFIX_KEY_SEGMENT: &str = "eth_msgs";

/// Get the key prefix corresponding to where details of seen [`EthereumEvent`]s
/// are stored
pub fn prefix() -> Key {
    super::prefix()
        .push(&PREFIX_KEY_SEGMENT.to_owned())
        .expect("should always be able to construct this key")
}

const BODY_KEY_SEGMENT: &str = "body";
const SEEN_KEY_SEGMENT: &str = "seen";
const SEEN_BY_KEY_SEGMENT: &str = "seen_by";
const VOTING_POWER_KEY_SEGMENT: &str = "voting_power";

/// Generator for the keys under which details of an [`EthereumEvent`] is stored
pub struct Keys {
    /// The prefix under which the details are an [`EthereumEvent`] is stored
    pub prefix: Key,
}

impl Keys {
    /// Get the `body` key- there should be an [`EthereumEvent`] stored here.
    pub fn body(&self) -> Key {
        self.prefix
            .push(&BODY_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
    }

    /// Get the `seen` key - there should be a [`bool`] stored here.
    pub fn seen(&self) -> Key {
        self.prefix
            .push(&SEEN_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
    }

    /// Get the `seen_by` key - there should be a [`Vec<Address>`] stored here.
    pub fn seen_by(&self) -> Key {
        self.prefix
            .push(&SEEN_BY_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
    }

    /// Get the `voting_power` key - there should be a `(u64, u64)` stored
    /// here.
    pub fn voting_power(&self) -> Key {
        self.prefix
            .push(&VOTING_POWER_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
    }
}

impl IntoIterator for &Keys {
    type IntoIter = std::vec::IntoIter<Self::Item>;
    type Item = Key;

    fn into_iter(self) -> Self::IntoIter {
        vec![
            self.body(),
            self.seen(),
            self.seen_by(),
            self.voting_power(),
        ]
        .into_iter()
    }
}

impl From<&EthereumEvent> for Keys {
    fn from(event: &EthereumEvent) -> Self {
        let hash = event
            .hash()
            .expect("should always be able to hash Ethereum events");
        (&hash).into()
    }
}

impl From<&Hash> for Keys {
    fn from(hash: &Hash) -> Self {
        let hex = format!("{}", hash);
        let prefix = prefix()
            .push(&hex)
            .expect("should always be able to construct this key");
        Self { prefix }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::eth_bridge::ADDRESS;
    use crate::types::storage::DbKeySeg;

    fn arbitrary_event_with_hash() -> (EthereumEvent, String) {
        (
            EthereumEvent::TransfersToNamada {
                nonce: 1.into(),
                transfers: vec![],
            },
            "06799912C0FD8785EE29E13DFB84FE2778AF6D9CA026BD5B054F86CE9FE8C017"
                .to_owned(),
        )
    }

    #[test]
    fn test_prefix() {
        assert_matches!(&prefix().segments[..], [
                DbKeySeg::AddressSeg(ADDRESS),
                DbKeySeg::StringSeg(s),
            ] if s == PREFIX_KEY_SEGMENT)
    }

    #[test]
    fn test_keys_all_keys() {
        let (event, hash) = arbitrary_event_with_hash();
        let keys: Keys = (&event).into();
        let prefix = vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(PREFIX_KEY_SEGMENT.to_owned()),
            DbKeySeg::StringSeg(hash),
        ];
        let body_key = keys.body();
        assert_eq!(body_key.segments[..3], prefix[..]);
        assert_eq!(
            body_key.segments[3],
            DbKeySeg::StringSeg(BODY_KEY_SEGMENT.to_owned())
        );

        let seen_key = keys.seen();
        assert_eq!(seen_key.segments[..3], prefix[..]);
        assert_eq!(
            seen_key.segments[3],
            DbKeySeg::StringSeg(SEEN_KEY_SEGMENT.to_owned())
        );

        let seen_by_key = keys.seen_by();
        assert_eq!(seen_by_key.segments[..3], prefix[..]);
        assert_eq!(
            seen_by_key.segments[3],
            DbKeySeg::StringSeg(SEEN_BY_KEY_SEGMENT.to_owned())
        );

        let voting_power_key = keys.voting_power();
        assert_eq!(voting_power_key.segments[..3], prefix[..]);
        assert_eq!(
            voting_power_key.segments[3],
            DbKeySeg::StringSeg(VOTING_POWER_KEY_SEGMENT.to_owned())
        );
    }

    #[test]
    fn test_keys_into_iter() {
        let (event, _) = arbitrary_event_with_hash();
        let keys: Keys = (&event).into();
        let as_keys: Vec<_> = keys.into_iter().collect();
        assert_eq!(
            as_keys,
            vec![
                keys.body(),
                keys.seen(),
                keys.seen_by(),
                keys.voting_power(),
            ]
        );
    }

    #[test]
    fn test_keys_from_ethereum_event() {
        let (event, hash) = arbitrary_event_with_hash();
        let keys: Keys = (&event).into();
        let expected = vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(PREFIX_KEY_SEGMENT.to_owned()),
            DbKeySeg::StringSeg(hash),
        ];
        assert_eq!(&keys.prefix.segments[..], &expected[..]);
    }

    #[test]
    fn test_keys_from_hash() {
        let (event, hash) = arbitrary_event_with_hash();
        let keys: Keys = (&event.hash().unwrap()).into();
        let expected = vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(PREFIX_KEY_SEGMENT.to_owned()),
            DbKeySeg::StringSeg(hash),
        ];
        assert_eq!(&keys.prefix.segments[..], &expected[..]);
    }
}
