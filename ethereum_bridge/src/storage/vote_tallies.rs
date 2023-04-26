//! Functionality for accessing keys to do with tallying votes

use std::io::Write;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::eth_bridge::ADDRESS;
use namada_core::types::ethereum_events::{EthereumEvent, Uint};
use namada_core::types::hash::Hash;
use namada_core::types::keccak::KeccakHash;
use namada_core::types::storage::{DbKeySeg, Epoch, Key};
use namada_core::types::vote_extensions::validator_set_update::VotingPowersMap;
use namada_macros::StorageKeys;

use crate::storage::proof::{BridgePoolRootProof, EthereumProof};

/// Storage sub-key space reserved to keeping track of the
/// voting power assigned to Ethereum events.
pub const ETH_MSGS_PREFIX_KEY_SEGMENT: &str = "eth_msgs";

/// Storage sub-key space reserved to keeping track of the
/// voting power assigned to Ethereum bridge pool roots and
/// nonces.
pub const BRIDGE_POOL_ROOT_PREFIX_KEY_SEGMENT: &str = "bp_root_and_nonce";

/// Storage sub-key space reserved to keeping track of the
/// voting power assigned to validator set updates.
pub const VALSET_UPDS_PREFIX_KEY_SEGMENT: &str = "validator_set_updates";

/// Storage segments of [`Keys`].
#[derive(StorageKeys)]
pub struct KeysSegments {
    /// The data being voted on, corresponding to the `T` type
    /// argument in [`Keys`].
    pub body: &'static str,
    /// Whether more than two thirds of voting power across different
    /// epochs have voted on `body`.
    pub seen: &'static str,
    /// The validators who have voted on `body`.
    pub seen_by: &'static str,
    /// The total voting power behind `body`.
    pub voting_power: &'static str,
    /// The epoch when voting on `body` started.
    pub voting_started_epoch: &'static str,
}

/// Generator for the keys under which details of votes for some piece of data
/// is stored
#[derive(Clone, PartialEq)]
pub struct Keys<T> {
    /// The prefix under which the details of a piece of data for which we are
    /// tallying votes is stored
    pub prefix: Key,
    _phantom: std::marker::PhantomData<*const T>,
}

impl Keys<()> {
    /// Return the storage key segments to be stored under [`Keys`].
    #[inline(always)]
    pub fn segments() -> &'static KeysSegments {
        &KeysSegments::VALUES
    }
}

impl<T> Keys<T> {
    /// Get the `body` key - there should be a Borsh-serialized `T` stored
    /// here.
    pub fn body(&self) -> Key {
        self.prefix
            .push(&KeysSegments::VALUES.body.to_owned())
            .expect("should always be able to construct this key")
    }

    /// Get the `seen` key - there should be a [`bool`] stored here.
    pub fn seen(&self) -> Key {
        self.prefix
            .push(&KeysSegments::VALUES.seen.to_owned())
            .expect("should always be able to construct this key")
    }

    /// Get the `seen_by` key - there should be a `BTreeSet<Address>` stored
    /// here.
    pub fn seen_by(&self) -> Key {
        self.prefix
            .push(&KeysSegments::VALUES.seen_by.to_owned())
            .expect("should always be able to construct this key")
    }

    /// Get the `voting_power` key - there should be a `(u64, u64)` stored
    /// here.
    pub fn voting_power(&self) -> Key {
        self.prefix
            .push(&KeysSegments::VALUES.voting_power.to_owned())
            .expect("should always be able to construct this key")
    }

    /// Get the `voting_started_epoch` key - there should be an [`Epoch`] stored
    /// here.
    pub fn voting_started_epoch(&self) -> Key {
        self.prefix
            .push(&KeysSegments::VALUES.voting_started_epoch.to_owned())
            .expect("should always be able to construct this key")
    }
}

impl<T> IntoIterator for &Keys<T> {
    type IntoIter = std::vec::IntoIter<Self::Item>;
    type Item = Key;

    fn into_iter(self) -> Self::IntoIter {
        vec![
            self.body(),
            self.seen(),
            self.seen_by(),
            self.voting_power(),
            self.voting_started_epoch(),
        ]
        .into_iter()
    }
}

/// Get the key prefix corresponding to the storage location of
/// [`EthereumEvent`]s whose "seen" state is being tracked.
pub fn eth_msgs_prefix() -> Key {
    super::prefix()
        .push(&ETH_MSGS_PREFIX_KEY_SEGMENT.to_owned())
        .expect("should always be able to construct this key")
}

/// Get the Keys from the storage key. It returns None if the storage key isn't
/// for an Ethereum event.
pub fn eth_event_keys(storage_key: &Key) -> Option<Keys<EthereumEvent>> {
    match &storage_key.segments[..] {
        [
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(hash),
            ..,
        ] if prefix == ETH_MSGS_PREFIX_KEY_SEGMENT => {
            let hash = &Hash::from_str(hash).expect("Hash should be parsable");
            Some(hash.into())
        }
        _ => None,
    }
}

/// Return true if the storage key is a key to store the epoch
pub fn is_epoch_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
                DbKeySeg::AddressSeg(ADDRESS),
                DbKeySeg::StringSeg(_prefix),
                DbKeySeg::StringSeg(_hash),
                DbKeySeg::StringSeg(e),
            ] if e == KeysSegments::VALUES.voting_started_epoch)
}

/// Return true if the storage key is a key to store the `seen`
pub fn is_seen_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
                DbKeySeg::AddressSeg(ADDRESS),
                DbKeySeg::StringSeg(_prefix),
                DbKeySeg::StringSeg(_hash),
                DbKeySeg::StringSeg(e),
            ] if e == KeysSegments::VALUES.seen)
}

impl From<&EthereumEvent> for Keys<EthereumEvent> {
    fn from(event: &EthereumEvent) -> Self {
        let hash = event
            .hash()
            .expect("should always be able to hash Ethereum events");
        (&hash).into()
    }
}

impl From<&Hash> for Keys<EthereumEvent> {
    fn from(hash: &Hash) -> Self {
        let hex = format!("{}", hash);
        let prefix = eth_msgs_prefix()
            .push(&hex)
            .expect("should always be able to construct this key");
        Keys {
            prefix,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// A wrapper struct for managing keys related to
/// tracking signatures over bridge pool roots and nonces.
#[derive(Clone)]
pub struct BridgePoolRoot(pub BridgePoolRootProof);

impl BorshSerialize for BridgePoolRoot {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for BridgePoolRoot {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        <EthereumProof<(KeccakHash, Uint)> as BorshDeserialize>::deserialize(
            buf,
        )
        .map(BridgePoolRoot)
    }
}

impl<'a> From<&'a BridgePoolRoot> for Keys<BridgePoolRoot> {
    fn from(bp_root: &BridgePoolRoot) -> Self {
        let hash = [bp_root.0.data.0.to_string(), bp_root.0.data.1.to_string()]
            .concat();
        let prefix = super::prefix()
            .push(&BRIDGE_POOL_ROOT_PREFIX_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
            .push(&hash)
            .expect("should always be able to construct this key");
        Keys {
            prefix,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl From<BridgePoolRoot> for Keys<BridgePoolRoot> {
    fn from(bp_root: BridgePoolRoot) -> Self {
        Self::from(&bp_root)
    }
}

/// Get the key prefix corresponding to the storage location of validator set
/// updates whose "seen" state is being tracked.
pub fn valset_upds_prefix() -> Key {
    super::prefix()
        .push(&VALSET_UPDS_PREFIX_KEY_SEGMENT.to_owned())
        .expect("should always be able to construct this key")
}

impl From<&Epoch> for Keys<EthereumProof<VotingPowersMap>> {
    fn from(epoch: &Epoch) -> Self {
        let prefix = valset_upds_prefix()
            .push(epoch)
            .expect("should always be able to construct this key");
        Keys {
            prefix,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;

    mod helpers {
        use super::*;

        pub(super) fn arbitrary_event_with_hash() -> (EthereumEvent, String) {
            (
                EthereumEvent::TransfersToNamada {
                    nonce: 0.into(),
                    transfers: vec![],
                    valid_transfers_map: vec![],
                },
                "9E1736C43D19118E6CE4302118AF337109491ECC52757DFB949BAD6A7940B0C2"
                    .to_owned(),
            )
        }
    }

    #[test]
    fn test_eth_msgs_prefix() {
        assert_matches!(&eth_msgs_prefix().segments[..], [
                DbKeySeg::AddressSeg(ADDRESS),
                DbKeySeg::StringSeg(s),
            ] if s == ETH_MSGS_PREFIX_KEY_SEGMENT)
    }

    #[test]
    fn test_ethereum_event_keys_all_keys() {
        let (event, hash) = helpers::arbitrary_event_with_hash();
        let keys: Keys<EthereumEvent> = (&event).into();
        let prefix = vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(ETH_MSGS_PREFIX_KEY_SEGMENT.to_owned()),
            DbKeySeg::StringSeg(hash),
        ];
        let body_key = keys.body();
        assert_eq!(body_key.segments[..3], prefix[..]);
        assert_eq!(
            body_key.segments[3],
            DbKeySeg::StringSeg(KeysSegments::VALUES.body.to_owned())
        );

        let seen_key = keys.seen();
        assert_eq!(seen_key.segments[..3], prefix[..]);
        assert_eq!(
            seen_key.segments[3],
            DbKeySeg::StringSeg(KeysSegments::VALUES.seen.to_owned())
        );

        let seen_by_key = keys.seen_by();
        assert_eq!(seen_by_key.segments[..3], prefix[..]);
        assert_eq!(
            seen_by_key.segments[3],
            DbKeySeg::StringSeg(KeysSegments::VALUES.seen_by.to_owned())
        );

        let voting_power_key = keys.voting_power();
        assert_eq!(voting_power_key.segments[..3], prefix[..]);
        assert_eq!(
            voting_power_key.segments[3],
            DbKeySeg::StringSeg(KeysSegments::VALUES.voting_power.to_owned())
        );
    }

    #[test]
    fn test_ethereum_event_keys_into_iter() {
        let (event, _) = helpers::arbitrary_event_with_hash();
        let keys: Keys<EthereumEvent> = (&event).into();
        let as_keys: Vec<_> = keys.into_iter().collect();
        assert_eq!(
            as_keys,
            vec![
                keys.body(),
                keys.seen(),
                keys.seen_by(),
                keys.voting_power(),
                keys.voting_started_epoch(),
            ]
        );
    }

    #[test]
    fn test_ethereum_event_keys_from_ethereum_event() {
        let (event, hash) = helpers::arbitrary_event_with_hash();
        let keys: Keys<EthereumEvent> = (&event).into();
        let expected = vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(ETH_MSGS_PREFIX_KEY_SEGMENT.to_owned()),
            DbKeySeg::StringSeg(hash),
        ];
        assert_eq!(&keys.prefix.segments[..], &expected[..]);
    }

    #[test]
    fn test_ethereum_event_keys_from_hash() {
        let (event, hash) = helpers::arbitrary_event_with_hash();
        let keys: Keys<EthereumEvent> = (&event.hash().unwrap()).into();
        let expected = vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(ETH_MSGS_PREFIX_KEY_SEGMENT.to_owned()),
            DbKeySeg::StringSeg(hash),
        ];
        assert_eq!(&keys.prefix.segments[..], &expected[..]);
    }
}
