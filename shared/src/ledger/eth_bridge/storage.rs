//! storage helpers
use super::vp::ADDRESS;
use crate::types::address::Address;
use crate::types::ethereum_events::EthAddress;
use crate::types::storage::{Key, KeySeg};

const QUEUE_STORAGE_KEY: &str = "queue";

/// Get the key corresponding to @EthBridge/queue
pub fn queue_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&QUEUE_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Keys to do with the /eth_msgs storage subspace
// TODO: This module should live with the EthSentinel VP rather than
// the EthBridge VP, as it is the EthSentinel VP which guards it
pub mod eth_msgs {
    use crate::types::hash::Hash;
    use crate::types::storage::{DbKeySeg, Key};

    const TOP_LEVEL_KEY: &str = "eth_msgs";

    /// Get the key corresponding to the /eth_msgs storage subspace
    pub fn top_level_key() -> Key {
        Key::from(DbKeySeg::StringSeg(TOP_LEVEL_KEY.to_owned()))
    }

    const BODY_KEY: &str = "body";
    const SEEN_KEY: &str = "seen";
    const SEEN_BY_KEY: &str = "seen_by";
    const VOTING_POWER_KEY: &str = "voting_power";

    /// Handle for the storage space for a specific [`EthMsg`]
    pub struct EthMsgKeys {
        /// The prefix under which the keys for the EthMsg are stored
        pub prefix: Key,
    }

    impl EthMsgKeys {
        /// Create a new [`EthMsgKeys`] based on the hash
        pub fn new(msg_hash: Hash) -> Self {
            let hex = format!("{}", msg_hash);
            let prefix = top_level_key().push(&hex).expect(
                "should always be able to construct prefix, given hex-encoded \
                 hash",
            );
            Self { prefix }
        }

        /// Get the `body` key for the given EthMsg
        pub fn body(&self) -> Key {
            self.prefix.push(&BODY_KEY.to_owned()).unwrap()
        }

        /// Get the `seen` key for the given EthMsg
        pub fn seen(&self) -> Key {
            self.prefix.push(&SEEN_KEY.to_owned()).unwrap()
        }

        /// Get the `seen_by` key for the given EthMsg
        pub fn seen_by(&self) -> Key {
            self.prefix.push(&SEEN_BY_KEY.to_owned()).unwrap()
        }

        /// Get the `voting_power` key for the given EthMsg
        pub fn voting_power(&self) -> Key {
            self.prefix.push(&VOTING_POWER_KEY.to_owned()).unwrap()
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        fn arbitrary_hash_with_hex() -> (Hash, String) {
            (Hash::sha256(b"arbitrary"), "87288D68ED71BF8FA35E531A1E56F3B3705FA0EEA54A2AA689B41694A8F83F5B".to_owned())
        }

        #[test]
        fn test_top_level_key() {
            assert!(
                matches!(&top_level_key().segments[..], [DbKeySeg::StringSeg(s)] if s == TOP_LEVEL_KEY)
            )
        }

        #[test]
        fn test_eth_msgs_keys_all_keys() {
            let (msg_hash, hex) = arbitrary_hash_with_hex();
            let keys = EthMsgKeys::new(msg_hash);
            let prefix = vec![
                DbKeySeg::StringSeg(TOP_LEVEL_KEY.to_owned()),
                DbKeySeg::StringSeg(hex),
            ];
            let body_key = keys.body();
            assert_eq!(body_key.segments[..2], prefix[..]);
            assert_eq!(
                body_key.segments[2],
                DbKeySeg::StringSeg(BODY_KEY.to_owned())
            );

            let seen_key = keys.seen();
            assert_eq!(seen_key.segments[..2], prefix[..]);
            assert_eq!(
                seen_key.segments[2],
                DbKeySeg::StringSeg(SEEN_KEY.to_owned())
            );

            let seen_by_key = keys.seen_by();
            assert_eq!(seen_by_key.segments[..2], prefix[..]);
            assert_eq!(
                seen_by_key.segments[2],
                DbKeySeg::StringSeg(SEEN_BY_KEY.to_owned())
            );

            let voting_power_key = keys.voting_power();
            assert_eq!(voting_power_key.segments[..2], prefix[..]);
            assert_eq!(
                voting_power_key.segments[2],
                DbKeySeg::StringSeg(VOTING_POWER_KEY.to_owned())
            );
        }
    }
}

pub const BALANCE_KEY_SEGMENT: &str = "balance";
pub const SUPPLY_KEY_SEGMENT: &str = "supply";
pub const MULTITOKEN_PATH: &str = "ERC20";

pub fn wrapped_erc20_balance(erc20: &EthAddress, owner: &Address) -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&MULTITOKEN_PATH.to_owned())
        .unwrap()
        .push(&erc20.to_canonical().to_owned())
        .unwrap()
        .push(&BALANCE_KEY_SEGMENT.to_owned())
        .unwrap()
        .push(&format!("#{}", owner.encode()))
        .unwrap()
}

pub fn wrapped_erc20_supply(erc20: &EthAddress) -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&MULTITOKEN_PATH.to_owned())
        .unwrap()
        .push(&erc20.to_canonical().to_owned())
        .unwrap()
        .push(&SUPPLY_KEY_SEGMENT.to_owned())
        .unwrap()
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::types::address::Address;
    use crate::types::ethereum_events::EthAddress;
    use crate::types::storage::DbKeySeg;

    const DAI_ERC20_ADDRESS: &str =
        "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    const OWNER_ADDRESS: &str =
        "atest1d9khqw36x9zyxwfhgfpygv2pgc65gse4gy6rjs34gfzr2v69gy6y23zpggurjv2yx5m52sesu6r4y4";

    fn dai() -> EthAddress {
        EthAddress::from_str(DAI_ERC20_ADDRESS).unwrap()
    }

    #[test]
    fn test_balance_segment_types() {
        let key = wrapped_erc20_balance(
            &dai(),
            &Address::from_str(OWNER_ADDRESS).unwrap(),
        );
        assert!(matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::AddressSeg(owner_addr),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_PATH &&
            token_id == &DAI_ERC20_ADDRESS.to_ascii_lowercase() &&
            balance_key_seg == BALANCE_KEY_SEGMENT &&
            owner_addr == &Address::decode(OWNER_ADDRESS).unwrap()
        ))
    }

    #[test]
    fn test_balance_to_string() {
        let key = wrapped_erc20_balance(
            &dai(),
            &Address::from_str(OWNER_ADDRESS).unwrap(),
        );
        assert_eq!(
                "#atest1v9hx7w36g42ysgzzwf5kgem9ypqkgerjv4ehxgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq8f99ew/ERC20/0x6b175474e89094c44da98b954eedeac495271d0f/balance/#atest1d9khqw36x9zyxwfhgfpygv2pgc65gse4gy6rjs34gfzr2v69gy6y23zpggurjv2yx5m52sesu6r4y4",
                key.to_string()
            )
    }

    #[test]
    fn test_supply_segment_types() {
        let key = wrapped_erc20_supply(&dai());
        assert!(matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(supply_key_seg),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_PATH &&
            token_id == &DAI_ERC20_ADDRESS.to_ascii_lowercase() &&
            supply_key_seg == SUPPLY_KEY_SEGMENT
        ))
    }

    #[test]
    fn test_supply_to_string() {
        let key = wrapped_erc20_supply(&dai());
        assert_eq!(
                "#atest1v9hx7w36g42ysgzzwf5kgem9ypqkgerjv4ehxgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq8f99ew/ERC20/0x6b175474e89094c44da98b954eedeac495271d0f/supply",
                key.to_string(),
            )
    }
}
