//! Functionality for accessing the multitoken subspace
use std::str::FromStr;

use eyre::eyre;

use crate::types::address::Address;
use crate::types::ethereum_events::EthAddress;
use crate::types::storage::{self, DbKeySeg};

#[allow(missing_docs)]
pub const MULTITOKEN_KEY_SEGMENT: &str = "ERC20";

/// Get the key prefix corresponding to the storage subspace that holds wrapped
/// ERC20 tokens
pub fn prefix() -> storage::Key {
    super::prefix()
        .push(&MULTITOKEN_KEY_SEGMENT.to_owned())
        .expect("should always be able to construct this key")
}

const BALANCE_KEY_SEGMENT: &str = "balance";
const SUPPLY_KEY_SEGMENT: &str = "supply";

/// Generator for the keys under which details of an ERC20 token are stored
pub struct Keys {
    /// The prefix of keys under which the details for a specific ERC20 token
    /// are stored
    prefix: storage::Key,
}

impl Keys {
    /// Get the `balance` key for a specific owner - there should be a
    /// [`crate::types::token::Amount`] stored here
    pub fn balance(&self, owner: &Address) -> storage::Key {
        self.prefix
            .push(&BALANCE_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
            .push(&format!("#{}", owner.encode()))
            .expect("should always be able to construct this key")
    }

    /// Get the `supply` key - there should be a
    /// [`crate::types::token::Amount`] stored here
    pub fn supply(&self) -> storage::Key {
        self.prefix
            .push(&SUPPLY_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
    }
}

impl From<&EthAddress> for Keys {
    fn from(address: &EthAddress) -> Self {
        Keys {
            prefix: prefix()
                .push(&address.to_canonical())
                .expect("should always be able to construct this key"),
        }
    }
}

/// Represents the type of a key relating to a wrapped ERC20
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum KeyType {
    /// The key holds a wrapped ERC20 balance
    Balance {
        /// The owner of the balance
        owner: Address,
    },
    /// A type of key which tracks the total supply of some wrapped ERC20
    Supply,
}

/// Represents a key relating to a wrapped ERC20
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct Key {
    /// The specific ERC20 as identified by its Ethereum address
    pub asset: EthAddress,
    /// The type of this key
    pub suffix: KeyType,
}

impl From<&Key> for storage::Key {
    fn from(mt_key: &Key) -> Self {
        let keys = Keys::from(&mt_key.asset);
        match &mt_key.suffix {
            KeyType::Balance { owner } => keys.balance(owner),
            KeyType::Supply => keys.supply(),
        }
    }
}

fn has_erc20_segment(key: &storage::Key) -> bool {
    matches!(
        key.segments.get(1),
        Some(segment) if segment == &DbKeySeg::StringSeg(MULTITOKEN_KEY_SEGMENT.to_owned()),
    )
}

impl TryFrom<&storage::Key> for Key {
    type Error = eyre::Error;

    fn try_from(key: &storage::Key) -> Result<Self, Self::Error> {
        if !super::is_eth_bridge_key(key) {
            return Err(eyre!("key does not belong to the EthBridge"));
        }
        if !has_erc20_segment(key) {
            return Err(eyre!("key does not have ERC20 segment"));
        }

        let asset = match key.segments.get(2) {
            Some(segment) => match segment {
                DbKeySeg::StringSeg(segment) => EthAddress::from_str(segment)?,
                _ => {
                    return Err(eyre!(
                        "key has unrecognized segment at index #2, expected \
                         an Ethereum address"
                    ));
                }
            },
            None => {
                return Err(eyre!(
                    "key has no segment at index #2, expected an Ethereum \
                     address"
                ));
            }
        };

        let segment_3 = match key.segments.get(3) {
            Some(segment) => match segment {
                DbKeySeg::StringSeg(segment) => segment.to_owned(),
                _ => {
                    return Err(eyre!(
                        "key has unrecognized segment at index #3, expected a \
                         string segment"
                    ));
                }
            },
            None => {
                return Err(eyre!(
                    "key has no segment at index #3, expected a string segment"
                ));
            }
        };

        match segment_3.as_str() {
            SUPPLY_KEY_SEGMENT => {
                let supply_key = Key {
                    asset,
                    suffix: KeyType::Supply,
                };
                Ok(supply_key)
            }
            BALANCE_KEY_SEGMENT => {
                let owner = match key.segments.get(4) {
                    Some(segment) => match segment {
                        DbKeySeg::AddressSeg(address) => address.to_owned(),
                        DbKeySeg::StringSeg(_) => {
                            return Err(eyre!(
                                "key has string segment at index #4, expected \
                                 an address segment"
                            ));
                        }
                    },
                    None => {
                        return Err(eyre!(
                            "key has no segment at index #4, expected an \
                             address segment"
                        ));
                    }
                };
                let balance_key = Key {
                    asset,
                    suffix: KeyType::Balance { owner },
                };
                Ok(balance_key)
            }
            _ => Err(eyre!("key has unrecognized string segment at index #3")),
        }
    }
}

#[cfg(test)]
mod test {
    use std::result::Result;
    use std::str::FromStr;

    use super::*;
    use crate::ledger::eth_bridge::ADDRESS;
    use crate::types::address::Address;
    use crate::types::ethereum_events::testing::{
        DAI_ERC20_ETH_ADDRESS, DAI_ERC20_ETH_ADDRESS_CHECKSUMMED,
    };
    use crate::types::storage::DbKeySeg;

    const ARBITRARY_OWNER_ADDRESS: &str =
        "atest1d9khqw36x9zyxwfhgfpygv2pgc65gse4gy6rjs34gfzr2v69gy6y23zpggurjv2yx5m52sesu6r4y4";

    #[test]
    fn test_prefix() {
        assert_matches!(
            &prefix().segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_KEY_SEGMENT
        )
    }

    #[test]
    fn test_keys_from_eth_address() {
        let keys: Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        assert_matches!(
            &keys.prefix.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_KEY_SEGMENT &&
            token_id == &DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase()
        )
    }

    #[test]
    fn test_keys_balance() {
        let keys: Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        let key =
            keys.balance(&Address::from_str(ARBITRARY_OWNER_ADDRESS).unwrap());
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::AddressSeg(owner_addr),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_KEY_SEGMENT &&
            token_id == &DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase() &&
            balance_key_seg == BALANCE_KEY_SEGMENT &&
            owner_addr == &Address::decode(ARBITRARY_OWNER_ADDRESS).unwrap()
        )
    }

    #[test]
    fn test_keys_balance_to_string() {
        let keys: Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        let key =
            keys.balance(&Address::from_str(ARBITRARY_OWNER_ADDRESS).unwrap());
        assert_eq!(
                "#atest1v9hx7w36g42ysgzzwf5kgem9ypqkgerjv4ehxgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq8f99ew/ERC20/0x6b175474e89094c44da98b954eedeac495271d0f/balance/#atest1d9khqw36x9zyxwfhgfpygv2pgc65gse4gy6rjs34gfzr2v69gy6y23zpggurjv2yx5m52sesu6r4y4",
                key.to_string()
            )
    }

    #[test]
    fn test_keys_supply() {
        let keys: Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        let key = keys.supply();
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(supply_key_seg),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_KEY_SEGMENT &&
            token_id == &DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase() &&
            supply_key_seg == SUPPLY_KEY_SEGMENT
        )
    }

    #[test]
    fn test_keys_supply_to_string() {
        let keys: Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        let key = keys.supply();
        assert_eq!(
                "#atest1v9hx7w36g42ysgzzwf5kgem9ypqkgerjv4ehxgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq8f99ew/ERC20/0x6b175474e89094c44da98b954eedeac495271d0f/supply",
                key.to_string(),
            )
    }

    #[test]
    fn test_from_multitoken_key_for_key() {
        // supply key
        let wdai_supply = Key {
            asset: DAI_ERC20_ETH_ADDRESS,
            suffix: KeyType::Supply,
        };
        let key: storage::Key = (&wdai_supply).into();
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(supply_key_seg),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_KEY_SEGMENT &&
            token_id == &DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase() &&
            supply_key_seg == SUPPLY_KEY_SEGMENT
        );

        // balance key
        let wdai_balance = Key {
            asset: DAI_ERC20_ETH_ADDRESS,
            suffix: KeyType::Balance {
                owner: Address::from_str(ARBITRARY_OWNER_ADDRESS).unwrap(),
            },
        };
        let key: storage::Key = (&wdai_balance).into();
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::AddressSeg(owner_addr),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == MULTITOKEN_KEY_SEGMENT &&
            token_id == &DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase() &&
            balance_key_seg == BALANCE_KEY_SEGMENT &&
            owner_addr == &Address::decode(ARBITRARY_OWNER_ADDRESS).unwrap()
        );
    }

    #[test]
    fn test_try_from_key_for_multitoken_key_supply() {
        // supply key
        let key = storage::Key::from_str(&format!(
            "#{}/ERC20/{}/supply",
            ADDRESS,
            DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase(),
        ))
        .expect("Should be able to construct key for test");

        let result: Result<Key, _> = Key::try_from(&key);

        let mt_key = match result {
            Ok(mt_key) => mt_key,
            Err(error) => {
                panic!(
                    "Could not convert key {:?} to MultitokenKey: {:?}",
                    key, error
                )
            }
        };

        assert_eq!(mt_key.asset, DAI_ERC20_ETH_ADDRESS);
        assert_eq!(mt_key.suffix, KeyType::Supply);
    }

    #[test]
    fn test_try_from_key_for_multitoken_key_balance() {
        // supply key
        let key = storage::Key::from_str(&format!(
            "#{}/ERC20/{}/balance/#{}",
            ADDRESS,
            DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase(),
            ARBITRARY_OWNER_ADDRESS
        ))
        .expect("Should be able to construct key for test");

        let result: Result<Key, _> = Key::try_from(&key);

        let mt_key = match result {
            Ok(mt_key) => mt_key,
            Err(error) => {
                panic!(
                    "Could not convert key {:?} to MultitokenKey: {:?}",
                    key, error
                )
            }
        };

        assert_eq!(mt_key.asset, DAI_ERC20_ETH_ADDRESS);
        assert_eq!(
            mt_key.suffix,
            KeyType::Balance {
                owner: Address::from_str(ARBITRARY_OWNER_ADDRESS).unwrap()
            }
        );
    }

    #[test]
    fn test_has_erc20_segment() {
        let key = storage::Key::from_str(&format!(
            "#{}/ERC20/{}/balance/#{}",
            ADDRESS,
            DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase(),
            ARBITRARY_OWNER_ADDRESS
        ))
        .expect("Should be able to construct key for test");

        assert!(has_erc20_segment(&key));

        let key = storage::Key::from_str(&format!(
            "#{}/ERC20/{}/supply",
            ADDRESS,
            DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase(),
        ))
        .expect("Should be able to construct key for test");

        assert!(has_erc20_segment(&key));

        let key = storage::Key::from_str(&format!("#{}/ERC20", ADDRESS))
            .expect("Should be able to construct key for test");

        assert!(has_erc20_segment(&key));
    }
}
