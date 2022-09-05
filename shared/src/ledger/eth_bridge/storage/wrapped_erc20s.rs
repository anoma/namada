//! Functionality for accessing the multitoken subspace
use std::str::FromStr;

use eyre::{eyre, Context};

use crate::ledger::eth_bridge::ADDRESS;
use crate::types::address::Address;
use crate::types::ethereum_events::EthAddress;
use crate::types::storage::{DbKeySeg, Key, KeySeg};

#[allow(missing_docs)]
pub const PREFIX_KEY_SEGMENT: &str = "ERC20";

/// Get the key prefix corresponding to the storage subspace that holds wrapped
/// ERC20 tokens
pub fn prefix() -> Key {
    super::prefix()
        .push(&PREFIX_KEY_SEGMENT.to_owned())
        .expect("should always be able to construct this key")
}

const BALANCE_KEY_SEGMENT: &str = "balance";
const SUPPLY_KEY_SEGMENT: &str = "supply";

/// Generator for the keys under which details of an ERC20 token are stored
pub struct Keys {
    /// The prefix of keys under which the details for a specific ERC20 token
    /// are stored
    pub prefix: Key,
}

impl Keys {
    /// Get the `balance` key for a specific owner - there should be a
    /// [`crate::types::token::Amount`] stored here
    pub fn balance(&self, owner: &Address) -> Key {
        self.prefix
            .push(&BALANCE_KEY_SEGMENT.to_owned())
            .expect("should always be able to construct this key")
            .push(&format!("#{}", owner.encode()))
            .expect("should always be able to construct this key")
    }

    /// Get the `supply` key - there should be a
    /// [`crate::types::token::Amount`] stored here
    pub fn supply(&self) -> Key {
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

#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum MultitokenKeyType {
    Balance { owner: Address },
    Supply,
}

#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct MultitokenKey {
    pub asset: EthAddress,
    pub suffix: MultitokenKeyType,
}

#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error that may be returned
pub struct Error(#[from] eyre::Error);

impl From<&MultitokenKey> for Key {
    fn from(mt_key: &MultitokenKey) -> Self {
        let keys = Keys::from(&mt_key.asset);
        match &mt_key.suffix {
            MultitokenKeyType::Balance { owner } => keys.balance(owner),
            MultitokenKeyType::Supply => keys.supply(),
        }
    }
}

impl From<MultitokenKey> for Key {
    fn from(mt_key: MultitokenKey) -> Self {
        (&mt_key).into()
    }
}

impl TryFrom<&Key> for MultitokenKey {
    type Error = Error;

    // TODO: make this code prettier
    // TODO: write tests for this
    fn try_from(key: &Key) -> Result<Self, Self::Error> {
        match key.segments.get(0) {
            Some(segment) => {
                if segment != &ADDRESS.to_db_key() {
                    return Err(Error::from(eyre!(
                        "key does not belong to this account"
                    )));
                }
            }
            None => return Err(Error::from(eyre!("key has no segments"))),
        }
        match key.segments.get(1) {
            Some(segment) => {
                if segment
                    != &DbKeySeg::StringSeg(PREFIX_KEY_SEGMENT.to_owned())
                {
                    return Err(Error::from(eyre!(
                        "key does not have the correct multitoken segment"
                    )));
                }
            }
            None => {
                return Err(Error::from(eyre!(
                    "key has no segment at index #1"
                )));
            }
        }

        let asset = match key.segments.get(2) {
            Some(segment) => match segment {
                DbKeySeg::StringSeg(segment) => EthAddress::from_str(segment)?,
                _ => {
                    return Err(Error::from(eyre!(
                        "key has unrecognized segment at index #2"
                    )));
                }
            },
            None => {
                return Err(Error::from(eyre!(
                    "key has no segment at index #2"
                )));
            }
        };

        let segment_3 = match key.segments.get(3) {
            Some(segment) => match segment {
                DbKeySeg::StringSeg(segment) => segment.to_owned(),
                _ => {
                    return Err(Error::from(eyre!(
                        "key has unrecognized segment at index #3"
                    )));
                }
            },
            None => {
                return Err(Error::from(eyre!(
                    "key has no segment at index #3"
                )));
            }
        };

        match segment_3.as_str() {
            SUPPLY_KEY_SEGMENT => {
                let supply_key = MultitokenKey {
                    asset,
                    suffix: MultitokenKeyType::Supply,
                };
                Ok(supply_key)
            }
            BALANCE_KEY_SEGMENT => {
                let owner = match key.segments.get(4) {
                    Some(segment) => match segment {
                        DbKeySeg::StringSeg(segment) => {
                            Address::decode(segment).wrap_err_with(|| {
                                "couldn't decode segment at index #4 into \
                                 address"
                            })?
                        }
                        _ => {
                            return Err(Error::from(eyre!(
                                "key has unrecognized segment at index #4"
                            )));
                        }
                    },
                    None => {
                        return Err(Error::from(eyre!(
                            "key has no segment at index #4"
                        )));
                    }
                };
                let balance_key = MultitokenKey {
                    asset,
                    suffix: MultitokenKeyType::Balance { owner },
                };
                Ok(balance_key)
            }
            _ => Err(Error::from(eyre!(
                "key has unrecognized string segment at index #3"
            ))),
        }
    }
}

#[cfg(test)]
mod test {
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
            multitoken_path == PREFIX_KEY_SEGMENT
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
            multitoken_path == PREFIX_KEY_SEGMENT &&
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
            multitoken_path == PREFIX_KEY_SEGMENT &&
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
            multitoken_path == PREFIX_KEY_SEGMENT &&
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
        let wdai_supply = MultitokenKey {
            asset: DAI_ERC20_ETH_ADDRESS,
            suffix: MultitokenKeyType::Supply,
        };
        let key: Key = wdai_supply.into();
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(supply_key_seg),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == PREFIX_KEY_SEGMENT &&
            token_id == &DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase() &&
            supply_key_seg == SUPPLY_KEY_SEGMENT
        );

        // balance key
        let wdai_balance = MultitokenKey {
            asset: DAI_ERC20_ETH_ADDRESS,
            suffix: MultitokenKeyType::Balance {
                owner: Address::from_str(ARBITRARY_OWNER_ADDRESS).unwrap(),
            },
        };
        let key: Key = wdai_balance.into();
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::StringSeg(multitoken_path),
                DbKeySeg::StringSeg(token_id),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::AddressSeg(owner_addr),
            ] if multitoken_addr == &ADDRESS &&
            multitoken_path == PREFIX_KEY_SEGMENT &&
            token_id == &DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase() &&
            balance_key_seg == BALANCE_KEY_SEGMENT &&
            owner_addr == &Address::decode(ARBITRARY_OWNER_ADDRESS).unwrap()
        );
    }
}
