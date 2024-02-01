//! ERC20 token whitelist storage data.
//!
//! These storage keys should only ever be written to by governance,
//! or `InitChain`.

use std::str::FromStr;

use namada_core::eth_bridge_pool::erc20_token_address;
use namada_core::ethereum_events::EthAddress;
use namada_core::storage;
use namada_core::storage::DbKeySeg;
use namada_trans_token::storage_key::{denom_key, minted_balance_key};

use super::prefix as ethbridge_key_prefix;
use crate::ADDRESS as BRIDGE_ADDRESS;

mod segments {
    //! Storage key segments under the token whitelist.
    use namada_core::address::Address;
    use namada_macros::StorageKeys;

    /// The name of the main storage segment.
    pub(super) const MAIN_SEGMENT: &str = "whitelist";

    /// Storage key segments under the token whitelist.
    #[derive(StorageKeys)]
    pub(super) struct Segments {
        /// Whether an ERC20 asset is whitelisted or not.
        pub whitelisted: &'static str,
        /// The token cap of an ERC20 asset.
        pub cap: &'static str,
    }

    /// All the values of the generated [`Segments`].
    pub(super) const VALUES: Segments = Segments::VALUES;

    /// Listing of each of the generated [`Segments`].
    pub(super) const ALL: &[&str] = Segments::ALL;
}

/// Represents the type of a key relating to whitelisted ERC20.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum KeyType {
    /// Whether an ERC20 asset is whitelisted or not.
    Whitelisted,
    /// The token cap of an ERC20 asset.
    Cap,
    /// The current supply of a wrapped ERC20 asset,
    /// circulating in Namada.
    WrappedSupply,
    /// The denomination of the ERC20 asset.
    Denomination,
}

/// Whitelisted ERC20 token storage sub-space.
pub struct Key {
    /// The specific ERC20 as identified by its Ethereum address.
    pub asset: EthAddress,
    /// The type of this key.
    pub suffix: KeyType,
}

/// Return the whitelist storage key sub-space prefix.
fn whitelist_prefix(asset: &EthAddress) -> storage::Key {
    ethbridge_key_prefix()
        .push(&segments::MAIN_SEGMENT.to_owned())
        .expect("Should be able to push a storage key segment")
        .push(&asset.to_canonical())
        .expect("Should be able to push a storage key segment")
}

impl From<Key> for storage::Key {
    #[inline]
    fn from(key: Key) -> Self {
        (&key).into()
    }
}

impl From<&Key> for storage::Key {
    fn from(key: &Key) -> Self {
        match &key.suffix {
            KeyType::Whitelisted => whitelist_prefix(&key.asset)
                .push(&segments::VALUES.whitelisted.to_owned())
                .expect("Should be able to push a storage key segment"),
            KeyType::Cap => whitelist_prefix(&key.asset)
                .push(&segments::VALUES.cap.to_owned())
                .expect("Should be able to push a storage key segment"),
            KeyType::WrappedSupply => {
                let token = erc20_token_address(&key.asset);
                minted_balance_key(&token)
            }
            KeyType::Denomination => {
                let token = erc20_token_address(&key.asset);
                denom_key(&token)
            }
        }
    }
}

/// Check if some [`storage::Key`] is an Ethereum bridge whitelist key
/// of type [`KeyType::Cap`] or [`KeyType::Whitelisted`].
pub fn is_cap_or_whitelisted_key(key: &storage::Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(s1),
            DbKeySeg::StringSeg(s2),
            DbKeySeg::StringSeg(s3),
            DbKeySeg::StringSeg(s4),
        ] => {
            s1 == &BRIDGE_ADDRESS
                && s2 == segments::MAIN_SEGMENT
                && EthAddress::from_str(s3).is_ok()
                && segments::ALL.binary_search(&s4.as_str()).is_ok()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use namada_core::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;

    use super::*;

    /// Test that storage key serialization yields the expected value.
    #[test]
    fn test_keys_whitelisted_to_string() {
        let key: storage::Key = Key {
            asset: DAI_ERC20_ETH_ADDRESS,
            suffix: KeyType::Whitelisted,
        }
        .into();
        let expected = "#tnam1quqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfgdmms/\
                        whitelist/0x6b175474e89094c44da98b954eedeac495271d0f/\
                        whitelisted";
        assert_eq!(expected, key.to_string());
    }

    /// Test that checking if a key is of type "cap" or "whitelisted" works.
    #[test]
    fn test_cap_or_whitelisted_key() {
        let whitelisted_key: storage::Key = Key {
            asset: DAI_ERC20_ETH_ADDRESS,
            suffix: KeyType::Whitelisted,
        }
        .into();
        assert!(is_cap_or_whitelisted_key(&whitelisted_key));

        let cap_key: storage::Key = Key {
            asset: DAI_ERC20_ETH_ADDRESS,
            suffix: KeyType::Cap,
        }
        .into();
        assert!(is_cap_or_whitelisted_key(&cap_key));

        let unexpected_key = {
            let mut k: storage::Key = Key {
                asset: DAI_ERC20_ETH_ADDRESS,
                suffix: KeyType::Cap,
            }
            .into();
            k.segments[3] = DbKeySeg::StringSeg("abc".to_owned());
            k
        };
        assert!(!is_cap_or_whitelisted_key(&unexpected_key));
    }
}
