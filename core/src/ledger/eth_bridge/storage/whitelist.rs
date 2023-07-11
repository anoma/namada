//! ERC20 token whitelist storage data.
//!
//! These storage keys should only ever be written to by governance,
//! or `InitChain`.

use std::str::FromStr;

use super::super::ADDRESS as BRIDGE_ADDRESS;
use super::{prefix as ethbridge_key_prefix, wrapped_erc20s};
use crate::types::ethereum_events::EthAddress;
use crate::types::storage;
use crate::types::storage::DbKeySeg;
use crate::types::token::{denom_key, minted_balance_key};

mod segments {
    //! Storage key segments under the token whitelist.
    use namada_macros::StorageKeys;

    use crate::types::address::Address;
    use crate::types::storage::{DbKeySeg, Key};

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
                let token = wrapped_erc20s::token(&key.asset);
                minted_balance_key(&token)
            }
            KeyType::Denomination => {
                let token = wrapped_erc20s::token(&key.asset);
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
