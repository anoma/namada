//! Functionality for accessing the multitoken subspace
use crate::types::address::Address;
use crate::types::ethereum_events::EthAddress;
use crate::types::storage::Key;

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
}
