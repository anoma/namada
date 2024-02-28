//! Functionality for accessing the multitoken subspace

use eyre::eyre;
use namada_core::address::{Address, InternalAddress};
pub use namada_core::eth_bridge_pool::{
    erc20_nut_address as nut, erc20_token_address as token,
};
use namada_core::ethereum_events::EthAddress;
use namada_core::storage::{self, DbKeySeg};
use namada_trans_token::storage_key::{
    balance_key, minted_balance_key, MINTED_STORAGE_KEY,
};

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
        let token = token(&mt_key.asset);
        match &mt_key.suffix {
            KeyType::Balance { owner } => balance_key(&token, owner),
            KeyType::Supply => minted_balance_key(&token),
        }
    }
}

/// Returns true if the given key has an ERC20 token
pub fn has_erc20_segment(key: &storage::Key) -> bool {
    matches!(
        key.segments.get(1),
        Some(DbKeySeg::AddressSeg(Address::Internal(
            InternalAddress::Erc20(_addr),
        )))
    )
}

impl TryFrom<(&Address, &storage::Key)> for Key {
    type Error = eyre::Error;

    fn try_from(
        (nam_addr, key): (&Address, &storage::Key),
    ) -> Result<Self, Self::Error> {
        if !super::is_eth_bridge_key(nam_addr, key) {
            return Err(eyre!("key does not belong to the EthBridge"));
        }
        if !has_erc20_segment(key) {
            return Err(eyre!("key does not have ERC20 segment"));
        }

        let asset = if let Some(DbKeySeg::AddressSeg(Address::Internal(
            InternalAddress::Erc20(addr),
        ))) = key.segments.get(1)
        {
            *addr
        } else {
            return Err(eyre!(
                "key has an incorrect segment at index #2, expected an \
                 Ethereum address"
            ));
        };

        match key.segments.get(3) {
            Some(DbKeySeg::AddressSeg(owner)) => {
                let balance_key = Key {
                    asset,
                    suffix: KeyType::Balance {
                        owner: owner.clone(),
                    },
                };
                Ok(balance_key)
            }
            Some(DbKeySeg::StringSeg(segment))
                if segment == MINTED_STORAGE_KEY =>
            {
                let supply_key = Key {
                    asset,
                    suffix: KeyType::Supply,
                };
                Ok(supply_key)
            }
            _ => Err(eyre!(
                "key has an incorrect segment at index #3, expected a string \
                 segment"
            )),
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use assert_matches::assert_matches;
    use namada_core::address::testing::nam;
    use namada_core::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;

    use super::*;
    use crate::token::storage_key::BALANCE_STORAGE_KEY;
    use crate::ADDRESS;

    const MULTITOKEN_ADDRESS: Address =
        Address::Internal(InternalAddress::Multitoken);
    const ARBITRARY_OWNER_ADDRESS: &str =
        "tnam1qqwuj7aart6ackjfkk7486jwm2ufr4t7cq4535u4";

    fn dai_erc20_token() -> Address {
        Address::Internal(InternalAddress::Erc20(DAI_ERC20_ETH_ADDRESS))
    }

    #[test]
    fn test_keys_balance() {
        let token = token(&DAI_ERC20_ETH_ADDRESS);
        let key = balance_key(
            &token,
            &Address::from_str(ARBITRARY_OWNER_ADDRESS).unwrap(),
        );
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::AddressSeg(token_addr),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::AddressSeg(owner_addr),
            ] if multitoken_addr == &MULTITOKEN_ADDRESS &&
            token_addr == &dai_erc20_token() &&
            balance_key_seg == BALANCE_STORAGE_KEY &&
            owner_addr == &Address::decode(ARBITRARY_OWNER_ADDRESS).unwrap()
        )
    }

    #[test]
    fn test_keys_balance_to_string() {
        let token = token(&DAI_ERC20_ETH_ADDRESS);
        let key = balance_key(
            &token,
            &Address::from_str(ARBITRARY_OWNER_ADDRESS).unwrap(),
        );
        assert_eq!(
            "#tnam1pyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqej6juv/#\
             tnam1pd43w4r5azgff3zd4x9e2nhdatzf2fcapusvp8s9/balance/#\
             tnam1qqwuj7aart6ackjfkk7486jwm2ufr4t7cq4535u4",
            key.to_string()
        )
    }

    #[test]
    fn test_keys_supply() {
        let token = token(&DAI_ERC20_ETH_ADDRESS);
        let key = minted_balance_key(&token);
        assert_matches!(
            &key.segments[..],
            [
                DbKeySeg::AddressSeg(multitoken_addr),
                DbKeySeg::AddressSeg(token_addr),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::StringSeg(supply_key_seg),
            ] if multitoken_addr == &MULTITOKEN_ADDRESS &&
            token_addr == &dai_erc20_token() &&
            balance_key_seg == BALANCE_STORAGE_KEY &&
            supply_key_seg == MINTED_STORAGE_KEY
        )
    }

    #[test]
    fn test_keys_supply_to_string() {
        let token = token(&DAI_ERC20_ETH_ADDRESS);
        let key = minted_balance_key(&token);
        assert_eq!(
            "#tnam1pyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqej6juv/#\
             tnam1pd43w4r5azgff3zd4x9e2nhdatzf2fcapusvp8s9/balance/minted",
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
                DbKeySeg::AddressSeg(token_addr),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::StringSeg(supply_key_seg),
            ] if multitoken_addr == &MULTITOKEN_ADDRESS &&
            token_addr == &dai_erc20_token() &&
            balance_key_seg == BALANCE_STORAGE_KEY &&
            supply_key_seg == MINTED_STORAGE_KEY
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
                DbKeySeg::AddressSeg(token_addr),
                DbKeySeg::StringSeg(balance_key_seg),
                DbKeySeg::AddressSeg(owner_addr),
            ] if multitoken_addr == &MULTITOKEN_ADDRESS &&
            token_addr == &dai_erc20_token() &&
            balance_key_seg == BALANCE_STORAGE_KEY &&
            owner_addr == &Address::decode(ARBITRARY_OWNER_ADDRESS).unwrap()
        );
    }

    #[test]
    fn test_try_from_key_for_multitoken_key_supply() {
        // supply key
        let key = storage::Key::from_str(&format!(
            "#{}/#{}/balance/{}",
            MULTITOKEN_ADDRESS,
            dai_erc20_token(),
            MINTED_STORAGE_KEY,
        ))
        .expect("Should be able to construct key for test");

        let result: Result<Key, _> = Key::try_from((&nam(), &key));

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
            "#{}/#{}/balance/#{}",
            ADDRESS,
            dai_erc20_token(),
            ARBITRARY_OWNER_ADDRESS
        ))
        .expect("Should be able to construct key for test");

        let result: Result<Key, _> = Key::try_from((&nam(), &key));

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
            "#{}/#{}/balance/#{}",
            ADDRESS,
            dai_erc20_token(),
            ARBITRARY_OWNER_ADDRESS
        ))
        .expect("Should be able to construct key for test");

        assert!(has_erc20_segment(&key));

        let key = storage::Key::from_str(&format!(
            "#{}/#{}/balance/{}",
            ADDRESS,
            dai_erc20_token(),
            MINTED_STORAGE_KEY,
        ))
        .expect("Should be able to construct key for test");

        assert!(has_erc20_segment(&key));

        let key = storage::Key::from_str(&format!(
            "#{}/#{}",
            MULTITOKEN_ADDRESS,
            dai_erc20_token()
        ))
        .expect("Should be able to construct key for test");

        assert!(has_erc20_segment(&key));
    }
}
