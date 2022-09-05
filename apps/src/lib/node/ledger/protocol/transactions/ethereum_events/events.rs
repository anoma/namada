//! Logic for acting on events

use std::collections::BTreeSet;

use eyre::Result;
use namada::ledger::eth_bridge::storage::wrapped_erc20s;
use namada::types::ethereum_events::{EthereumEvent, TransferToNamada};
use namada::types::storage::Key;

use super::update;
use crate::node::ledger::protocol::transactions::store::Store;

/// Updates storage based on the given confirmed `event`. For example, for a
/// confirmed [`EthereumEvent::TransfersToNamada`], mint the corresponding
/// transferred assets to the appropriate receiver addresses.
pub(super) fn act_on(
    store: &mut impl Store,
    event: &EthereumEvent,
) -> Result<BTreeSet<Key>> {
    match &event {
        EthereumEvent::TransfersToNamada { transfers, .. } => {
            act_on_transfers_to_namada(store, transfers)
        }
        _ => {
            tracing::debug!("No actions taken for event");
            Ok(BTreeSet::default())
        }
    }
}

fn act_on_transfers_to_namada(
    store: &mut impl Store,
    transfers: &[TransferToNamada],
) -> Result<BTreeSet<Key>> {
    let mut changed_keys = BTreeSet::default();
    for TransferToNamada {
        amount,
        asset,
        receiver,
    } in transfers
    {
        let keys: wrapped_erc20s::Keys = asset.into();
        let balance_key = keys.balance(receiver);
        update::amount(store, &balance_key, |balance| {
            tracing::debug!(
                %balance_key,
                ?balance,
                "Existing value found",
            );
            balance.receive(amount);
            tracing::debug!(
                %balance_key,
                ?balance,
                "New value calculated",
            );
        })?;
        _ = changed_keys.insert(balance_key);

        let supply_key = keys.supply();
        update::amount(store, &supply_key, |supply| {
            tracing::debug!(
                %supply_key,
                ?supply,
                "Existing value found",
            );
            supply.receive(amount);
            tracing::debug!(
                %supply_key,
                ?supply,
                "New value calculated",
            );
        })?;
        _ = changed_keys.insert(supply_key);
    }
    Ok(changed_keys)
}

#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_eth_address, arbitrary_keccak_hash, arbitrary_nonce,
        DAI_ERC20_ETH_ADDRESS,
    };
    use namada::types::token::Amount;

    use super::*;
    use crate::node::ledger::protocol::transactions::store::testing::FakeStore;

    #[test]
    /// Test that we do not make any changes to storage when acting on most
    /// events
    fn test_act_on_does_nothing_for_other_events() {
        let mut store = FakeStore::default();
        let events = vec![
            EthereumEvent::NewContract {
                name: "bridge".to_string(),
                address: arbitrary_eth_address(),
            },
            EthereumEvent::TransfersToEthereum {
                nonce: arbitrary_nonce(),
                transfers: vec![],
            },
            EthereumEvent::UpdateBridgeWhitelist {
                nonce: arbitrary_nonce(),
                whitelist: vec![],
            },
            EthereumEvent::UpgradedContract {
                name: "bridge".to_string(),
                address: arbitrary_eth_address(),
            },
            EthereumEvent::ValidatorSetUpdate {
                nonce: arbitrary_nonce(),
                bridge_validator_hash: arbitrary_keccak_hash(),
                governance_validator_hash: arbitrary_keccak_hash(),
            },
        ];

        for event in events.iter() {
            act_on(&mut store, event).unwrap();

            assert!(
                store.values.is_empty(),
                "storage changed unexpectedly while acting on event: {:#?}",
                event
            );
        }
    }

    #[test]
    /// Test that storage is indeed changed when we act on a non-empty
    /// TransfersToNamada batch
    fn test_act_on_changes_storage_for_transfers_to_namada() {
        let mut store = FakeStore::default();
        let amount = Amount::from(100);
        let receiver = address::testing::established_address_1();
        let transfers = vec![TransferToNamada {
            amount,
            asset: DAI_ERC20_ETH_ADDRESS,
            receiver,
        }];
        let event = EthereumEvent::TransfersToNamada {
            nonce: arbitrary_nonce(),
            transfers,
        };

        act_on(&mut store, &event).unwrap();

        assert!(!store.values.is_empty());
    }

    #[test]
    /// Test acting on a single transfer and minting the first ever wDAI
    fn test_act_on_transfers_to_namada_mints_wdai() {
        let mut store = FakeStore::default();

        let amount = Amount::from(100);
        let receiver = address::testing::established_address_1();
        let transfers = vec![TransferToNamada {
            amount,
            asset: DAI_ERC20_ETH_ADDRESS,
            receiver: receiver.clone(),
        }];

        act_on_transfers_to_namada(&mut store, &transfers).unwrap();

        let wdai: wrapped_erc20s::Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        let receiver_balance_key = wdai.balance(&receiver);
        let wdai_supply_key = wdai.supply();

        assert_eq!(store.values.len(), 2);
        assert_eq!(
            store.values.get(&receiver_balance_key).unwrap(),
            &amount.try_to_vec().unwrap()
        );
        assert_eq!(
            store.values.get(&wdai_supply_key).unwrap(),
            &amount.try_to_vec().unwrap()
        );
    }
}
