//! Logic for acting on events

use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use eyre::Result;
use namada_core::ledger::eth_bridge::storage::{
    native_erc20_key, wrapped_erc20s,
};
use namada_core::ledger::storage::traits::StorageHasher;
use namada_core::ledger::storage::{DBIter, Storage, DB};
use namada_core::types::ethereum_events::{
    EthAddress, EthereumEvent, TransferToNamada,
};
use namada_core::types::storage::Key;

use crate::protocol::transactions::update;

/// Updates storage based on the given confirmed `event`. For example, for a
/// confirmed [`EthereumEvent::TransfersToNamada`], mint the corresponding
/// transferred assets to the appropriate receiver addresses.
pub(super) fn act_on<D, H>(
    storage: &mut Storage<D, H>,
    event: &EthereumEvent,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    match &event {
        EthereumEvent::TransfersToNamada { transfers, .. } => {
            act_on_transfers_to_namada(storage, transfers)
        }
        _ => {
            tracing::debug!(?event, "No actions taken for Ethereum event");
            Ok(BTreeSet::default())
        }
    }
}

fn act_on_transfers_to_namada<D, H>(
    storage: &mut Storage<D, H>,
    transfers: &[TransferToNamada],
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();
    for transfer in transfers {
        let mut changed = mint_wrapped_erc20s(storage, transfer)?;
        changed_keys.append(&mut changed)
    }
    Ok(changed_keys)
}

/// Mints wrapped ERC20s based on `transfer`.
fn mint_wrapped_erc20s<D, H>(
    storage: &mut Storage<D, H>,
    TransferToNamada {
        ref asset,
        ref receiver,
        ref amount,
    }: &TransferToNamada,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();
    let keys: wrapped_erc20s::Keys = asset.into();
    let balance_key = keys.balance(receiver);
    update::amount(storage, &balance_key, |balance| {
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
    update::amount(storage, &supply_key, |supply| {
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
    Ok(changed_keys)
}

/// This must get the Ethereum address of wrapped native asset from storage. If
/// this isn't possible, the program panics.
/// TODO: adapted from <https://github.com/anoma/namada/blob/fd46922fdbee5445a7f3878174408ca437d7a550/shared/src/ledger/native_vp/ethereum_bridge/bridge_pool_vp.rs#L126>, should consolidate
fn native_erc20_address<D, H>(storage: &Storage<D, H>) -> Result<EthAddress>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // TODO: assuming here that if `.read` errors, it's recoverable?
    match storage.read(&native_erc20_key())? {
        (Some(bytes), _) => Ok(EthAddress::try_from_slice(bytes.as_slice())
            .expect("Cannot deserialize the native ERC20 address in storage!")),
        (None, _) => panic!(
            "Cannot apply an Ethereum event as Ethereum bridge configuration \
             is not initialized!"
        ),
    }
}
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use assert_matches::assert_matches;
    use borsh::BorshSerialize;
    use namada_core::ledger::storage::testing::TestStorage;
    use namada_core::types::address;
    use namada_core::types::ethereum_events::testing::{
        arbitrary_eth_address, arbitrary_keccak_hash, arbitrary_nonce,
        DAI_ERC20_ETH_ADDRESS,
    };
    use namada_core::types::token::Amount;

    use super::*;

    #[test]
    /// Test that we do not make any changes to storage when acting on most
    /// events
    fn test_act_on_does_nothing_for_other_events() {
        let mut storage = TestStorage::default();
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
            act_on(&mut storage, event).unwrap();
            let root = Key::from_str("").unwrap();
            assert_eq!(
                storage.iter_prefix(&root).0.count(),
                0,
                "storage changed unexpectedly while acting on event: {:#?}",
                event
            );
        }
    }

    #[test]
    /// Test that storage is indeed changed when we act on a non-empty
    /// TransfersToNamada batch
    fn test_act_on_changes_storage_for_transfers_to_namada() {
        let mut storage = TestStorage::default();
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

        act_on(&mut storage, &event).unwrap();

        let root = Key::from_str("").unwrap();
        assert_eq!(storage.iter_prefix(&root).0.count(), 2);
    }

    #[test]
    /// Test acting on a single transfer and minting the first ever wDAI
    fn test_act_on_transfers_to_namada_mints_wdai() {
        let mut storage = TestStorage::default();

        let amount = Amount::from(100);
        let receiver = address::testing::established_address_1();
        let transfers = vec![TransferToNamada {
            amount,
            asset: DAI_ERC20_ETH_ADDRESS,
            receiver: receiver.clone(),
        }];

        act_on_transfers_to_namada(&mut storage, &transfers).unwrap();

        let wdai: wrapped_erc20s::Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        let receiver_balance_key = wdai.balance(&receiver);
        let wdai_supply_key = wdai.supply();

        let root = Key::from_str("").unwrap();
        assert_eq!(storage.iter_prefix(&root).0.count(), 2);

        let expected_amount = amount.try_to_vec().unwrap();
        for key in vec![receiver_balance_key, wdai_supply_key] {
            let (value, _) = storage.read(&key).unwrap();
            assert_matches!(value, Some(bytes) if bytes == expected_amount);
        }
    }
}
