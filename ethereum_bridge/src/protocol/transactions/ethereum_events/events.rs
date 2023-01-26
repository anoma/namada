//! Logic for acting on events

use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;

use borsh::BorshDeserialize;
use eyre::Result;
use namada_core::hints::likely;
use namada_core::ledger::eth_bridge::storage::bridge_pool::{
    get_pending_key, is_pending_transfer_key, BRIDGE_POOL_ADDRESS,
};
use namada_core::ledger::eth_bridge::storage::{
    self as bridge_storage, wrapped_erc20s,
};
use namada_core::ledger::eth_bridge::ADDRESS as BRIDGE_ADDRESS;
use namada_core::ledger::parameters::read_epoch_duration_parameter;
use namada_core::ledger::storage::traits::StorageHasher;
use namada_core::ledger::storage::{DBIter, Storage, DB};
use namada_core::types::address::nam;
use namada_core::types::eth_bridge_pool::PendingTransfer;
use namada_core::types::ethereum_events::{
    EthAddress, EthereumEvent, TransferToEthereum, TransferToNamada,
};
use namada_core::types::storage::{BlockHeight, Key, KeySeg};
use namada_core::types::token::{
    balance_key, multitoken_balance_key, multitoken_balance_prefix,
};

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
        EthereumEvent::TransfersToEthereum { transfers, .. } => {
            act_on_transfers_to_eth(storage, transfers)
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
    for TransferToNamada {
        amount,
        asset,
        receiver,
    } in transfers
    {
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
    }
    Ok(changed_keys)
}

fn act_on_transfers_to_eth<D, H>(
    storage: &mut Storage<D, H>,
    transfers: &[TransferToEthereum],
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();
    // all keys of pending transfers
    let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
    let mut pending_keys: HashSet<Key> = storage
        .iter_prefix(&prefix)
        .0
        .map(|(k, _, _)| {
            Key::from_str(k.as_str()).expect("Key should be parsable")
        })
        .filter(is_pending_transfer_key)
        .collect();

    // Remove the completed transfers from the bridge pool
    for event in transfers {
        let pending_transfer = event.into();
        let key = get_pending_key(&pending_transfer);
        if likely(storage.has_key(&key)?.0) {
            _ = storage.delete(&key)?;
            _ = pending_keys.remove(&key);
        } else {
            unreachable!("The transfer should exist in the bridge pool");
        }

        _ = changed_keys.insert(key);
    }

    if pending_keys.is_empty() {
        return Ok(changed_keys);
    }

    // TODO the timeout height is min_num_blocks of an epoch for now
    let (epoch_duration, _) = read_epoch_duration_parameter(storage)?;
    let timeout_offset = epoch_duration.min_num_of_blocks;

    // Check time out and refund
    if storage.block.height.0 > timeout_offset {
        let timeout_height =
            BlockHeight(storage.block.height.0 - timeout_offset);
        for key in pending_keys {
            let inserted_height =
                BlockHeight::try_from_slice(&storage.block.tree.get(&key)?)
                    .expect("BlockHeight should be decoded");
            if inserted_height <= timeout_height {
                let mut keys = refund_transfer(storage, key)?;
                changed_keys.append(&mut keys);
            }
        }
    }

    Ok(changed_keys)
}

fn refund_transfer<D, H>(
    storage: &mut Storage<D, H>,
    key: Key,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_key = BTreeSet::default();

    let transfer = match storage.read(&key)?.0 {
        Some(v) => PendingTransfer::try_from_slice(&v[..])?,
        None => unreachable!(),
    };

    // Refund the gas fee
    let payer_balance_key = balance_key(&nam(), &transfer.gas_fee.payer);
    let pool_balance_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
    update::amount(storage, &payer_balance_key, |balance| {
        balance.receive(&transfer.gas_fee.amount);
    })?;
    update::amount(storage, &pool_balance_key, |balance| {
        balance.spend(&transfer.gas_fee.amount);
    })?;
    _ = changed_key.insert(payer_balance_key);
    _ = changed_key.insert(pool_balance_key);

    // Unescrow the token
    let native_erc20_addr = match storage
        .read(&bridge_storage::native_erc20_key())?
        .0
    {
        Some(v) => EthAddress::try_from_slice(&v[..])?,
        None => {
            return Err(eyre::eyre!("Could not read wNam key from storage"));
        }
    };
    let (source, target) = if transfer.transfer.asset == native_erc20_addr {
        let escrow_balance_key = balance_key(&nam(), &BRIDGE_ADDRESS);
        let sender_balance_key = balance_key(&nam(), &transfer.transfer.sender);
        (escrow_balance_key, sender_balance_key)
    } else {
        let sub_prefix = wrapped_erc20s::sub_prefix(&transfer.transfer.asset);
        let prefix = multitoken_balance_prefix(&BRIDGE_ADDRESS, &sub_prefix);
        let escrow_balance_key =
            multitoken_balance_key(&prefix, &BRIDGE_POOL_ADDRESS);
        let sender_balance_key =
            multitoken_balance_key(&prefix, &transfer.transfer.sender);
        (escrow_balance_key, sender_balance_key)
    };
    update::amount(storage, &source, |balance| {
        balance.spend(&transfer.transfer.amount);
    })?;
    update::amount(storage, &target, |balance| {
        balance.receive(&transfer.transfer.amount);
    })?;
    _ = changed_key.insert(source);
    _ = changed_key.insert(target);

    // Delete the key from the bridge pool
    _ = storage.delete(&key)?;
    _ = changed_key.insert(key);

    Ok(changed_key)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use assert_matches::assert_matches;
    use borsh::BorshSerialize;
    use namada_core::ledger::parameters::{
        update_epoch_parameter, EpochDuration,
    };
    use namada_core::ledger::storage::testing::TestStorage;
    use namada_core::ledger::storage::types::encode;
    use namada_core::types::eth_bridge_pool::GasFee;
    use namada_core::types::ethereum_events::testing::{
        arbitrary_eth_address, arbitrary_keccak_hash, arbitrary_nonce,
        DAI_ERC20_ETH_ADDRESS,
    };
    use namada_core::types::time::DurationSecs;
    use namada_core::types::token::Amount;
    use namada_core::types::{address, eth_bridge_pool};

    use super::*;

    fn init_storage(storage: &mut TestStorage) {
        // set the timeout height offset
        let timeout_offset = 10;
        let epoch_duration = EpochDuration {
            min_num_of_blocks: timeout_offset,
            min_duration: DurationSecs(5),
        };
        update_epoch_parameter(storage, &epoch_duration).expect("Test failed");
        // set native ERC20 token
        let native_erc20_key = bridge_storage::native_erc20_key();
        let native_erc20 = EthAddress([0; 20]);
        storage
            .write(&native_erc20_key, encode(&native_erc20))
            .expect("Test failed");
    }

    fn init_bridge_pool(storage: &mut TestStorage) -> Vec<PendingTransfer> {
        let sender = address::testing::established_address_1();
        let payer = address::testing::established_address_2();

        // set pending transfers
        let mut pending_transfers = vec![];
        for i in 0..2 {
            let transfer = PendingTransfer {
                transfer: eth_bridge_pool::TransferToEthereum {
                    asset: EthAddress([i; 20]),
                    sender: sender.clone(),
                    recipient: EthAddress([i + 1; 20]),
                    amount: Amount::from(10),
                },
                gas_fee: GasFee {
                    amount: Amount::from(1),
                    payer: payer.clone(),
                },
            };
            let key = get_pending_key(&transfer);
            _ = storage
                .write(&key, transfer.try_to_vec().expect("Test failed"))
                .expect("Test failed");

            pending_transfers.push(transfer);
        }
        pending_transfers
    }

    fn init_balance(
        storage: &mut TestStorage,
        pending_transfers: &Vec<PendingTransfer>,
    ) {
        // Gas payer
        let payer = address::testing::established_address_2();
        let payer_key = balance_key(&nam(), &payer);
        let payer_balance = Amount::from(0);
        _ = storage
            .write(&payer_key, payer_balance.try_to_vec().expect("Test failed"))
            .expect("Test failed");
        let pool_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let pool_balance = Amount::from(2);
        _ = storage
            .write(&pool_key, pool_balance.try_to_vec().expect("Test failed"))
            .expect("Test failed");

        for transfer in pending_transfers {
            if transfer.transfer.asset == EthAddress([0; 20]) {
                // native ERC20
                let sender_key = balance_key(&nam(), &transfer.transfer.sender);
                let sender_balance = Amount::from(0);
                _ = storage
                    .write(
                        &sender_key,
                        sender_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
                let escrow_key = balance_key(&nam(), &BRIDGE_ADDRESS);
                let escrow_balance = Amount::from(10);
                _ = storage
                    .write(
                        &escrow_key,
                        escrow_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
            } else {
                let sub_prefix =
                    wrapped_erc20s::sub_prefix(&transfer.transfer.asset);
                let prefix =
                    multitoken_balance_prefix(&BRIDGE_ADDRESS, &sub_prefix);
                let sender_key =
                    multitoken_balance_key(&prefix, &transfer.transfer.sender);
                let sender_balance = Amount::from(0);
                _ = storage
                    .write(
                        &sender_key,
                        sender_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
                let escrow_key =
                    multitoken_balance_key(&prefix, &BRIDGE_POOL_ADDRESS);
                let escrow_balance = Amount::from(10);
                _ = storage
                    .write(
                        &escrow_key,
                        escrow_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
            };
        }
    }

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

    #[test]
    /// Test that the transfers are deleted in the bridge pool when we act on a
    /// TransfersToEthereum
    fn test_act_on_changes_storage_for_transfers_to_eth() {
        let mut storage = TestStorage::default();
        init_storage(&mut storage);
        let pending_transfers = init_bridge_pool(&mut storage);
        let pending_keys: HashSet<Key> =
            pending_transfers.iter().map(get_pending_key).collect();

        let mut transfers = vec![];
        for transfer in pending_transfers {
            let transfer_to_eth = TransferToEthereum {
                amount: transfer.transfer.amount,
                asset: transfer.transfer.asset,
                receiver: transfer.transfer.recipient,
                gas_amount: transfer.gas_fee.amount,
                gas_payer: transfer.gas_fee.payer,
            };
            transfers.push(transfer_to_eth);
        }
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers,
        };

        let changed_keys = act_on(&mut storage, &event).unwrap();

        assert!(changed_keys.iter().all(|k| pending_keys.contains(k)));
        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(storage.iter_prefix(&prefix).0.count(), 0);
    }

    #[test]
    /// Test that the transfers time out in the bridge pool then the refund when
    /// we act on a TransfersToEthereum
    fn test_act_on_timeout_for_transfers_to_eth() {
        let mut storage = TestStorage::default();
        init_storage(&mut storage);
        // Height 0
        let pending_transfers = init_bridge_pool(&mut storage);
        init_balance(&mut storage, &pending_transfers);
        storage.commit().expect("Test failed");
        // pending transfers time out
        storage.block.height = storage.block.height + 10 + 1;
        // new pending transfer
        let transfer = PendingTransfer {
            transfer: eth_bridge_pool::TransferToEthereum {
                asset: EthAddress([4; 20]),
                sender: address::testing::established_address_1(),
                recipient: EthAddress([5; 20]),
                amount: Amount::from(10),
            },
            gas_fee: GasFee {
                amount: Amount::from(1),
                payer: address::testing::established_address_1(),
            },
        };
        let key = get_pending_key(&transfer);
        _ = storage
            .write(&key, transfer.try_to_vec().expect("Test failed"))
            .expect("Test failed");
        storage.commit().expect("Test failed");
        storage.block.height = storage.block.height + 1;

        // This should only refund
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers: vec![],
        };
        let _ = act_on(&mut storage, &event).unwrap();

        // The latest transfer is still pending
        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(storage.iter_prefix(&prefix).0.count(), 1);

        // Check the gas fee
        let expected = pending_transfers
            .iter()
            .fold(Amount::from(0), |acc, t| acc + t.gas_fee.amount);
        let payer = address::testing::established_address_2();
        let payer_key = balance_key(&nam(), &payer);
        let (value, _) = storage.read(&payer_key).expect("Test failed");
        let payer_balance =
            Amount::try_from_slice(&value.expect("Test failed"))
                .expect("Test failed");
        assert_eq!(payer_balance, expected);
        let pool_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let (value, _) = storage.read(&pool_key).expect("Test failed");
        let pool_balance = Amount::try_from_slice(&value.expect("Test failed"))
            .expect("Test failed");
        assert_eq!(pool_balance, Amount::from(0));

        // Check the balances
        for transfer in pending_transfers {
            if transfer.transfer.asset == EthAddress([0; 20]) {
                let sender_key = balance_key(&nam(), &transfer.transfer.sender);
                let (value, _) =
                    storage.read(&sender_key).expect("Test failed");
                let sender_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(sender_balance, transfer.transfer.amount);
                let escrow_key = balance_key(&nam(), &BRIDGE_ADDRESS);
                let (value, _) =
                    storage.read(&escrow_key).expect("Test failed");
                let escrow_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(escrow_balance, Amount::from(0));
            } else {
                let sub_prefix =
                    wrapped_erc20s::sub_prefix(&transfer.transfer.asset);
                let prefix =
                    multitoken_balance_prefix(&BRIDGE_ADDRESS, &sub_prefix);
                let sender_key =
                    multitoken_balance_key(&prefix, &transfer.transfer.sender);
                let (value, _) =
                    storage.read(&sender_key).expect("Test failed");
                let sender_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(sender_balance, transfer.transfer.amount);
                let escrow_key =
                    multitoken_balance_key(&prefix, &BRIDGE_POOL_ADDRESS);
                let (value, _) =
                    storage.read(&escrow_key).expect("Test failed");
                let escrow_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(escrow_balance, Amount::from(0));
            }
        }
    }
}
