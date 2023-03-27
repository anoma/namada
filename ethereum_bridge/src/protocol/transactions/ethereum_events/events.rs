//! Logic for acting on events

use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;

use borsh::BorshDeserialize;
use eyre::{Result, WrapErr};
use namada_core::hints::likely;
use namada_core::ledger::eth_bridge::storage::bridge_pool::{
    get_nonce_key, get_pending_key, is_pending_transfer_key,
    BRIDGE_POOL_ADDRESS,
};
use namada_core::ledger::eth_bridge::storage::{
    self as bridge_storage, wrapped_erc20s,
};
use namada_core::ledger::eth_bridge::ADDRESS as BRIDGE_ADDRESS;
use namada_core::ledger::parameters::read_epoch_duration_parameter;
use namada_core::ledger::storage::traits::StorageHasher;
use namada_core::ledger::storage::{DBIter, WlStorage, DB};
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::address::{nam, Address};
use namada_core::types::eth_bridge_pool::PendingTransfer;
use namada_core::types::ethereum_events::{
    EthAddress, EthereumEvent, TransferToEthereum, TransferToNamada,
};
use namada_core::types::storage::{BlockHeight, Key, KeySeg};
use namada_core::types::token;
use namada_core::types::token::{
    balance_key, multitoken_balance_key, multitoken_balance_prefix,
};

use crate::parameters::read_native_erc20_address;
use crate::protocol::transactions::update;
use crate::storage::eth_bridge_queries::EthBridgeQueries;

/// Updates storage based on the given confirmed `event`. For example, for a
/// confirmed [`EthereumEvent::TransfersToNamada`], mint the corresponding
/// transferred assets to the appropriate receiver addresses.
pub(super) fn act_on<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    event: &EthereumEvent,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    match &event {
        EthereumEvent::TransfersToNamada { transfers, .. } => {
            act_on_transfers_to_namada(wl_storage, transfers)
        }
        EthereumEvent::TransfersToEthereum {
            transfers, relayer, ..
        } => act_on_transfers_to_eth(wl_storage, transfers, relayer),
        _ => {
            tracing::debug!(?event, "No actions taken for Ethereum event");
            Ok(BTreeSet::default())
        }
    }
}

fn act_on_transfers_to_namada<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    transfers: &[TransferToNamada],
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let wrapped_native_erc20 = read_native_erc20_address(wl_storage)?;
    let mut changed_keys = BTreeSet::default();
    for TransferToNamada {
        amount,
        asset,
        receiver,
    } in transfers
    {
        let mut changed = if asset != &wrapped_native_erc20 {
            let changed =
                mint_wrapped_erc20s(wl_storage, asset, receiver, amount)?;
            tracing::info!(
                "Minted wrapped ERC20s - (receiver - {receiver}, amount - \
                 {amount})",
            );
            changed
        } else {
            redeem_native_token(wl_storage, receiver, amount)?
        };
        changed_keys.append(&mut changed)
    }
    Ok(changed_keys)
}

/// Redeems `amount` of the native token for `receiver` from escrow.
fn redeem_native_token<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    receiver: &Address,
    amount: &token::Amount,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let eth_bridge_native_token_balance_key =
        token::balance_key(&wl_storage.storage.native_token, &BRIDGE_ADDRESS);
    let receiver_native_token_balance_key =
        token::balance_key(&wl_storage.storage.native_token, receiver);

    let eth_bridge_native_token_balance_pre: token::Amount =
        StorageRead::read(wl_storage, &eth_bridge_native_token_balance_key)?
            .expect(
                "Ethereum bridge must always have an explicit balance of the \
                 native token",
            );
    let receiver_native_token_balance_pre: token::Amount =
        StorageRead::read(wl_storage, &receiver_native_token_balance_key)?
            .unwrap_or_default();

    let eth_bridge_native_token_balance_post =
        eth_bridge_native_token_balance_pre
            .checked_sub(*amount)
            .expect(
                "Ethereum bridge should always have enough native tokens to \
                 redeem any confirmed transfers",
            );
    let receiver_native_token_balance_post = receiver_native_token_balance_pre
        .checked_add(*amount)
        .expect("Receiver's balance is full");

    StorageWrite::write(
        wl_storage,
        &eth_bridge_native_token_balance_key,
        eth_bridge_native_token_balance_post,
    )?;
    StorageWrite::write(
        wl_storage,
        &receiver_native_token_balance_key,
        receiver_native_token_balance_post,
    )?;

    tracing::info!(
        %amount,
        %receiver,
        %eth_bridge_native_token_balance_pre,
        %eth_bridge_native_token_balance_post,
        %receiver_native_token_balance_pre,
        %receiver_native_token_balance_post,
        "Redeemed native token for wrapped ERC20 token"
    );
    Ok(BTreeSet::from([
        eth_bridge_native_token_balance_key,
        receiver_native_token_balance_key,
    ]))
}

/// Mints `amount` of a wrapped ERC20 `asset` for `receiver`.
fn mint_wrapped_erc20s<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    asset: &EthAddress,
    receiver: &Address,
    amount: &token::Amount,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();
    let keys: wrapped_erc20s::Keys = asset.into();
    let balance_key = keys.balance(receiver);
    update::amount(wl_storage, &balance_key, |balance| {
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
    update::amount(wl_storage, &supply_key, |supply| {
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

fn act_on_transfers_to_eth<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    transfers: &[TransferToEthereum],
    relayer: &Address,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();
    // all keys of pending transfers
    let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
    let mut pending_keys: HashSet<Key> = wl_storage
        .iter_prefix(&prefix)
        .context("Failed to iterate over storage")?
        .map(|(k, _, _)| {
            Key::from_str(k.as_str()).expect("Key should be parsable")
        })
        .filter(is_pending_transfer_key)
        .collect();
    let pool_balance_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
    let relayer_rewards_key = balance_key(&nam(), relayer);
    // Remove the completed transfers from the bridge pool
    for event in transfers {
        let pending_transfer = event.into();
        let key = get_pending_key(&pending_transfer);
        if likely(wl_storage.has_key(&key)?) {
            // give the relayer the gas fee for this transfer.
            update::amount(wl_storage, &relayer_rewards_key, |balance| {
                balance.receive(&pending_transfer.gas_fee.amount);
            })?;
            // the gas fee is removed from escrow.
            update::amount(wl_storage, &pool_balance_key, |balance| {
                balance.spend(&pending_transfer.gas_fee.amount);
            })?;
            wl_storage.delete(&key)?;
            _ = pending_keys.remove(&key);
        } else {
            unreachable!("The transfer should exist in the bridge pool");
        }
        _ = changed_keys.insert(key);
    }
    if !transfers.is_empty() {
        let nonce_key = get_nonce_key();
        increment_bp_nonce(&nonce_key, wl_storage)?;
        changed_keys.insert(nonce_key);
        changed_keys.insert(relayer_rewards_key);
        changed_keys.insert(pool_balance_key);
    }

    if pending_keys.is_empty() {
        return Ok(changed_keys);
    }

    // TODO the timeout height is min_num_blocks of an epoch for now
    let (epoch_duration, _) =
        read_epoch_duration_parameter(&wl_storage.storage)?;
    let timeout_offset = epoch_duration.min_num_of_blocks;

    // Check time out and refund
    if wl_storage.storage.block.height.0 > timeout_offset {
        let timeout_height =
            BlockHeight(wl_storage.storage.block.height.0 - timeout_offset);
        for key in pending_keys {
            let inserted_height = BlockHeight::try_from_slice(
                &wl_storage.storage.block.tree.get(&key)?,
            )
            .expect("BlockHeight should be decoded");
            if inserted_height <= timeout_height {
                let mut keys = refund_transfer(wl_storage, key)?;
                changed_keys.append(&mut keys);
            }
        }
    }

    Ok(changed_keys)
}

fn increment_bp_nonce<D, H>(
    nonce_key: &Key,
    wl_storage: &mut WlStorage<D, H>,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let next_nonce = wl_storage
        .ethbridge_queries()
        .get_bridge_pool_nonce()
        .checked_increment()
        .expect("Bridge pool nonce has overflowed");
    wl_storage.write(nonce_key, next_nonce)?;
    Ok(())
}

fn refund_transfer<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    key: Key,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_key = BTreeSet::default();

    let transfer = match wl_storage.read_bytes(&key)? {
        Some(v) => PendingTransfer::try_from_slice(&v[..])?,
        None => unreachable!(),
    };

    let payer_balance_key = balance_key(&nam(), &transfer.gas_fee.payer);
    let pool_balance_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
    update::amount(wl_storage, &payer_balance_key, |balance| {
        balance.receive(&transfer.gas_fee.amount);
    })?;
    update::amount(wl_storage, &pool_balance_key, |balance| {
        balance.spend(&transfer.gas_fee.amount);
    })?;
    _ = changed_key.insert(payer_balance_key);
    _ = changed_key.insert(pool_balance_key);

    // Unescrow the token
    let native_erc20_addr = match wl_storage
        .read_bytes(&bridge_storage::native_erc20_key())?
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
    update::amount(wl_storage, &source, |balance| {
        balance.spend(&transfer.transfer.amount);
    })?;
    update::amount(wl_storage, &target, |balance| {
        balance.receive(&transfer.transfer.amount);
    })?;
    _ = changed_key.insert(source);
    _ = changed_key.insert(target);

    // Delete the key from the bridge pool
    wl_storage.delete(&key)?;
    _ = changed_key.insert(key);

    Ok(changed_key)
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use borsh::BorshSerialize;
    use eyre::Result;
    use namada_core::ledger::parameters::{
        update_epoch_parameter, EpochDuration,
    };
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::ledger::storage::types::encode;
    use namada_core::types::address::gen_established_address;
    use namada_core::types::address::testing::gen_implicit_address;
    use namada_core::types::eth_bridge_pool::GasFee;
    use namada_core::types::ethereum_events::testing::{
        arbitrary_eth_address, arbitrary_keccak_hash, arbitrary_nonce,
        DAI_ERC20_ETH_ADDRESS,
    };
    use namada_core::types::time::DurationSecs;
    use namada_core::types::token::Amount;
    use namada_core::types::{address, eth_bridge_pool};

    use super::*;
    use crate::test_utils::{self, stored_keys_count};

    fn init_storage(wl_storage: &mut TestWlStorage) {
        // set the timeout height offset
        let timeout_offset = 10;
        let epoch_duration = EpochDuration {
            min_num_of_blocks: timeout_offset,
            min_duration: DurationSecs(5),
        };
        update_epoch_parameter(&mut wl_storage.storage, &epoch_duration)
            .expect("Test failed");
        // set native ERC20 token
        let native_erc20_key = bridge_storage::native_erc20_key();
        let native_erc20 = EthAddress([0; 20]);
        wl_storage
            .write_bytes(&native_erc20_key, encode(&native_erc20))
            .expect("Test failed");
    }

    fn init_bridge_pool(
        wl_storage: &mut TestWlStorage,
    ) -> Vec<PendingTransfer> {
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
            wl_storage
                .storage
                .write(&key, transfer.try_to_vec().expect("Test failed"))
                .expect("Test failed");

            pending_transfers.push(transfer);
        }
        pending_transfers
    }

    fn init_balance(
        wl_storage: &mut TestWlStorage,
        pending_transfers: &Vec<PendingTransfer>,
    ) {
        // Gas payer
        let payer = address::testing::established_address_2();
        let payer_key = balance_key(&nam(), &payer);
        let payer_balance = Amount::from(0);
        wl_storage
            .write_bytes(
                &payer_key,
                payer_balance.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        for transfer in pending_transfers {
            if transfer.transfer.asset == EthAddress([0; 20]) {
                // native ERC20
                let sender_key = balance_key(&nam(), &transfer.transfer.sender);
                let sender_balance = Amount::from(0);
                wl_storage
                    .write_bytes(
                        &sender_key,
                        sender_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
                let escrow_key = balance_key(&nam(), &BRIDGE_ADDRESS);
                let escrow_balance = Amount::from(10);
                wl_storage
                    .write_bytes(
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
                wl_storage
                    .write_bytes(
                        &sender_key,
                        sender_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
                let escrow_key =
                    multitoken_balance_key(&prefix, &BRIDGE_POOL_ADDRESS);
                let escrow_balance = Amount::from(10);
                wl_storage
                    .write_bytes(
                        &escrow_key,
                        escrow_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
            };
            let gas_fee = Amount::from(1);
            let escrow_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
            update::amount(wl_storage, &escrow_key, |balance| {
                balance.receive(&gas_fee);
            })
            .expect("Test failed");
        }
    }

    #[test]
    /// Test that we do not make any changes to wl_storage when acting on most
    /// events
    fn test_act_on_does_nothing_for_other_events() {
        let mut wl_storage = TestWlStorage::default();
        test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
        let initial_stored_keys_count = stored_keys_count(&wl_storage);
        let events = vec![
            EthereumEvent::NewContract {
                name: "bridge".to_string(),
                address: arbitrary_eth_address(),
            },
            EthereumEvent::TransfersToEthereum {
                nonce: arbitrary_nonce(),
                transfers: vec![],
                relayer: gen_implicit_address(),
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
            act_on(&mut wl_storage, event).unwrap();
            assert_eq!(
                stored_keys_count(&wl_storage),
                initial_stored_keys_count,
                "storage changed unexpectedly while acting on event: {:#?}",
                event
            );
        }
    }

    #[test]
    /// Test that wl_storage is indeed changed when we act on a non-empty
    /// TransfersToNamada batch
    fn test_act_on_changes_storage_for_transfers_to_namada() {
        let mut wl_storage = TestWlStorage::default();
        test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
        wl_storage.commit_block().expect("Test failed");
        let initial_stored_keys_count = stored_keys_count(&wl_storage);
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

        act_on(&mut wl_storage, &event).unwrap();

        assert_eq!(
            stored_keys_count(&wl_storage),
            initial_stored_keys_count + 2
        );
    }

    #[test]
    /// Test acting on a single transfer and minting the first ever wDAI
    fn test_act_on_transfers_to_namada_mints_wdai() {
        let mut wl_storage = TestWlStorage::default();
        test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
        let initial_stored_keys_count = stored_keys_count(&wl_storage);

        let amount = Amount::from(100);
        let receiver = address::testing::established_address_1();
        let transfers = vec![TransferToNamada {
            amount,
            asset: DAI_ERC20_ETH_ADDRESS,
            receiver: receiver.clone(),
        }];

        act_on_transfers_to_namada(&mut wl_storage, &transfers).unwrap();

        let wdai: wrapped_erc20s::Keys = (&DAI_ERC20_ETH_ADDRESS).into();
        let receiver_balance_key = wdai.balance(&receiver);
        let wdai_supply_key = wdai.supply();

        assert_eq!(
            stored_keys_count(&wl_storage),
            initial_stored_keys_count + 2
        );

        let expected_amount = amount.try_to_vec().unwrap();
        for key in vec![receiver_balance_key, wdai_supply_key] {
            let value = wl_storage.read_bytes(&key).unwrap();
            assert_matches!(value, Some(bytes) if bytes == expected_amount);
        }
    }

    #[test]
    /// Test that the transfers are deleted in the bridge pool when we act on a
    /// TransfersToEthereum
    fn test_act_on_changes_storage_for_transfers_to_eth() {
        let mut wl_storage = TestWlStorage::default();
        init_storage(&mut wl_storage);
        let pending_transfers = init_bridge_pool(&mut wl_storage);
        init_balance(&mut wl_storage, &pending_transfers);
        let pending_keys: HashSet<Key> =
            pending_transfers.iter().map(get_pending_key).collect();
        let relayer = gen_established_address("random");
        let mut transfers = vec![];
        for transfer in pending_transfers {
            let transfer_to_eth = TransferToEthereum {
                amount: transfer.transfer.amount,
                asset: transfer.transfer.asset,
                receiver: transfer.transfer.recipient,
                gas_amount: transfer.gas_fee.amount,
                gas_payer: transfer.gas_fee.payer,
                sender: transfer.transfer.sender,
            };
            transfers.push(transfer_to_eth);
        }
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers,
            relayer: relayer.clone(),
        };
        let payer_balance_key = balance_key(&nam(), &relayer);
        let pool_balance_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let mut bp_balance_pre = Amount::try_from_slice(
            &wl_storage
                .read_bytes(&pool_balance_key)
                .expect("Test failed")
                .expect("Test failed"),
        )
        .expect("Test failed");
        let mut changed_keys = act_on(&mut wl_storage, &event).unwrap();

        assert!(changed_keys.remove(&payer_balance_key));
        assert!(changed_keys.remove(&pool_balance_key));
        assert!(changed_keys.iter().all(|k| pending_keys.contains(k)));

        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(
            wl_storage
                .iter_prefix(&prefix)
                .expect("Test failed")
                .count(),
            0
        );
        let relayer_balance = Amount::try_from_slice(
            &wl_storage
                .read_bytes(&payer_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");
        assert_eq!(relayer_balance, Amount::from(2));
        let bp_balance_post = Amount::try_from_slice(
            &wl_storage
                .read_bytes(&pool_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");
        bp_balance_pre.spend(&bp_balance_post);
        assert_eq!(bp_balance_pre, Amount::from(2));
    }

    #[test]
    /// Test that the transfers time out in the bridge pool then the refund when
    /// we act on a TransfersToEthereum
    fn test_act_on_timeout_for_transfers_to_eth() {
        let mut wl_storage = TestWlStorage::default();
        init_storage(&mut wl_storage);
        // Height 0
        let pending_transfers = init_bridge_pool(&mut wl_storage);
        init_balance(&mut wl_storage, &pending_transfers);
        wl_storage.storage.commit_block().expect("Test failed");
        // pending transfers time out
        wl_storage.storage.block.height += 10 + 1;
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
        wl_storage
            .storage
            .write(&key, transfer.try_to_vec().expect("Test failed"))
            .expect("Test failed");
        wl_storage.storage.commit_block().expect("Test failed");
        wl_storage.storage.block.height += 1;

        // This should only refund
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers: vec![],
            relayer: gen_implicit_address(),
        };
        let _ = act_on(&mut wl_storage, &event).unwrap();

        // The latest transfer is still pending
        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(
            wl_storage
                .iter_prefix(&prefix)
                .expect("Test failed")
                .count(),
            1
        );

        // Check the gas fee
        let expected = pending_transfers
            .iter()
            .fold(Amount::from(0), |acc, t| acc + t.gas_fee.amount);
        let payer = address::testing::established_address_2();
        let payer_key = balance_key(&nam(), &payer);
        let value = wl_storage.read_bytes(&payer_key).expect("Test failed");
        let payer_balance =
            Amount::try_from_slice(&value.expect("Test failed"))
                .expect("Test failed");
        assert_eq!(payer_balance, expected);
        let pool_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let value = wl_storage.read_bytes(&pool_key).expect("Test failed");
        let pool_balance = Amount::try_from_slice(&value.expect("Test failed"))
            .expect("Test failed");
        assert_eq!(pool_balance, Amount::from(0));

        // Check the balances
        for transfer in pending_transfers {
            if transfer.transfer.asset == EthAddress([0; 20]) {
                let sender_key = balance_key(&nam(), &transfer.transfer.sender);
                let value =
                    wl_storage.read_bytes(&sender_key).expect("Test failed");
                let sender_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(sender_balance, transfer.transfer.amount);
                let escrow_key = balance_key(&nam(), &BRIDGE_ADDRESS);
                let value =
                    wl_storage.read_bytes(&escrow_key).expect("Test failed");
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
                let value =
                    wl_storage.read_bytes(&sender_key).expect("Test failed");
                let sender_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(sender_balance, transfer.transfer.amount);
                let escrow_key =
                    multitoken_balance_key(&prefix, &BRIDGE_POOL_ADDRESS);
                let value =
                    wl_storage.read_bytes(&escrow_key).expect("Test failed");
                let escrow_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(escrow_balance, Amount::from(0));
            }
        }
    }

    #[test]
    fn test_redeem_native_token() -> Result<()> {
        let mut wl_storage = TestWlStorage::default();
        test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
        let receiver = address::testing::established_address_1();
        let amount = Amount::from(100);

        let bridge_pool_initial_balance = Amount::from(100_000_000);
        let bridge_pool_native_token_balance_key = token::balance_key(
            &wl_storage.storage.native_token,
            &BRIDGE_ADDRESS,
        );
        StorageWrite::write(
            &mut wl_storage,
            &bridge_pool_native_token_balance_key,
            bridge_pool_initial_balance,
        )?;
        let receiver_native_token_balance_key =
            token::balance_key(&wl_storage.storage.native_token, &receiver);

        let changed_keys =
            redeem_native_token(&mut wl_storage, &receiver, &amount)?;

        assert_eq!(
            changed_keys,
            BTreeSet::from([
                bridge_pool_native_token_balance_key.clone(),
                receiver_native_token_balance_key.clone()
            ])
        );
        assert_eq!(
            StorageRead::read(
                &wl_storage,
                &bridge_pool_native_token_balance_key
            )?,
            Some(bridge_pool_initial_balance - amount)
        );
        assert_eq!(
            StorageRead::read(&wl_storage, &receiver_native_token_balance_key)?,
            Some(amount)
        );

        Ok(())
    }
}
