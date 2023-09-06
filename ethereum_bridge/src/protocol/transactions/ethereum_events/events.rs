//! Logic for acting on events

use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;

use borsh::BorshDeserialize;
use eyre::{Result, WrapErr};
use namada_core::hints;
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
use namada_core::types::address::Address;
use namada_core::types::eth_bridge_pool::PendingTransfer;
use namada_core::types::ethereum_events::{
    EthAddress, EthereumEvent, TransferToEthereum, TransferToNamada,
    TransfersToNamada,
};
use namada_core::types::storage::{BlockHeight, Key, KeySeg};
use namada_core::types::token;
use namada_core::types::token::{balance_key, minted_balance_key};

use crate::parameters::read_native_erc20_address;
use crate::protocol::transactions::update;
use crate::storage::eth_bridge_queries::{EthAssetMint, EthBridgeQueries};

/// Updates storage based on the given confirmed `event`. For example, for a
/// confirmed [`EthereumEvent::TransfersToNamada`], mint the corresponding
/// transferred assets to the appropriate receiver addresses.
pub(super) fn act_on<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    event: EthereumEvent,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    match event {
        EthereumEvent::TransfersToNamada {
            transfers,
            valid_transfers_map,
            nonce,
        } => act_on_transfers_to_namada(
            wl_storage,
            TransfersToNamada {
                transfers,
                valid_transfers_map,
                nonce,
            },
        ),
        EthereumEvent::TransfersToEthereum {
            ref transfers,
            ref relayer,
            ref valid_transfers_map,
            ..
        } => act_on_transfers_to_eth(
            wl_storage,
            transfers,
            valid_transfers_map,
            relayer,
        ),
        _ => {
            tracing::debug!(?event, "No actions taken for Ethereum event");
            Ok(BTreeSet::default())
        }
    }
}

fn act_on_transfers_to_namada<'tx, D, H>(
    wl_storage: &mut WlStorage<D, H>,
    transfer_event: TransfersToNamada,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    tracing::debug!(?transfer_event, "Acting on transfers to Namada");
    let mut changed_keys = BTreeSet::new();
    // we need to collect the events into a separate
    // buffer because of rust's borrowing rules :|
    let confirmed_events: Vec<_> = wl_storage
        .storage
        .eth_events_queue
        .transfers_to_namada
        .push_and_iter(transfer_event)
        .collect();
    for TransfersToNamada {
        transfers,
        valid_transfers_map,
        ..
    } in confirmed_events
    {
        update_transfers_to_namada_state(
            wl_storage,
            &mut changed_keys,
            transfers.iter().zip(valid_transfers_map.iter()).filter_map(
                |(transfer, &valid)| {
                    if valid {
                        Some(transfer)
                    } else {
                        tracing::debug!(
                            ?transfer,
                            "Ignoring invalid transfer to Namada event"
                        );
                        None
                    }
                },
            ),
        )?;
    }
    Ok(changed_keys)
}

fn update_transfers_to_namada_state<'tx, D, H>(
    wl_storage: &mut WlStorage<D, H>,
    changed_keys: &mut BTreeSet<Key>,
    transfers: impl IntoIterator<Item = &'tx TransferToNamada>,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let wrapped_native_erc20 = read_native_erc20_address(wl_storage)?;
    for transfer in transfers {
        tracing::debug!(
            ?transfer,
            "Applying state updates derived from a transfer to Namada event"
        );
        let TransferToNamada {
            amount,
            asset,
            receiver,
        } = transfer;
        let mut changed = if asset != &wrapped_native_erc20 {
            let (asset_count, changed) =
                mint_eth_assets(wl_storage, asset, receiver, amount)?;
            // TODO: query denomination of the whitelisted token from storage,
            // and print this amount with the proper formatting; for now, use
            // NAM's formatting
            if !asset_count.erc20_amount.is_zero() {
                tracing::info!(
                    "Minted wrapped ERC20s - (asset - {asset}, receiver - \
                     {receiver}, amount - {})",
                    asset_count.erc20_amount.to_string_native(),
                );
            }
            if !asset_count.nut_amount.is_zero() {
                tracing::info!(
                    "Minted NUTs - (asset - {asset}, receiver - {receiver}, \
                     amount - {})",
                    asset_count.nut_amount.to_string_native(),
                );
            }
            changed
        } else {
            redeem_native_token(wl_storage, receiver, amount)?
        };
        changed_keys.append(&mut changed)
    }
    Ok(())
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
        amount = %amount.to_string_native(),
        %receiver,
        eth_bridge_native_token_balance_pre = %eth_bridge_native_token_balance_pre.to_string_native(),
        eth_bridge_native_token_balance_post = %eth_bridge_native_token_balance_post.to_string_native(),
        receiver_native_token_balance_pre = %receiver_native_token_balance_pre.to_string_native(),
        receiver_native_token_balance_post = %receiver_native_token_balance_post.to_string_native(),
        "Redeemed native token for wrapped ERC20 token"
    );
    Ok(BTreeSet::from([
        eth_bridge_native_token_balance_key,
        receiver_native_token_balance_key,
    ]))
}

/// Helper function to mint assets originating from Ethereum
/// on Namada.
///
/// Mints `amount` of a wrapped ERC20 `asset` for `receiver`.
/// If the given asset is not whitelisted or has exceeded the
/// token caps, mint NUTs, too.
fn mint_eth_assets<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    asset: &EthAddress,
    receiver: &Address,
    &amount: &token::Amount,
) -> Result<(EthAssetMint, BTreeSet<Key>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let asset_count = wl_storage
        .ethbridge_queries()
        .get_eth_assets_to_mint(asset, amount);

    let assets_to_mint = [
        // check if we should mint nuts
        (!asset_count.nut_amount.is_zero())
            .then(|| (wrapped_erc20s::nut(asset), asset_count.nut_amount)),
        // check if we should mint erc20s
        (!asset_count.erc20_amount.is_zero())
            .then(|| (wrapped_erc20s::token(asset), asset_count.erc20_amount)),
    ]
    .into_iter()
    // remove assets that do not need to be
    // minted from the iterator
    .flatten();

    for (token, ref amount) in assets_to_mint {
        let balance_key = balance_key(&token, receiver);
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

        let supply_key = minted_balance_key(&token);
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
    }

    Ok((asset_count, changed_keys))
}

fn act_on_transfers_to_eth<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    transfers: &[TransferToEthereum],
    valid_transfers: &[bool],
    relayer: &Address,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    tracing::debug!(
        ?transfers,
        ?valid_transfers,
        "Acting on transfers to Ethereum"
    );
    let mut changed_keys = BTreeSet::default();

    // the BP nonce should always be incremented, even if no valid
    // transfers to Ethereum were relayed. failing to do this
    // halts the Ethereum bridge, since nonces will fall out
    // of sync between Namada and Ethereum
    let nonce_key = get_nonce_key();
    increment_bp_nonce(&nonce_key, wl_storage)?;
    changed_keys.insert(nonce_key);

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
    let pool_balance_key =
        balance_key(&wl_storage.storage.native_token, &BRIDGE_POOL_ADDRESS);
    let relayer_rewards_key =
        balance_key(&wl_storage.storage.native_token, relayer);
    // Remove the completed transfers from the bridge pool
    for (event, is_valid) in
        transfers.iter().zip(valid_transfers.iter().copied())
    {
        let pending_transfer = event.into();
        let key = get_pending_key(&pending_transfer);
        if hints::unlikely(!wl_storage.has_key(&key)?) {
            unreachable!("The transfer should exist in the bridge pool");
        }
        if hints::likely(is_valid) {
            tracing::debug!(
                ?pending_transfer,
                "Valid transfer to Ethereum detected, compensating the \
                 relayer and burning any Ethereum assets in Namada"
            );
            changed_keys.append(&mut burn_transferred_assets(
                wl_storage,
                &pending_transfer,
            )?);
        } else {
            tracing::debug!(
                ?pending_transfer,
                "Invalid transfer to Ethereum detected, compensating the \
                 relayer and refunding assets in Namada"
            );
            changed_keys.append(&mut refund_transferred_assets(
                wl_storage,
                &pending_transfer,
            )?);
        }
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
        _ = changed_keys.insert(key);
    }
    if !transfers.is_empty() {
        changed_keys.insert(relayer_rewards_key);
        changed_keys.insert(pool_balance_key);
    }

    if pending_keys.is_empty() {
        return Ok(changed_keys);
    }

    // TODO the timeout height is min_num_blocks of an epoch for now
    let epoch_duration = read_epoch_duration_parameter(wl_storage)?;
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
    let mut changed_keys = BTreeSet::default();

    let transfer = match wl_storage.read_bytes(&key)? {
        Some(v) => PendingTransfer::try_from_slice(&v[..])?,
        None => unreachable!(),
    };
    changed_keys.append(&mut refund_transfer_fees(wl_storage, &transfer)?);
    changed_keys.append(&mut refund_transferred_assets(wl_storage, &transfer)?);

    // Delete the key from the bridge pool
    wl_storage.delete(&key)?;
    _ = changed_keys.insert(key);

    Ok(changed_keys)
}

fn refund_transfer_fees<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    transfer: &PendingTransfer,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let payer_balance_key =
        balance_key(&wl_storage.storage.native_token, &transfer.gas_fee.payer);
    let pool_balance_key =
        balance_key(&wl_storage.storage.native_token, &BRIDGE_POOL_ADDRESS);
    update::amount(wl_storage, &payer_balance_key, |balance| {
        balance.receive(&transfer.gas_fee.amount);
    })?;
    update::amount(wl_storage, &pool_balance_key, |balance| {
        balance.spend(&transfer.gas_fee.amount);
    })?;

    tracing::debug!(?transfer, "Refunded Bridge pool transfer fees");
    _ = changed_keys.insert(payer_balance_key);
    _ = changed_keys.insert(pool_balance_key);
    Ok(changed_keys)
}

fn refund_transferred_assets<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    transfer: &PendingTransfer,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let native_erc20_addr = match wl_storage
        .read_bytes(&bridge_storage::native_erc20_key())?
    {
        Some(v) => EthAddress::try_from_slice(&v[..])?,
        None => {
            return Err(eyre::eyre!("Could not read wNam key from storage"));
        }
    };
    let (source, target) = if transfer.transfer.asset == native_erc20_addr {
        let escrow_balance_key =
            balance_key(&wl_storage.storage.native_token, &BRIDGE_ADDRESS);
        let sender_balance_key = balance_key(
            &wl_storage.storage.native_token,
            &transfer.transfer.sender,
        );
        (escrow_balance_key, sender_balance_key)
    } else {
        let token = transfer.token_address();
        let escrow_balance_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
        let sender_balance_key = balance_key(&token, &transfer.transfer.sender);
        (escrow_balance_key, sender_balance_key)
    };
    update::amount(wl_storage, &source, |balance| {
        balance.spend(&transfer.transfer.amount);
    })?;
    update::amount(wl_storage, &target, |balance| {
        balance.receive(&transfer.transfer.amount);
    })?;

    tracing::debug!(?transfer, "Refunded Bridge pool transferred assets");
    _ = changed_keys.insert(source);
    _ = changed_keys.insert(target);
    Ok(changed_keys)
}

fn burn_transferred_assets<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    transfer: &PendingTransfer,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let maybe_addr = wl_storage.read(&bridge_storage::native_erc20_key())?;
    let Some(native_erc20_addr) = maybe_addr else {
        return Err(eyre::eyre!("Could not read wNam key from storage"));
    };

    if transfer.transfer.asset == native_erc20_addr {
        tracing::debug!(?transfer, "Keeping wrapped NAM in escrow");
        return Ok(changed_keys);
    }

    let token = transfer.token_address();

    let escrow_balance_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
    update::amount(wl_storage, &escrow_balance_key, |balance| {
        balance.spend(&transfer.transfer.amount);
    })?;
    _ = changed_keys.insert(escrow_balance_key);

    let supply_key = minted_balance_key(&token);
    update::amount(wl_storage, &supply_key, |supply| {
        supply.spend(&transfer.transfer.amount);
    })?;
    _ = changed_keys.insert(supply_key);

    tracing::debug!(?transfer, "Burned wrapped ERC20 tokens");
    Ok(changed_keys)
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use borsh::BorshSerialize;
    use eyre::Result;
    use namada_core::ledger::parameters::{
        update_epoch_parameter, EpochDuration,
    };
    use namada_core::ledger::storage::mockdb::MockDBWriteBatch;
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::ledger::storage::types::encode;
    use namada_core::types::address::testing::gen_implicit_address;
    use namada_core::types::address::{gen_established_address, nam};
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
        update_epoch_parameter(wl_storage, &epoch_duration)
            .expect("Test failed");
        // set native ERC20 token
        let native_erc20_key = bridge_storage::native_erc20_key();
        let native_erc20 = EthAddress([0; 20]);
        wl_storage
            .write_bytes(&native_erc20_key, encode(&native_erc20))
            .expect("Test failed");
    }

    fn init_bridge_pool_transfers<A>(
        wl_storage: &mut TestWlStorage,
        assets_transferred: A,
    ) -> Vec<PendingTransfer>
    where
        A: Into<
            BTreeSet<(EthAddress, eth_bridge_pool::TransferToEthereumKind)>,
        >,
    {
        let sender = address::testing::established_address_1();
        let payer = address::testing::established_address_2();

        // set pending transfers
        let mut pending_transfers = vec![];
        for (i, (asset, kind)) in
            assets_transferred.into().into_iter().enumerate()
        {
            let transfer = PendingTransfer {
                transfer: eth_bridge_pool::TransferToEthereum {
                    asset,
                    sender: sender.clone(),
                    recipient: EthAddress([i as u8 + 1; 20]),
                    amount: Amount::from(10),
                    kind,
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

    #[inline]
    fn init_bridge_pool(
        wl_storage: &mut TestWlStorage,
    ) -> Vec<PendingTransfer> {
        init_bridge_pool_transfers(
            wl_storage,
            (0..2)
                .map(|i| {
                    (
                        EthAddress([i; 20]),
                        if i & 1 == 0 {
                            eth_bridge_pool::TransferToEthereumKind::Erc20
                        } else {
                            eth_bridge_pool::TransferToEthereumKind::Nut
                        },
                    )
                })
                .collect::<BTreeSet<_>>(),
        )
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
                let token = transfer.token_address();
                let sender_key = balance_key(&token, &transfer.transfer.sender);
                let sender_balance = Amount::from(0);
                wl_storage
                    .write_bytes(
                        &sender_key,
                        sender_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
                let escrow_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
                let escrow_balance = Amount::from(10);
                wl_storage
                    .write_bytes(
                        &escrow_key,
                        escrow_balance.try_to_vec().expect("Test failed"),
                    )
                    .expect("Test failed");
                update::amount(
                    wl_storage,
                    &minted_balance_key(&token),
                    |supply| {
                        supply.receive(&transfer.transfer.amount);
                    },
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

        for event in events {
            act_on(&mut wl_storage, event.clone()).unwrap();
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
            valid_transfers_map: transfers.iter().map(|_| true).collect(),
            transfers,
        };

        act_on(&mut wl_storage, event).unwrap();

        assert_eq!(
            stored_keys_count(&wl_storage),
            initial_stored_keys_count + 2
        );
    }

    /// Parameters to test minting DAI in Namada.
    struct TestMintDai {
        /// The token cap of DAI.
        ///
        /// If the token is not whitelisted, this value
        /// is not set.
        dai_token_cap: Option<token::Amount>,
        /// The transferred amount of DAI.
        transferred_amount: token::Amount,
    }

    impl TestMintDai {
        /// Execute a test with the given parameters.
        fn run_test(self) {
            let dai_token_cap = self.dai_token_cap.unwrap_or_default();

            let (erc20_amount, nut_amount) =
                if dai_token_cap > self.transferred_amount {
                    (self.transferred_amount, token::Amount::zero())
                } else {
                    (dai_token_cap, self.transferred_amount - dai_token_cap)
                };
            assert_eq!(self.transferred_amount, nut_amount + erc20_amount);

            let mut wl_storage = TestWlStorage::default();
            test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
            if !dai_token_cap.is_zero() {
                test_utils::whitelist_tokens(
                    &mut wl_storage,
                    [(
                        DAI_ERC20_ETH_ADDRESS,
                        test_utils::WhitelistMeta {
                            cap: dai_token_cap,
                            denom: 18,
                        },
                    )],
                );
            }

            let receiver = address::testing::established_address_1();
            let transfers = vec![TransferToNamada {
                amount: self.transferred_amount,
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: receiver.clone(),
            }];

            update_transfers_to_namada_state(
                &mut wl_storage,
                &mut BTreeSet::new(),
                &transfers,
            )
            .unwrap();

            for is_nut in [false, true] {
                let wdai = if is_nut {
                    wrapped_erc20s::nut(&DAI_ERC20_ETH_ADDRESS)
                } else {
                    wrapped_erc20s::token(&DAI_ERC20_ETH_ADDRESS)
                };
                let expected_amount =
                    if is_nut { nut_amount } else { erc20_amount };

                let receiver_balance_key = balance_key(&wdai, &receiver);
                let wdai_supply_key = minted_balance_key(&wdai);

                for key in vec![receiver_balance_key, wdai_supply_key] {
                    let value: Option<token::Amount> =
                        wl_storage.read(&key).unwrap();
                    if expected_amount.is_zero() {
                        assert_matches!(value, None);
                    } else {
                        assert_matches!(value, Some(amount) if amount == expected_amount);
                    }
                }
            }
        }
    }

    /// Test that if DAI is never whitelisted, we only mint NUTs.
    #[test]
    fn test_minting_dai_when_not_whitelisted() {
        TestMintDai {
            dai_token_cap: None,
            transferred_amount: Amount::from(100),
        }
        .run_test();
    }

    /// Test that overrunning the token caps results in minting DAI NUTs,
    /// along with wDAI.
    #[test]
    fn test_minting_dai_on_cap_overrun() {
        TestMintDai {
            dai_token_cap: Some(Amount::from(80)),
            transferred_amount: Amount::from(100),
        }
        .run_test();
    }

    /// Test acting on a single "transfer to Namada" Ethereum event
    /// and minting the first ever wDAI.
    #[test]
    fn test_minting_dai_wrapped() {
        TestMintDai {
            dai_token_cap: Some(Amount::max()),
            transferred_amount: Amount::from(100),
        }
        .run_test();
    }

    #[test]
    /// When we act on an [`EthereumEvent::TransfersToEthereum`], test
    /// that pending transfers are deleted from the Bridge pool, the
    /// Bridge pool nonce is updated and escrowed assets are burned.
    fn test_act_on_changes_storage_for_transfers_to_eth() {
        let mut wl_storage = TestWlStorage::default();
        test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
        wl_storage.commit_block().expect("Test failed");
        init_storage(&mut wl_storage);
        let native_erc20 =
            read_native_erc20_address(&wl_storage).expect("Test failed");
        let random_erc20 = EthAddress([0xff; 20]);
        let random_erc20_token = wrapped_erc20s::nut(&random_erc20);
        let random_erc20_2 = EthAddress([0xee; 20]);
        let random_erc20_token_2 = wrapped_erc20s::token(&random_erc20_2);
        let pending_transfers = init_bridge_pool_transfers(
            &mut wl_storage,
            [
                (native_erc20, eth_bridge_pool::TransferToEthereumKind::Erc20),
                (random_erc20, eth_bridge_pool::TransferToEthereumKind::Nut),
                (
                    random_erc20_2,
                    eth_bridge_pool::TransferToEthereumKind::Erc20,
                ),
            ],
        );
        init_balance(&mut wl_storage, &pending_transfers);
        let pending_keys: HashSet<Key> =
            pending_transfers.iter().map(get_pending_key).collect();
        let relayer = gen_established_address("random");
        let mut transfers = vec![];
        for transfer in pending_transfers {
            let transfer_to_eth = TransferToEthereum {
                kind: transfer.transfer.kind,
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
            valid_transfers_map: transfers.iter().map(|_| true).collect(),
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
        let mut changed_keys = act_on(&mut wl_storage, event).unwrap();

        assert!(
            changed_keys.remove(&balance_key(
                &random_erc20_token,
                &BRIDGE_POOL_ADDRESS
            ))
        );
        assert!(
            changed_keys.remove(&balance_key(
                &random_erc20_token_2,
                &BRIDGE_POOL_ADDRESS
            ))
        );
        assert!(changed_keys.remove(&minted_balance_key(&random_erc20_token)));
        assert!(
            changed_keys.remove(&minted_balance_key(&random_erc20_token_2))
        );
        assert!(changed_keys.remove(&payer_balance_key));
        assert!(changed_keys.remove(&pool_balance_key));
        assert!(changed_keys.remove(&get_nonce_key()));
        assert!(changed_keys.iter().all(|k| pending_keys.contains(k)));

        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(
            wl_storage
                .iter_prefix(&prefix)
                .expect("Test failed")
                .count(),
            // NOTE: we should have one write -- the bridge pool nonce update
            1
        );
        let relayer_balance = Amount::try_from_slice(
            &wl_storage
                .read_bytes(&payer_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");
        assert_eq!(relayer_balance, Amount::from(3));
        let bp_balance_post = Amount::try_from_slice(
            &wl_storage
                .read_bytes(&pool_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");
        bp_balance_pre.spend(&bp_balance_post);
        assert_eq!(bp_balance_pre, Amount::from(3));
        assert_eq!(bp_balance_post, Amount::from(0));
    }

    #[test]
    /// Test that the transfers time out in the bridge pool then the refund when
    /// we act on a TransfersToEthereum
    fn test_act_on_timeout_for_transfers_to_eth() {
        let mut wl_storage = TestWlStorage::default();
        test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
        wl_storage.commit_block().expect("Test failed");
        init_storage(&mut wl_storage);
        // Height 0
        let pending_transfers = init_bridge_pool(&mut wl_storage);
        init_balance(&mut wl_storage, &pending_transfers);
        wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");
        // pending transfers time out
        wl_storage.storage.block.height += 10 + 1;
        // new pending transfer
        let transfer = PendingTransfer {
            transfer: eth_bridge_pool::TransferToEthereum {
                asset: EthAddress([4; 20]),
                sender: address::testing::established_address_1(),
                recipient: EthAddress([5; 20]),
                amount: Amount::from(10),
                kind: eth_bridge_pool::TransferToEthereumKind::Erc20,
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
        wl_storage
            .storage
            .commit_block(MockDBWriteBatch)
            .expect("Test failed");
        wl_storage.storage.block.height += 1;

        // This should only refund
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers: vec![],
            valid_transfers_map: vec![],
            relayer: gen_implicit_address(),
        };
        let _ = act_on(&mut wl_storage, event).unwrap();

        // The latest transfer is still pending
        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(
            wl_storage
                .iter_prefix(&prefix)
                .expect("Test failed")
                .count(),
            // NOTE: we should have two writes -- one of them being
            // the bridge pool nonce update
            2
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
                let token = transfer.token_address();
                let sender_key = balance_key(&token, &transfer.transfer.sender);
                let value =
                    wl_storage.read_bytes(&sender_key).expect("Test failed");
                let sender_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(sender_balance, transfer.transfer.amount);
                let escrow_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
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

    /// Auxiliary function to test wrapped Ethereum ERC20s functionality.
    fn test_wrapped_erc20s_aux<F>(mut f: F)
    where
        F: FnMut(&mut TestWlStorage, EthereumEvent),
    {
        let mut wl_storage = TestWlStorage::default();
        test_utils::bootstrap_ethereum_bridge(&mut wl_storage);
        wl_storage.commit_block().expect("Test failed");
        init_storage(&mut wl_storage);
        let native_erc20 =
            read_native_erc20_address(&wl_storage).expect("Test failed");
        let pending_transfers = init_bridge_pool_transfers(
            &mut wl_storage,
            [
                (native_erc20, eth_bridge_pool::TransferToEthereumKind::Nut),
                (
                    EthAddress([0xaa; 20]),
                    eth_bridge_pool::TransferToEthereumKind::Erc20,
                ),
                (
                    EthAddress([0xbb; 20]),
                    eth_bridge_pool::TransferToEthereumKind::Nut,
                ),
                (
                    EthAddress([0xcc; 20]),
                    eth_bridge_pool::TransferToEthereumKind::Erc20,
                ),
                (
                    EthAddress([0xdd; 20]),
                    eth_bridge_pool::TransferToEthereumKind::Nut,
                ),
                (
                    EthAddress([0xee; 20]),
                    eth_bridge_pool::TransferToEthereumKind::Erc20,
                ),
                (
                    EthAddress([0xff; 20]),
                    eth_bridge_pool::TransferToEthereumKind::Nut,
                ),
            ],
        );
        init_balance(&mut wl_storage, &pending_transfers);
        let (transfers, valid_transfers_map) = pending_transfers
            .into_iter()
            .map(|transfer| {
                let transfer_to_eth = TransferToEthereum {
                    kind: transfer.transfer.kind,
                    amount: transfer.transfer.amount,
                    asset: transfer.transfer.asset,
                    receiver: transfer.transfer.recipient,
                    gas_amount: transfer.gas_fee.amount,
                    gas_payer: transfer.gas_fee.payer,
                    sender: transfer.transfer.sender,
                };
                (transfer_to_eth, true)
            })
            .unzip();
        let relayer = gen_established_address("random");
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            valid_transfers_map,
            transfers,
            relayer,
        };
        f(&mut wl_storage, event)
    }

    #[test]
    /// When we act on an [`EthereumEvent::TransfersToEthereum`], test
    /// that the transferred wrapped ERC20 tokens are burned in Namada.
    fn test_wrapped_erc20s_are_burned() {
        struct Delta {
            asset: EthAddress,
            sent_amount: token::Amount,
            prev_balance: Option<token::Amount>,
            prev_supply: Option<token::Amount>,
            kind: eth_bridge_pool::TransferToEthereumKind,
        }

        test_wrapped_erc20s_aux(|wl_storage, event| {
            let transfers = match &event {
                EthereumEvent::TransfersToEthereum { transfers, .. } => {
                    transfers.iter()
                }
                _ => panic!("Test failed"),
            };
            let native_erc20 =
                read_native_erc20_address(wl_storage).expect("Test failed");
            let deltas = transfers
                .filter_map(
                    |TransferToEthereum {
                         kind,
                         asset,
                         amount,
                         ..
                     }| {
                        if asset == &native_erc20 {
                            return None;
                        }
                        let erc20_token = match kind {
                            eth_bridge_pool::TransferToEthereumKind::Erc20 => {
                                wrapped_erc20s::token(asset)
                            }
                            eth_bridge_pool::TransferToEthereumKind::Nut => {
                                wrapped_erc20s::nut(asset)
                            }
                        };
                        let prev_balance = wl_storage
                            .read(&balance_key(
                                &erc20_token,
                                &BRIDGE_POOL_ADDRESS,
                            ))
                            .expect("Test failed");
                        let prev_supply = wl_storage
                            .read(&minted_balance_key(&erc20_token))
                            .expect("Test failed");
                        Some(Delta {
                            kind: *kind,
                            asset: *asset,
                            sent_amount: *amount,
                            prev_balance,
                            prev_supply,
                        })
                    },
                )
                .collect::<Vec<_>>();

            _ = act_on(wl_storage, event).unwrap();

            for Delta {
                kind,
                ref asset,
                sent_amount,
                prev_balance,
                prev_supply,
            } in deltas
            {
                let burn_balance = prev_balance
                    .unwrap_or_default()
                    .checked_sub(sent_amount)
                    .expect("Test failed");
                let burn_supply = prev_supply
                    .unwrap_or_default()
                    .checked_sub(sent_amount)
                    .expect("Test failed");

                let erc20_token = match kind {
                    eth_bridge_pool::TransferToEthereumKind::Erc20 => {
                        wrapped_erc20s::token(asset)
                    }
                    eth_bridge_pool::TransferToEthereumKind::Nut => {
                        wrapped_erc20s::nut(asset)
                    }
                };

                let balance: token::Amount = wl_storage
                    .read(&balance_key(&erc20_token, &BRIDGE_POOL_ADDRESS))
                    .expect("Read must succeed")
                    .expect("Balance must exist");
                let supply: token::Amount = wl_storage
                    .read(&minted_balance_key(&erc20_token))
                    .expect("Read must succeed")
                    .expect("Balance must exist");

                assert_eq!(balance, burn_balance);
                assert_eq!(supply, burn_supply);
            }
        })
    }

    #[test]
    /// When we act on an [`EthereumEvent::TransfersToEthereum`], test
    /// that the transferred wrapped NAM tokens are not burned in
    /// Namada and instead are kept in escrow, under the Ethereum bridge
    /// account.
    fn test_wrapped_nam_not_burned() {
        test_wrapped_erc20s_aux(|wl_storage, event| {
            let native_erc20 =
                read_native_erc20_address(wl_storage).expect("Test failed");
            let wnam = wrapped_erc20s::token(&native_erc20);
            let escrow_balance_key = balance_key(&nam(), &BRIDGE_ADDRESS);

            // check pre supply
            assert!(
                wl_storage
                    .read_bytes(&balance_key(&wnam, &BRIDGE_POOL_ADDRESS))
                    .expect("Test failed")
                    .is_none()
            );
            assert!(
                wl_storage
                    .read_bytes(&minted_balance_key(&wnam))
                    .expect("Test failed")
                    .is_none()
            );

            // check pre balance
            let pre_escrowed_balance: token::Amount = wl_storage
                .read(&escrow_balance_key)
                .expect("Read must succeed")
                .expect("Balance must exist");

            _ = act_on(wl_storage, event).unwrap();

            // check post supply
            assert!(
                wl_storage
                    .read_bytes(&balance_key(&wnam, &BRIDGE_POOL_ADDRESS))
                    .expect("Test failed")
                    .is_none()
            );
            assert!(
                wl_storage
                    .read_bytes(&minted_balance_key(&wnam))
                    .expect("Test failed")
                    .is_none()
            );

            // check post balance
            let post_escrowed_balance: token::Amount = wl_storage
                .read(&escrow_balance_key)
                .expect("Read must succeed")
                .expect("Balance must exist");

            assert_eq!(pre_escrowed_balance, post_escrowed_balance);
        })
    }
}
