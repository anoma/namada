//! Logic for acting on events

use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;

use borsh::BorshDeserialize;
use eyre::{Result, WrapErr};
use namada_core::address::Address;
use namada_core::eth_abi::Encode;
use namada_core::eth_bridge_pool::{
    erc20_nut_address, erc20_token_address, PendingTransfer,
    TransferToEthereumKind,
};
use namada_core::ethereum_events::{
    EthAddress, EthereumEvent, TransferToEthereum, TransferToNamada,
    TransfersToNamada,
};
use namada_core::ethereum_structs::EthBridgeEvent;
use namada_core::hints;
use namada_core::storage::{BlockHeight, Key, KeySeg};
use namada_parameters::read_epoch_duration_parameter;
use namada_state::{DBIter, StorageHasher, WlState, DB};
use namada_storage::{StorageRead, StorageWrite};
use namada_trans_token::storage_key::{balance_key, minted_balance_key};

use crate::protocol::transactions::update;
use crate::storage::bridge_pool::{
    get_nonce_key, is_pending_transfer_key, BRIDGE_POOL_ADDRESS,
};
use crate::storage::eth_bridge_queries::{EthAssetMint, EthBridgeQueries};
use crate::storage::parameters::read_native_erc20_address;
use crate::storage::{self as bridge_storage};
use crate::{token, ADDRESS as BRIDGE_ADDRESS};

/// Updates storage based on the given confirmed `event`. For example, for a
/// confirmed [`EthereumEvent::TransfersToNamada`], mint the corresponding
/// transferred assets to the appropriate receiver addresses.
pub(super) fn act_on<D, H>(
    state: &mut WlState<D, H>,
    event: EthereumEvent,
) -> Result<(BTreeSet<Key>, BTreeSet<EthBridgeEvent>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    match event {
        EthereumEvent::TransfersToNamada { transfers, nonce } => {
            act_on_transfers_to_namada(
                state,
                TransfersToNamada { transfers, nonce },
            )
        }
        EthereumEvent::TransfersToEthereum {
            ref transfers,
            ref relayer,
            ..
        } => act_on_transfers_to_eth(state, transfers, relayer),
        _ => {
            tracing::debug!(?event, "No actions taken for Ethereum event");
            Ok(Default::default())
        }
    }
}

fn act_on_transfers_to_namada<'tx, D, H>(
    state: &mut WlState<D, H>,
    transfer_event: TransfersToNamada,
) -> Result<(BTreeSet<Key>, BTreeSet<EthBridgeEvent>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    tracing::debug!(?transfer_event, "Acting on transfers to Namada");
    let mut changed_keys = BTreeSet::new();
    // we need to collect the events into a separate
    // buffer because of rust's borrowing rules :|
    let confirmed_events: Vec<_> = state
        .in_mem_mut()
        .eth_events_queue
        .transfers_to_namada
        .push_and_iter(transfer_event)
        .collect();
    for TransfersToNamada { transfers, .. } in confirmed_events {
        update_transfers_to_namada_state(
            state,
            &mut changed_keys,
            transfers.iter(),
        )?;
    }
    Ok((
        changed_keys,
        // no tx events when we get a transfer to namada
        BTreeSet::new(),
    ))
}

fn update_transfers_to_namada_state<'tx, D, H>(
    state: &mut WlState<D, H>,
    changed_keys: &mut BTreeSet<Key>,
    transfers: impl IntoIterator<Item = &'tx TransferToNamada>,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let wrapped_native_erc20 = read_native_erc20_address(state)?;
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
                mint_eth_assets(state, asset, receiver, amount)?;
            // TODO: query denomination of the whitelisted token from storage,
            // and print this amount with the proper formatting; for now, use
            // NAM's formatting
            if asset_count.should_mint_erc20s() {
                tracing::info!(
                    "Minted wrapped ERC20s - (asset - {asset}, receiver - \
                     {receiver}, amount - {})",
                    asset_count.erc20_amount.to_string_native(),
                );
            }
            if asset_count.should_mint_nuts() {
                tracing::info!(
                    "Minted NUTs - (asset - {asset}, receiver - {receiver}, \
                     amount - {})",
                    asset_count.nut_amount.to_string_native(),
                );
            }
            changed
        } else {
            redeem_native_token(state, &wrapped_native_erc20, receiver, amount)?
        };
        changed_keys.append(&mut changed)
    }
    Ok(())
}

/// Redeems `amount` of the native token for `receiver` from escrow.
fn redeem_native_token<D, H>(
    state: &mut WlState<D, H>,
    native_erc20: &EthAddress,
    receiver: &Address,
    amount: &token::Amount,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let eth_bridge_native_token_balance_key =
        balance_key(&state.in_mem().native_token, &BRIDGE_ADDRESS);
    let receiver_native_token_balance_key =
        balance_key(&state.in_mem().native_token, receiver);
    let native_werc20_supply_key =
        minted_balance_key(&erc20_token_address(native_erc20));

    update::amount(state, &eth_bridge_native_token_balance_key, |balance| {
        tracing::debug!(
            %eth_bridge_native_token_balance_key,
            ?balance,
            "Existing value found",
        );
        balance.spend(amount)?;
        tracing::debug!(
            %eth_bridge_native_token_balance_key,
            ?balance,
            "New value calculated",
        );
        Ok(())
    })?;
    update::amount(state, &receiver_native_token_balance_key, |balance| {
        tracing::debug!(
            %receiver_native_token_balance_key,
            ?balance,
            "Existing value found",
        );
        balance.receive(amount)?;
        tracing::debug!(
            %receiver_native_token_balance_key,
            ?balance,
            "New value calculated",
        );
        Ok(())
    })?;
    update::amount(state, &native_werc20_supply_key, |balance| {
        tracing::debug!(
            %native_werc20_supply_key,
            ?balance,
            "Existing value found",
        );
        balance.spend(amount)?;
        tracing::debug!(
            %native_werc20_supply_key,
            ?balance,
            "New value calculated",
        );
        Ok(())
    })?;

    tracing::info!(
        amount = %amount.to_string_native(),
        %receiver,
        "Redeemed native token for wrapped ERC20 token"
    );
    Ok(BTreeSet::from([
        eth_bridge_native_token_balance_key,
        receiver_native_token_balance_key,
        native_werc20_supply_key,
    ]))
}

/// Helper function to mint assets originating from Ethereum
/// on Namada.
///
/// Mints `amount` of a wrapped ERC20 `asset` for `receiver`.
/// If the given asset is not whitelisted or has exceeded the
/// token caps, mint NUTs, too.
fn mint_eth_assets<D, H>(
    state: &mut WlState<D, H>,
    asset: &EthAddress,
    receiver: &Address,
    &amount: &token::Amount,
) -> Result<(EthAssetMint, BTreeSet<Key>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let asset_count = state
        .ethbridge_queries()
        .get_eth_assets_to_mint(asset, amount);

    let assets_to_mint = [
        // check if we should mint nuts
        asset_count
            .should_mint_nuts()
            .then(|| (erc20_nut_address(asset), asset_count.nut_amount)),
        // check if we should mint erc20s
        asset_count
            .should_mint_erc20s()
            .then(|| (erc20_token_address(asset), asset_count.erc20_amount)),
    ]
    .into_iter()
    // remove assets that do not need to be
    // minted from the iterator
    .flatten();

    for (token, ref amount) in assets_to_mint {
        let balance_key = balance_key(&token, receiver);
        update::amount(state, &balance_key, |balance| {
            tracing::debug!(
                %balance_key,
                ?balance,
                "Existing value found",
            );
            balance.receive(amount)?;
            tracing::debug!(
                %balance_key,
                ?balance,
                "New value calculated",
            );
            Ok(())
        })?;
        _ = changed_keys.insert(balance_key);

        let supply_key = minted_balance_key(&token);
        update::amount(state, &supply_key, |supply| {
            tracing::debug!(
                %supply_key,
                ?supply,
                "Existing value found",
            );
            supply.receive(amount)?;
            tracing::debug!(
                %supply_key,
                ?supply,
                "New value calculated",
            );
            Ok(())
        })?;
        _ = changed_keys.insert(supply_key);
    }

    Ok((asset_count, changed_keys))
}

fn act_on_transfers_to_eth<D, H>(
    state: &mut WlState<D, H>,
    transfers: &[TransferToEthereum],
    relayer: &Address,
) -> Result<(BTreeSet<Key>, BTreeSet<EthBridgeEvent>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    tracing::debug!(?transfers, "Acting on transfers to Ethereum");
    let mut changed_keys = BTreeSet::default();
    let mut tx_events = BTreeSet::default();

    // the BP nonce should always be incremented, even if no valid
    // transfers to Ethereum were relayed. failing to do this
    // halts the Ethereum bridge, since nonces will fall out
    // of sync between Namada and Ethereum
    let nonce_key = get_nonce_key();
    increment_bp_nonce(&nonce_key, state)?;
    changed_keys.insert(nonce_key);

    // all keys of pending transfers
    let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
    let mut pending_keys: HashSet<Key> = state
        .iter_prefix(&prefix)
        .context("Failed to iterate over storage")?
        .map(|(k, _, _)| {
            Key::from_str(k.as_str()).expect("Key should be parsable")
        })
        .filter(is_pending_transfer_key)
        .collect();
    // Remove the completed transfers from the bridge pool
    for event in transfers {
        let (pending_transfer, key) = if let Some((pending, key)) =
            state.ethbridge_queries().lookup_transfer_to_eth(event)
        {
            (pending, key)
        } else {
            hints::cold();
            unreachable!("The transfer should exist in the bridge pool");
        };
        tracing::debug!(
            ?pending_transfer,
            "Valid transfer to Ethereum detected, compensating the relayer \
             and burning any Ethereum assets in Namada"
        );
        changed_keys.append(&mut update_transferred_asset_balances(
            state,
            &pending_transfer,
        )?);
        let pool_balance_key =
            balance_key(&pending_transfer.gas_fee.token, &BRIDGE_POOL_ADDRESS);
        let relayer_rewards_key =
            balance_key(&pending_transfer.gas_fee.token, relayer);
        // give the relayer the gas fee for this transfer.
        update::amount(state, &relayer_rewards_key, |balance| {
            balance.receive(&pending_transfer.gas_fee.amount)
        })?;
        // the gas fee is removed from escrow.
        update::amount(state, &pool_balance_key, |balance| {
            balance.spend(&pending_transfer.gas_fee.amount)
        })?;
        state.delete(&key)?;
        _ = pending_keys.remove(&key);
        _ = changed_keys.insert(key);
        _ = changed_keys.insert(pool_balance_key);
        _ = changed_keys.insert(relayer_rewards_key);
        _ = tx_events.insert(EthBridgeEvent::new_bridge_pool_relayed(
            pending_transfer.keccak256(),
        ));
    }

    if pending_keys.is_empty() {
        return Ok((changed_keys, tx_events));
    }

    // TODO the timeout height is min_num_blocks of an epoch for now
    let epoch_duration = read_epoch_duration_parameter(state)?;
    let timeout_offset = epoch_duration.min_num_of_blocks;

    // Check time out and refund
    if state.in_mem().block.height.0 > timeout_offset {
        let timeout_height =
            BlockHeight(state.in_mem().block.height.0 - timeout_offset);
        for key in pending_keys {
            let inserted_height = BlockHeight::try_from_slice(
                &state.in_mem().block.tree.get(&key)?,
            )
            .expect("BlockHeight should be decoded");
            if inserted_height <= timeout_height {
                let (mut keys, mut new_tx_events) =
                    refund_transfer(state, key)?;
                changed_keys.append(&mut keys);
                tx_events.append(&mut new_tx_events);
            }
        }
    }

    Ok((changed_keys, tx_events))
}

fn increment_bp_nonce<D, H>(
    nonce_key: &Key,
    state: &mut WlState<D, H>,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let next_nonce = state
        .ethbridge_queries()
        .get_bridge_pool_nonce()
        .checked_increment()
        .expect("Bridge pool nonce has overflowed");
    state.write(nonce_key, next_nonce)?;
    Ok(())
}

fn refund_transfer<D, H>(
    state: &mut WlState<D, H>,
    key: Key,
) -> Result<(BTreeSet<Key>, BTreeSet<EthBridgeEvent>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();
    let mut tx_events = BTreeSet::default();

    let transfer = match state.read_bytes(&key)? {
        Some(v) => PendingTransfer::try_from_slice(&v[..])?,
        None => unreachable!(),
    };
    changed_keys.append(&mut refund_transfer_fees(state, &transfer)?);
    changed_keys.append(&mut refund_transferred_assets(state, &transfer)?);

    // Delete the key from the bridge pool
    state.delete(&key)?;
    _ = changed_keys.insert(key);

    // Emit expiration event
    _ = tx_events.insert(EthBridgeEvent::new_bridge_pool_expired(
        transfer.keccak256(),
    ));

    Ok((changed_keys, tx_events))
}

fn refund_transfer_fees<D, H>(
    state: &mut WlState<D, H>,
    transfer: &PendingTransfer,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let payer_balance_key =
        balance_key(&transfer.gas_fee.token, &transfer.gas_fee.payer);
    let pool_balance_key =
        balance_key(&transfer.gas_fee.token, &BRIDGE_POOL_ADDRESS);
    update::amount(state, &payer_balance_key, |balance| {
        balance.receive(&transfer.gas_fee.amount)
    })?;
    update::amount(state, &pool_balance_key, |balance| {
        balance.spend(&transfer.gas_fee.amount)
    })?;

    tracing::debug!(?transfer, "Refunded Bridge pool transfer fees");
    _ = changed_keys.insert(payer_balance_key);
    _ = changed_keys.insert(pool_balance_key);
    Ok(changed_keys)
}

fn refund_transferred_assets<D, H>(
    state: &mut WlState<D, H>,
    transfer: &PendingTransfer,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let native_erc20_addr = match state
        .read_bytes(&bridge_storage::native_erc20_key())?
    {
        Some(v) => EthAddress::try_from_slice(&v[..])?,
        None => {
            return Err(eyre::eyre!("Could not read wNam key from storage"));
        }
    };
    let (source, target) = if transfer.transfer.asset == native_erc20_addr {
        let escrow_balance_key =
            balance_key(&state.in_mem().native_token, &BRIDGE_ADDRESS);
        let sender_balance_key = balance_key(
            &state.in_mem().native_token,
            &transfer.transfer.sender,
        );
        (escrow_balance_key, sender_balance_key)
    } else {
        let token = transfer.token_address();
        let escrow_balance_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
        let sender_balance_key = balance_key(&token, &transfer.transfer.sender);
        (escrow_balance_key, sender_balance_key)
    };
    update::amount(state, &source, |balance| {
        balance.spend(&transfer.transfer.amount)
    })?;
    update::amount(state, &target, |balance| {
        balance.receive(&transfer.transfer.amount)
    })?;

    tracing::debug!(?transfer, "Refunded Bridge pool transferred assets");
    _ = changed_keys.insert(source);
    _ = changed_keys.insert(target);
    Ok(changed_keys)
}

/// Burns any transferred ERC20s other than wNAM. If NAM is transferred,
/// update the wNAM supply key.
fn update_transferred_asset_balances<D, H>(
    state: &mut WlState<D, H>,
    transfer: &PendingTransfer,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut changed_keys = BTreeSet::default();

    let maybe_addr = state.read(&bridge_storage::native_erc20_key())?;
    let Some(native_erc20_addr) = maybe_addr else {
        return Err(eyre::eyre!("Could not read wNam key from storage"));
    };

    let token = transfer.token_address();

    // the wrapped NAM supply increases when we transfer to Ethereum
    if transfer.transfer.asset == native_erc20_addr {
        if hints::unlikely(matches!(
            &transfer.transfer.kind,
            TransferToEthereumKind::Nut
        )) {
            unreachable!("Attempted to mint wNAM NUTs!");
        }
        let supply_key = minted_balance_key(&token);
        update::amount(state, &supply_key, |supply| {
            supply.receive(&transfer.transfer.amount)
        })?;
        _ = changed_keys.insert(supply_key);
        tracing::debug!(?transfer, "Updated wrapped NAM supply");
        return Ok(changed_keys);
    }

    // other asset kinds must be burned

    let escrow_balance_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
    update::amount(state, &escrow_balance_key, |balance| {
        balance.spend(&transfer.transfer.amount)
    })?;
    _ = changed_keys.insert(escrow_balance_key);

    let supply_key = minted_balance_key(&token);
    update::amount(state, &supply_key, |supply| {
        supply.spend(&transfer.transfer.amount)
    })?;
    _ = changed_keys.insert(supply_key);

    tracing::debug!(?transfer, "Burned wrapped ERC20 tokens");
    Ok(changed_keys)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_matches::assert_matches;
    use namada_core::address::gen_established_address;
    use namada_core::address::testing::{gen_implicit_address, nam, wnam};
    use namada_core::eth_bridge_pool::GasFee;
    use namada_core::ethereum_events::testing::{
        arbitrary_keccak_hash, arbitrary_nonce, DAI_ERC20_ETH_ADDRESS,
    };
    use namada_core::time::DurationSecs;
    use namada_core::token::Amount;
    use namada_core::{address, eth_bridge_pool};
    use namada_parameters::{update_epoch_parameter, EpochDuration};
    use namada_state::testing::TestState;

    use super::*;
    use crate::storage::bridge_pool::get_pending_key;
    use crate::storage::wrapped_erc20s;
    use crate::test_utils::{self, stored_keys_count};

    fn init_storage(state: &mut TestState) {
        // set the timeout height offset
        let timeout_offset = 10;
        let epoch_duration = EpochDuration {
            min_num_of_blocks: timeout_offset,
            min_duration: DurationSecs(5),
        };
        update_epoch_parameter(state, &epoch_duration).expect("Test failed");
        // set native ERC20 token
        state
            .write(&bridge_storage::native_erc20_key(), wnam())
            .expect("Test failed");
    }

    /// Helper data structure to feed to [`init_bridge_pool_transfers`].
    struct TransferData {
        kind: eth_bridge_pool::TransferToEthereumKind,
        gas_token: Address,
    }

    impl Default for TransferData {
        fn default() -> Self {
            Self {
                kind: eth_bridge_pool::TransferToEthereumKind::Erc20,
                gas_token: nam(),
            }
        }
    }

    /// Build [`TransferData`] values.
    struct TransferDataBuilder {
        kind: Option<eth_bridge_pool::TransferToEthereumKind>,
        gas_token: Option<Address>,
    }

    #[allow(dead_code)]
    impl TransferDataBuilder {
        fn new() -> Self {
            Self {
                kind: None,
                gas_token: None,
            }
        }

        fn kind(
            mut self,
            kind: eth_bridge_pool::TransferToEthereumKind,
        ) -> Self {
            self.kind = Some(kind);
            self
        }

        fn kind_erc20(self) -> Self {
            self.kind(eth_bridge_pool::TransferToEthereumKind::Erc20)
        }

        fn kind_nut(self) -> Self {
            self.kind(eth_bridge_pool::TransferToEthereumKind::Nut)
        }

        fn gas_token(mut self, address: Address) -> Self {
            self.gas_token = Some(address);
            self
        }

        fn gas_erc20(self, address: &EthAddress) -> Self {
            self.gas_token(wrapped_erc20s::token(address))
        }

        fn gas_nut(self, address: &EthAddress) -> Self {
            self.gas_token(wrapped_erc20s::nut(address))
        }

        fn build(self) -> TransferData {
            TransferData {
                kind: self.kind.unwrap_or_else(|| TransferData::default().kind),
                gas_token: self
                    .gas_token
                    .unwrap_or_else(|| TransferData::default().gas_token),
            }
        }
    }

    fn init_bridge_pool_transfers<A>(
        state: &mut TestState,
        assets_transferred: A,
    ) -> Vec<PendingTransfer>
    where
        A: Into<HashMap<EthAddress, TransferData>>,
    {
        let sender = address::testing::established_address_1();
        let payer = address::testing::established_address_2();

        // set pending transfers
        let mut pending_transfers = vec![];
        for (i, (asset, TransferData { kind, gas_token })) in
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
                    token: gas_token,
                    amount: Amount::from(1),
                    payer: payer.clone(),
                },
            };
            let key = get_pending_key(&transfer);
            state.write(&key, &transfer).expect("Test failed");

            pending_transfers.push(transfer);
        }
        pending_transfers
    }

    #[inline]
    fn init_bridge_pool(state: &mut TestState) -> Vec<PendingTransfer> {
        init_bridge_pool_transfers(
            state,
            (0..2)
                .map(|i| {
                    (
                        EthAddress([i; 20]),
                        TransferDataBuilder::new()
                            .kind(if i & 1 == 0 {
                                eth_bridge_pool::TransferToEthereumKind::Erc20
                            } else {
                                eth_bridge_pool::TransferToEthereumKind::Nut
                            })
                            .build(),
                    )
                })
                .collect::<HashMap<_, _>>(),
        )
    }

    fn init_balance(
        state: &mut TestState,
        pending_transfers: &Vec<PendingTransfer>,
    ) {
        for transfer in pending_transfers {
            // Gas
            let payer = address::testing::established_address_2();
            let payer_key = balance_key(&transfer.gas_fee.token, &payer);
            let payer_balance = Amount::from(0);
            state.write(&payer_key, payer_balance).expect("Test failed");
            let escrow_key =
                balance_key(&transfer.gas_fee.token, &BRIDGE_POOL_ADDRESS);
            update::amount(state, &escrow_key, |balance| {
                let gas_fee = Amount::from_u64(1);
                balance.receive(&gas_fee)
            })
            .expect("Test failed");

            if transfer.transfer.asset == wnam() {
                // native ERC20
                let sender_key = balance_key(&nam(), &transfer.transfer.sender);
                let sender_balance = Amount::from(0);
                state
                    .write(&sender_key, sender_balance)
                    .expect("Test failed");
                let escrow_key = balance_key(&nam(), &BRIDGE_ADDRESS);
                let escrow_balance = Amount::from(10);
                state
                    .write(&escrow_key, escrow_balance)
                    .expect("Test failed");
            } else {
                let token = transfer.token_address();
                let sender_key = balance_key(&token, &transfer.transfer.sender);
                let sender_balance = Amount::from(0);
                state
                    .write(&sender_key, sender_balance)
                    .expect("Test failed");
                let escrow_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
                let escrow_balance = Amount::from(10);
                state
                    .write(&escrow_key, escrow_balance)
                    .expect("Test failed");
                update::amount(state, &minted_balance_key(&token), |supply| {
                    supply.receive(&transfer.transfer.amount)
                })
                .expect("Test failed");
            };
        }
    }

    #[test]
    /// Test that we do not make any changes to state when acting on most
    /// events
    fn test_act_on_does_nothing_for_other_events() {
        let mut state = TestState::default();
        test_utils::bootstrap_ethereum_bridge(&mut state);
        let initial_stored_keys_count = stored_keys_count(&state);
        let events = vec![EthereumEvent::ValidatorSetUpdate {
            nonce: arbitrary_nonce(),
            bridge_validator_hash: arbitrary_keccak_hash(),
            governance_validator_hash: arbitrary_keccak_hash(),
        }];

        for event in events {
            act_on(&mut state, event.clone()).unwrap();
            assert_eq!(
                stored_keys_count(&state),
                initial_stored_keys_count,
                "storage changed unexpectedly while acting on event: {:#?}",
                event
            );
        }
    }

    #[test]
    /// Test that state is indeed changed when we act on a non-empty
    /// TransfersToNamada batch
    fn test_act_on_changes_storage_for_transfers_to_namada() {
        let mut state = TestState::default();
        test_utils::bootstrap_ethereum_bridge(&mut state);
        state.commit_block().expect("Test failed");
        let initial_stored_keys_count = stored_keys_count(&state);
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

        act_on(&mut state, event).unwrap();

        assert_eq!(stored_keys_count(&state), initial_stored_keys_count + 2);
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

            let mut state = TestState::default();
            test_utils::bootstrap_ethereum_bridge(&mut state);
            if !dai_token_cap.is_zero() {
                test_utils::whitelist_tokens(
                    &mut state,
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
                &mut state,
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

                for key in [receiver_balance_key, wdai_supply_key] {
                    let value: Option<token::Amount> =
                        state.read(&key).unwrap();
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
        let mut state = TestState::default();
        test_utils::bootstrap_ethereum_bridge(&mut state);
        state.commit_block().expect("Test failed");
        init_storage(&mut state);
        let native_erc20 =
            read_native_erc20_address(&state).expect("Test failed");
        let random_erc20 = EthAddress([0xff; 20]);
        let random_erc20_token = wrapped_erc20s::nut(&random_erc20);
        let random_erc20_2 = EthAddress([0xee; 20]);
        let random_erc20_token_2 = wrapped_erc20s::token(&random_erc20_2);
        let random_erc20_3 = EthAddress([0xdd; 20]);
        let random_erc20_token_3 = wrapped_erc20s::token(&random_erc20_3);
        let random_erc20_4 = EthAddress([0xcc; 20]);
        let random_erc20_token_4 = wrapped_erc20s::nut(&random_erc20_4);
        let erc20_gas_addr = EthAddress([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19,
        ]);
        let pending_transfers = init_bridge_pool_transfers(
            &mut state,
            [
                (native_erc20, TransferData::default()),
                (random_erc20, TransferDataBuilder::new().kind_nut().build()),
                (
                    random_erc20_2,
                    TransferDataBuilder::new().kind_erc20().build(),
                ),
                (
                    random_erc20_3,
                    TransferDataBuilder::new()
                        .kind_erc20()
                        .gas_erc20(&erc20_gas_addr)
                        .build(),
                ),
                (
                    random_erc20_4,
                    TransferDataBuilder::new()
                        .kind_nut()
                        .gas_erc20(&erc20_gas_addr)
                        .build(),
                ),
            ],
        );
        init_balance(&mut state, &pending_transfers);
        let pending_keys: HashSet<Key> =
            pending_transfers.iter().map(get_pending_key).collect();
        let relayer = gen_established_address("random");
        let transfers: Vec<_> = pending_transfers
            .iter()
            .map(TransferToEthereum::from)
            .collect();
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers,
            relayer: relayer.clone(),
        };
        let payer_nam_balance_key = balance_key(&nam(), &relayer);
        let payer_erc_balance_key =
            balance_key(&wrapped_erc20s::token(&erc20_gas_addr), &relayer);
        let pool_nam_balance_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let pool_erc_balance_key = balance_key(
            &wrapped_erc20s::token(&erc20_gas_addr),
            &BRIDGE_POOL_ADDRESS,
        );
        let mut bp_nam_balance_pre = Amount::try_from_slice(
            &state
                .read_bytes(&pool_nam_balance_key)
                .expect("Test failed")
                .expect("Test failed"),
        )
        .expect("Test failed");
        let mut bp_erc_balance_pre = Amount::try_from_slice(
            &state
                .read_bytes(&pool_erc_balance_key)
                .expect("Test failed")
                .expect("Test failed"),
        )
        .expect("Test failed");
        let (mut changed_keys, _) = act_on(&mut state, event).unwrap();

        for erc20 in [
            random_erc20_token,
            random_erc20_token_2,
            random_erc20_token_3,
            random_erc20_token_4,
        ] {
            assert!(
                changed_keys.remove(&balance_key(&erc20, &BRIDGE_POOL_ADDRESS)),
                "Expected {erc20:?} Bridge pool balance to change"
            );
            assert!(
                changed_keys.remove(&minted_balance_key(&erc20)),
                "Expected {erc20:?} minted supply to change"
            );
        }
        assert!(
            changed_keys
                .remove(&minted_balance_key(&wrapped_erc20s::token(&wnam())))
        );
        assert!(changed_keys.remove(&payer_nam_balance_key));
        assert!(changed_keys.remove(&payer_erc_balance_key));
        assert!(changed_keys.remove(&pool_nam_balance_key));
        assert!(changed_keys.remove(&pool_erc_balance_key));
        assert!(changed_keys.remove(&get_nonce_key()));
        assert!(changed_keys.iter().all(|k| pending_keys.contains(k)));

        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(
            state.iter_prefix(&prefix).expect("Test failed").count(),
            // NOTE: we should have one write -- the bridge pool nonce update
            1
        );
        let relayer_nam_balance = Amount::try_from_slice(
            &state
                .read_bytes(&payer_nam_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");
        assert_eq!(relayer_nam_balance, Amount::from(3));
        let relayer_erc_balance = Amount::try_from_slice(
            &state
                .read_bytes(&payer_erc_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");
        assert_eq!(relayer_erc_balance, Amount::from(2));

        let bp_nam_balance_post = Amount::try_from_slice(
            &state
                .read_bytes(&pool_nam_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");
        let bp_erc_balance_post = Amount::try_from_slice(
            &state
                .read_bytes(&pool_erc_balance_key)
                .expect("Test failed: read error")
                .expect("Test failed: no value in storage"),
        )
        .expect("Test failed");

        bp_nam_balance_pre.spend(&bp_nam_balance_post).unwrap();
        assert_eq!(bp_nam_balance_pre, Amount::from(3));
        assert_eq!(bp_nam_balance_post, Amount::from(0));

        bp_erc_balance_pre.spend(&bp_erc_balance_post).unwrap();
        assert_eq!(bp_erc_balance_pre, Amount::from(2));
        assert_eq!(bp_erc_balance_post, Amount::from(0));
    }

    #[test]
    /// Test that the transfers time out in the bridge pool then the refund when
    /// we act on a TransfersToEthereum
    fn test_act_on_timeout_for_transfers_to_eth() {
        let mut state = TestState::default();
        test_utils::bootstrap_ethereum_bridge(&mut state);
        state.commit_block().expect("Test failed");
        init_storage(&mut state);
        // Height 0
        let pending_transfers = init_bridge_pool(&mut state);
        init_balance(&mut state, &pending_transfers);
        state.commit_block().expect("Test failed");
        // pending transfers time out
        state.in_mem_mut().block.height += 10 + 1;
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
                token: nam(),
                amount: Amount::from(1),
                payer: address::testing::established_address_1(),
            },
        };
        let key = get_pending_key(&transfer);
        state.write(&key, transfer).expect("Test failed");
        state.commit_block().expect("Test failed");
        state.in_mem_mut().block.height += 1;

        // This should only refund
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers: vec![],
            relayer: gen_implicit_address(),
        };
        let _ = act_on(&mut state, event).unwrap();

        // The latest transfer is still pending
        let prefix = BRIDGE_POOL_ADDRESS.to_db_key().into();
        assert_eq!(
            state.iter_prefix(&prefix).expect("Test failed").count(),
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
        let value = state.read_bytes(&payer_key).expect("Test failed");
        let payer_balance =
            Amount::try_from_slice(&value.expect("Test failed"))
                .expect("Test failed");
        assert_eq!(payer_balance, expected);
        let pool_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        let value = state.read_bytes(&pool_key).expect("Test failed");
        let pool_balance = Amount::try_from_slice(&value.expect("Test failed"))
            .expect("Test failed");
        assert_eq!(pool_balance, Amount::from(0));

        // Check the balances
        for transfer in pending_transfers {
            if transfer.transfer.asset == wnam() {
                let sender_key = balance_key(&nam(), &transfer.transfer.sender);
                let value = state.read_bytes(&sender_key).expect("Test failed");
                let sender_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(sender_balance, transfer.transfer.amount);
                let escrow_key = balance_key(&nam(), &BRIDGE_ADDRESS);
                let value = state.read_bytes(&escrow_key).expect("Test failed");
                let escrow_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(escrow_balance, Amount::from(0));
            } else {
                let token = transfer.token_address();
                let sender_key = balance_key(&token, &transfer.transfer.sender);
                let value = state.read_bytes(&sender_key).expect("Test failed");
                let sender_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(sender_balance, transfer.transfer.amount);
                let escrow_key = balance_key(&token, &BRIDGE_POOL_ADDRESS);
                let value = state.read_bytes(&escrow_key).expect("Test failed");
                let escrow_balance =
                    Amount::try_from_slice(&value.expect("Test failed"))
                        .expect("Test failed");
                assert_eq!(escrow_balance, Amount::from(0));
            }
        }
    }

    #[test]
    fn test_redeem_native_token() -> Result<()> {
        let mut state = TestState::default();
        test_utils::bootstrap_ethereum_bridge(&mut state);
        let receiver = address::testing::established_address_1();
        let amount = Amount::from(100);

        // pre wNAM balance - 0
        let receiver_wnam_balance_key = token::storage_key::balance_key(
            &wrapped_erc20s::token(&wnam()),
            &receiver,
        );
        assert!(
            state
                .read_bytes(&receiver_wnam_balance_key)
                .unwrap()
                .is_none()
        );

        let bridge_pool_initial_balance = Amount::from(100_000_000);
        let bridge_pool_native_token_balance_key =
            token::storage_key::balance_key(
                &state.in_mem().native_token,
                &BRIDGE_ADDRESS,
            );
        let bridge_pool_native_erc20_supply_key =
            minted_balance_key(&wrapped_erc20s::token(&wnam()));
        StorageWrite::write(
            &mut state,
            &bridge_pool_native_token_balance_key,
            bridge_pool_initial_balance,
        )?;
        StorageWrite::write(
            &mut state,
            &bridge_pool_native_erc20_supply_key,
            amount,
        )?;
        let receiver_native_token_balance_key = token::storage_key::balance_key(
            &state.in_mem().native_token,
            &receiver,
        );

        let changed_keys =
            redeem_native_token(&mut state, &wnam(), &receiver, &amount)?;

        assert_eq!(
            changed_keys,
            BTreeSet::from([
                bridge_pool_native_token_balance_key.clone(),
                receiver_native_token_balance_key.clone(),
                bridge_pool_native_erc20_supply_key.clone(),
            ])
        );
        assert_eq!(
            StorageRead::read(&state, &bridge_pool_native_token_balance_key)?,
            Some(bridge_pool_initial_balance - amount)
        );
        assert_eq!(
            StorageRead::read(&state, &receiver_native_token_balance_key)?,
            Some(amount)
        );
        assert_eq!(
            StorageRead::read(&state, &bridge_pool_native_erc20_supply_key)?,
            Some(Amount::zero())
        );

        // post wNAM balance - 0
        //
        // wNAM is never minted, it's converted back to NAM
        assert!(
            state
                .read_bytes(&receiver_wnam_balance_key)
                .unwrap()
                .is_none()
        );

        Ok(())
    }

    /// Auxiliary function to test wrapped Ethereum ERC20s functionality.
    fn test_wrapped_erc20s_aux<F>(mut f: F)
    where
        F: FnMut(&mut TestState, EthereumEvent),
    {
        let mut state = TestState::default();
        test_utils::bootstrap_ethereum_bridge(&mut state);
        state.commit_block().expect("Test failed");
        init_storage(&mut state);
        let native_erc20 =
            read_native_erc20_address(&state).expect("Test failed");
        let pending_transfers = init_bridge_pool_transfers(
            &mut state,
            [
                (native_erc20, TransferData::default()),
                (
                    EthAddress([0xaa; 20]),
                    TransferDataBuilder::new().kind_erc20().build(),
                ),
                (
                    EthAddress([0xbb; 20]),
                    TransferDataBuilder::new().kind_nut().build(),
                ),
                (
                    EthAddress([0xcc; 20]),
                    TransferDataBuilder::new().kind_erc20().build(),
                ),
                (
                    EthAddress([0xdd; 20]),
                    TransferDataBuilder::new().kind_nut().build(),
                ),
                (
                    EthAddress([0xee; 20]),
                    TransferDataBuilder::new().kind_erc20().build(),
                ),
                (
                    EthAddress([0xff; 20]),
                    TransferDataBuilder::new().kind_nut().build(),
                ),
            ],
        );
        init_balance(&mut state, &pending_transfers);
        let transfers = pending_transfers
            .into_iter()
            .map(|ref transfer| {
                let transfer_to_eth: TransferToEthereum = transfer.into();
                transfer_to_eth
            })
            .collect();
        let relayer = gen_established_address("random");
        let event = EthereumEvent::TransfersToEthereum {
            nonce: arbitrary_nonce(),
            transfers,
            relayer,
        };
        f(&mut state, event)
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

        test_wrapped_erc20s_aux(|state, event| {
            let transfers = match &event {
                EthereumEvent::TransfersToEthereum { transfers, .. } => {
                    transfers.iter()
                }
                _ => panic!("Test failed"),
            };
            let native_erc20 =
                read_native_erc20_address(state).expect("Test failed");
            let deltas = transfers
                .filter_map(
                    |event @ TransferToEthereum { asset, amount, .. }| {
                        if asset == &native_erc20 {
                            return None;
                        }
                        let kind = {
                            let (pending, _) = state
                                .ethbridge_queries()
                                .lookup_transfer_to_eth(event)
                                .expect("Test failed");
                            pending.transfer.kind
                        };
                        let erc20_token = match &kind {
                            eth_bridge_pool::TransferToEthereumKind::Erc20 => {
                                wrapped_erc20s::token(asset)
                            }
                            eth_bridge_pool::TransferToEthereumKind::Nut => {
                                wrapped_erc20s::nut(asset)
                            }
                        };
                        let prev_balance = state
                            .read(&balance_key(
                                &erc20_token,
                                &BRIDGE_POOL_ADDRESS,
                            ))
                            .expect("Test failed");
                        let prev_supply = state
                            .read(&minted_balance_key(&erc20_token))
                            .expect("Test failed");
                        Some(Delta {
                            kind,
                            asset: *asset,
                            sent_amount: *amount,
                            prev_balance,
                            prev_supply,
                        })
                    },
                )
                .collect::<Vec<_>>();

            _ = act_on(state, event).unwrap();

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

                let balance: token::Amount = state
                    .read(&balance_key(&erc20_token, &BRIDGE_POOL_ADDRESS))
                    .expect("Read must succeed")
                    .expect("Balance must exist");
                let supply: token::Amount = state
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
        test_wrapped_erc20s_aux(|state, event| {
            let native_erc20 =
                read_native_erc20_address(state).expect("Test failed");
            let wnam = wrapped_erc20s::token(&native_erc20);
            let escrow_balance_key = balance_key(&nam(), &BRIDGE_ADDRESS);

            // check pre supply
            assert!(
                state
                    .read_bytes(&balance_key(&wnam, &BRIDGE_POOL_ADDRESS))
                    .expect("Test failed")
                    .is_none()
            );
            assert!(
                state
                    .read_bytes(&minted_balance_key(&wnam))
                    .expect("Test failed")
                    .is_none()
            );

            // check pre balance
            let pre_escrowed_balance: token::Amount = state
                .read(&escrow_balance_key)
                .expect("Read must succeed")
                .expect("Balance must exist");

            _ = act_on(state, event).unwrap();

            // check post supply - the wNAM minted supply should increase
            // by the transferred amount
            assert!(
                state
                    .read_bytes(&balance_key(&wnam, &BRIDGE_POOL_ADDRESS))
                    .expect("Test failed")
                    .is_none()
            );
            assert_eq!(
                state
                    .read::<Amount>(&minted_balance_key(&wnam))
                    .expect("Reading from storage should not fail")
                    .expect("The wNAM supply should have been updated"),
                Amount::from_u64(10),
            );

            // check post balance
            let post_escrowed_balance: token::Amount = state
                .read(&escrow_balance_key)
                .expect("Read must succeed")
                .expect("Balance must exist");

            assert_eq!(pre_escrowed_balance, post_escrowed_balance);
        })
    }

    /// Test that the ledger appropriately panics when we try to mint
    /// wrapped NAM NUTs. Under normal circumstances, this should never
    /// happen.
    #[test]
    #[should_panic(expected = "Attempted to mint wNAM NUTs!")]
    fn test_wnam_doesnt_mint_nuts() {
        let mut state = TestState::default();
        test_utils::bootstrap_ethereum_bridge(&mut state);

        let transfer = PendingTransfer {
            transfer: eth_bridge_pool::TransferToEthereum {
                asset: wnam(),
                sender: address::testing::established_address_1(),
                recipient: EthAddress([5; 20]),
                amount: Amount::from(10),
                kind: eth_bridge_pool::TransferToEthereumKind::Nut,
            },
            gas_fee: GasFee {
                token: nam(),
                amount: Amount::from(1),
                payer: address::testing::established_address_1(),
            },
        };

        _ = update_transferred_asset_balances(&mut state, &transfer);
    }
}
