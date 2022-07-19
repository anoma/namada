//! Logic for acting on events

use std::collections::BTreeSet;

use eyre::Result;
use namada::ledger::eth_bridge::storage::wrapped_erc20s;
use namada::types::ethereum_events::{EthereumEvent, TransferToNamada};
use namada::types::storage::Key;

use super::update;
use crate::node::ledger::protocol::transactions::store::Store;

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
