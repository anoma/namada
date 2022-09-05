//! Code for handling [`ProtocolTxType::EthereumEvents`] transactions.
mod eth_msgs;
mod events;
mod read;
mod update;
mod utils;

use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::BorshSerialize;
use eth_msgs::{EthMsg, EthMsgUpdate};
use eyre::{eyre, Result};
use namada::ledger::eth_bridge::storage::eth_msgs::Keys;
use namada::types::address::Address;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::storage;
use namada::types::transaction::TxResult;
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;
use namada::types::voting_power::FractionalVotingPower;

use super::store::{Store, StoreExt};

/// The keys changed while applying a protocol transaction
type ChangedKeys = BTreeSet<storage::Key>;

/// Applies derived state changes to storage, based on Ethereum `events` which
/// were newly seen by some active validator(s) in the last epoch. For `events`
/// which have been seen by enough voting power, extra state changes may take
/// place, such as minting of wrapped ERC20s.
///
/// This function is deterministic based on some existing blockchain state and
/// the passed `events`.
pub(crate) fn apply_derived_tx(
    store: &mut impl StoreExt,
    events: Vec<MultiSignedEthEvent>,
) -> Result<TxResult> {
    if events.is_empty() {
        return Ok(TxResult::default());
    }
    tracing::info!(
        ethereum_events = events.len(),
        "Applying state updates derived from Ethereum events found in \
         protocol transaction"
    );

    let (updates, voting_powers) = get_update_data(store, events)?;

    let changed_keys = apply_updates(store, updates, voting_powers)?;

    Ok(TxResult {
        changed_keys,
        ..Default::default()
    })
}

/// Constructs all needed data that may be needed for updating #EthBridge
/// internal account storage based on `events`.
fn get_update_data(
    store: &impl StoreExt,
    events: Vec<MultiSignedEthEvent>,
) -> Result<(
    HashSet<EthMsgUpdate>,
    HashMap<Address, FractionalVotingPower>,
)> {
    let last_epoch = store.get_last_epoch();
    tracing::debug!(?last_epoch, "Got epoch of last block");

    let active_validators = store.get_active_validators(Some(last_epoch));
    tracing::debug!(
        n = active_validators.len(),
        "got active validators - {:#?}",
        active_validators,
    );

    let voters = utils::get_voters_for_events(events.iter());
    tracing::debug!(?voters, "Got validators who voted on at least one event");

    let voting_powers =
        utils::get_voting_powers_for_selected(&active_validators, voters)?;
    tracing::debug!(
        ?voting_powers,
        "got voting powers for relevant validators"
    );

    let updates = events.into_iter().map(Into::<EthMsgUpdate>::into).collect();

    Ok((updates, voting_powers))
}

/// Apply an Ethereum state update + act on any events which are confirmed
pub(super) fn apply_updates(
    store: &mut impl Store,
    updates: HashSet<EthMsgUpdate>,
    voting_powers: HashMap<Address, FractionalVotingPower>,
) -> Result<ChangedKeys> {
    tracing::debug!(
        updates.len = updates.len(),
        ?voting_powers,
        "Applying Ethereum state update transaction"
    );

    let mut changed_keys = BTreeSet::default();
    let mut confirmed = vec![];
    for update in updates {
        // The order in which updates are applied to storage does not matter.
        // The final storage state will be the same regardless.
        let (mut changed, newly_confirmed) =
            apply_update(store, update.clone(), &voting_powers)?;
        changed_keys.append(&mut changed);
        if newly_confirmed {
            confirmed.push(update.body);
        }
    }
    if confirmed.is_empty() {
        tracing::debug!("No events were newly confirmed");
        return Ok(changed_keys);
    }
    tracing::debug!(n = confirmed.len(), "Events were newly confirmed",);

    // Right now, the order in which events are acted on does not matter.
    // For `TransfersToNamada` events, they can happen in any order.
    for event in &confirmed {
        let mut changed = events::act_on(store, event)?;
        changed_keys.append(&mut changed);
    }
    Ok(changed_keys)
}

/// Apply an [`EthMsgUpdate`] to storage. Returns any keys changed and whether
/// the event was newly seen.
fn apply_update(
    store: &mut impl Store,
    update: EthMsgUpdate,
    voting_powers: &HashMap<Address, FractionalVotingPower>,
) -> Result<(ChangedKeys, bool)> {
    let eth_msg_keys = Keys::from(&update.body);

    // we arbitrarily look at whether the seen key is present to
    // determine if the /eth_msg already exists in storage, but maybe there
    // is a less arbitrary way to do this
    let exists_in_storage = store.has_key(&eth_msg_keys.seen())?;

    let (eth_msg_post, changed) = if !exists_in_storage {
        calculate_new_eth_msg(update, voting_powers)?
    } else {
        calculate_updated_eth_msg(store, update, voting_powers)?
    };
    write_eth_msg(store, &eth_msg_keys, &eth_msg_post)?;
    Ok((changed, !exists_in_storage))
}

fn calculate_new_eth_msg(
    update: EthMsgUpdate,
    voting_powers: &HashMap<Address, FractionalVotingPower>,
) -> Result<(EthMsg, ChangedKeys)> {
    let eth_msg_keys = Keys::from(&update.body);
    tracing::debug!(%eth_msg_keys.prefix, "Ethereum event not seen before by any validator");

    let mut seen_by_voting_power = FractionalVotingPower::default();
    for validator in &update.seen_by {
        match voting_powers.get(validator) {
            Some(voting_power) => seen_by_voting_power += voting_power,
            None => {
                return Err(eyre!(
                    "voting power was not provided for validator {}",
                    validator
                ));
            }
        };
    }

    let newly_confirmed =
        seen_by_voting_power > FractionalVotingPower::TWO_THIRDS;
    Ok((
        EthMsg {
            body: update.body,
            voting_power: seen_by_voting_power,
            // the below `.collect()` is deterministic and will result in a
            // sorted vector as `update.seen_by` is a [`BTreeSet`]
            seen_by: update.seen_by.into_iter().collect(),
            seen: newly_confirmed,
        },
        eth_msg_keys.into_iter().collect(),
    ))
}

fn calculate_updated_eth_msg(
    store: &mut impl Store,
    update: EthMsgUpdate,
    voting_powers: &HashMap<Address, FractionalVotingPower>,
) -> Result<(EthMsg, ChangedKeys)> {
    let eth_msg_keys = Keys::from(&update.body);
    tracing::debug!(
        %eth_msg_keys.prefix,
        "Ethereum event already exists in storage",
    );
    let body: EthereumEvent = read::value(store, &eth_msg_keys.body())?;
    let seen: bool = read::value(store, &eth_msg_keys.seen())?;
    let seen_by: Vec<Address> = read::value(store, &eth_msg_keys.seen_by())?;
    let voting_power: FractionalVotingPower =
        read::value(store, &eth_msg_keys.voting_power())?;

    let eth_msg_pre = EthMsg {
        body,
        voting_power,
        seen_by,
        seen,
    };
    tracing::debug!("Read EthMsg - {:#?}", &eth_msg_pre);
    Ok(calculate_diff(eth_msg_pre, update, voting_powers))
}

fn calculate_diff(
    eth_msg: EthMsg,
    _update: EthMsgUpdate,
    _voting_powers: &HashMap<Address, FractionalVotingPower>,
) -> (EthMsg, ChangedKeys) {
    tracing::warn!(
        "Updating Ethereum events is not yet implemented, so this Ethereum \
         event won't change"
    );
    (eth_msg, BTreeSet::default())
}

fn write_eth_msg(
    store: &mut impl Store,
    eth_msg_keys: &Keys,
    eth_msg: &EthMsg,
) -> Result<()> {
    tracing::debug!("writing EthMsg - {:#?}", eth_msg);
    store.write(&eth_msg_keys.body(), &eth_msg.body.try_to_vec()?)?;
    store.write(&eth_msg_keys.seen(), &eth_msg.seen.try_to_vec()?)?;
    store.write(&eth_msg_keys.seen_by(), &eth_msg.seen_by.try_to_vec()?)?;
    store.write(
        &eth_msg_keys.voting_power(),
        &eth_msg.voting_power.try_to_vec()?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use borsh::BorshDeserialize;
    use namada::ledger::eth_bridge::storage::wrapped_erc20s;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
    };
    use namada::types::ethereum_events::{EthereumEvent, TransferToNamada};
    use namada::types::token::Amount;

    use super::*;
    use crate::node::ledger::protocol::transactions::store::testing::FakeStore;

    #[test]
    /// Test applying a `TransfersToNamada` batch containing a single transfer
    fn test_apply_single_transfer() -> Result<()> {
        let sole_validator = address::testing::gen_established_address();
        let receiver = address::testing::established_address_2();

        let amount = arbitrary_amount();
        let asset = arbitrary_eth_address();
        let body = EthereumEvent::TransfersToNamada {
            nonce: arbitrary_nonce(),
            transfers: vec![TransferToNamada {
                amount,
                asset: asset.clone(),
                receiver: receiver.clone(),
            }],
        };
        let update = EthMsgUpdate {
            body: body.clone(),
            seen_by: BTreeSet::from_iter(vec![sole_validator.clone()]),
        };
        let updates = HashSet::from_iter(vec![update]);
        let voting_powers = HashMap::from_iter(vec![(
            sole_validator.clone(),
            FractionalVotingPower::new(1, 1).unwrap(),
        )]);
        let mut storage = FakeStore::default();

        let changed_keys = apply_updates(&mut storage, updates, voting_powers)?;

        let eth_msg_keys: Keys = (&body).into();
        let wrapped_erc20_keys: wrapped_erc20s::Keys = (&asset).into();
        assert_eq!(
            BTreeSet::from_iter(vec![
                eth_msg_keys.body(),
                eth_msg_keys.seen(),
                eth_msg_keys.seen_by(),
                eth_msg_keys.voting_power(),
                wrapped_erc20_keys.balance(&receiver),
                wrapped_erc20_keys.supply(),
            ]),
            changed_keys
        );

        let body_bytes = storage.read(&eth_msg_keys.body())?.unwrap();
        assert_eq!(EthereumEvent::try_from_slice(&body_bytes)?, body);
        let seen_bytes = storage.read(&eth_msg_keys.seen())?.unwrap();
        assert!(bool::try_from_slice(&seen_bytes)?);
        let seen_by_bytes = storage.read(&eth_msg_keys.seen_by())?.unwrap();
        assert_eq!(
            Vec::<Address>::try_from_slice(&seen_by_bytes)?,
            vec![sole_validator]
        );
        let voting_power_bytes =
            storage.read(&eth_msg_keys.voting_power())?.unwrap();
        assert_eq!(<(u64, u64)>::try_from_slice(&voting_power_bytes)?, (1, 1));

        let wrapped_erc20_balance_bytes = storage
            .read(&wrapped_erc20_keys.balance(&receiver))?
            .unwrap();
        assert_eq!(
            Amount::try_from_slice(&wrapped_erc20_balance_bytes)?,
            amount
        );
        let wrapped_erc20_supply_bytes =
            storage.read(&wrapped_erc20_keys.supply())?.unwrap();
        assert_eq!(
            Amount::try_from_slice(&wrapped_erc20_supply_bytes)?,
            amount
        );

        Ok(())
    }
}
