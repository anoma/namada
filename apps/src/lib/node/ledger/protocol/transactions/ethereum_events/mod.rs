//! Code for handling [`ProtocolTxType::EthereumEvents`] transactions.
mod events;
mod read;
mod update;
mod utils;

use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};
use namada::ledger::eth_bridge::storage::eth_msgs::{self, Keys};
use namada::ledger::pos::types::{VotingPower, WeightedValidator};
use namada::types::address::Address;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::storage::{self, Epoch};
use namada::types::transaction::TxResult;
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;
use num_rational::Ratio;

use super::store::{Store, StoreExt};

/// Represents an event stored under `eth_msgs`
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct EthMsg {
    /// The event being stored
    pub body: EthereumEvent,
    /// The total voting power that's voted for this event across all epochs
    pub voting_power: (u64, u64),
    /// The addresses of validators that voted for this event, in sorted order.
    pub seen_by: Vec<Address>,
    /// Whether this event has been acted on or not
    pub seen: bool,
}

/// Represents an Ethereum event being seen by some validators
#[derive(
    Debug,
    Clone,
    Ord,
    PartialOrd,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct EthMsgUpdate {
    /// The event being seen
    pub body: EthereumEvent,
    /// Addresses of the validators who have just seen this event
    /// we use [`BTreeSet`] even though ordering is not important here, so that
    /// we can derive [`Hash`] for [`EthMsgUpdate`]. This also conveniently
    /// orders addresses in the order in which they should be stored in
    /// blockchain storage.
    pub seen_by: BTreeSet<Address>,
}

impl From<MultiSignedEthEvent> for EthMsgUpdate {
    fn from(
        MultiSignedEthEvent { event, signers }: MultiSignedEthEvent,
    ) -> Self {
        Self {
            body: event,
            seen_by: signers.into_iter().collect(),
        }
    }
}

/// Applies derived state changes to storage, based on Ethereum `events` which
/// have been newly seen by some active validator(s). For `events` which have
/// been seen by enough voting power, extra state changes may take place, such
/// as minting of wrapped ERC20s.
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

    let last_epoch = store.get_last_epoch();
    tracing::debug!(?last_epoch, "Got epoch of last block");

    let active_validators = store.get_active_validators(Some(last_epoch));
    tracing::debug!(
        n = active_validators.len(),
        "got active validators - {:#?}",
        active_validators,
    );

    apply_derived_tx_aux(store, events, last_epoch, active_validators)
}

fn apply_derived_tx_aux(
    store: &mut impl Store,
    events: Vec<MultiSignedEthEvent>,
    last_epoch: Epoch,
    active_validators: BTreeSet<WeightedValidator<Address>>,
) -> Result<TxResult> {
    let total_voting_power = utils::sum_voting_powers(&active_validators);
    tracing::debug!(
        ?total_voting_power,
        epoch = %last_epoch,
        "got total voting power for epoch"
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

    let changed_keys =
        apply_updates(store, updates, total_voting_power, voting_powers)?;

    Ok(TxResult {
        changed_keys,
        ..Default::default()
    })
}

/// Apply an Ethereum state update + act on any events which are confirmed
pub(super) fn apply_updates(
    store: &mut impl Store,
    updates: HashSet<EthMsgUpdate>,
    total_voting_power: VotingPower,
    voting_powers: HashMap<Address, VotingPower>,
) -> Result<BTreeSet<storage::Key>> {
    tracing::debug!(
        updates.len = updates.len(),
        %total_voting_power,
        ?voting_powers,
        "Applying Ethereum state update transaction"
    );

    let mut changed_keys = BTreeSet::default();
    let mut confirmed = vec![];
    for update in updates {
        // The order in which updates are applied to storage does not matter.
        // The final storage state will be the same regardless.
        let (mut changed, newly_confirmed) = apply_single_update(
            store,
            update.clone(),
            total_voting_power,
            &voting_powers,
        )?;
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
fn apply_single_update(
    store: &mut impl Store,
    update: EthMsgUpdate,
    total_voting_power: VotingPower,
    voting_powers: &HashMap<Address, VotingPower>,
) -> Result<(BTreeSet<storage::Key>, bool)> {
    let eth_msg_keys = eth_msgs::Keys::from(&update.body);

    // we arbitrarily look at whether the seen key is present to
    // determine if the /eth_msg already exists in storage, but maybe there
    // is a less arbitrary way to do this
    let exists_in_storage = store.has_key(&eth_msg_keys.seen())?;

    let (eth_msg, changed, newly_confirmed) = if !exists_in_storage {
        tracing::debug!(%eth_msg_keys.prefix, "Ethereum event not seen before by any validator");

        let mut seen_by_voting_power: VotingPower = VotingPower::from(0);
        for validator in &update.seen_by {
            match voting_powers.get(validator) {
                Some(voting_power) => seen_by_voting_power += *voting_power,
                None => {
                    return Err(eyre!(
                        "voting power was not provided for validator {}",
                        validator
                    ));
                }
            };
        }

        let seen_by_voting_power: u64 = seen_by_voting_power.into();
        let total_voting_power: u64 = total_voting_power.into();
        let fvp: Ratio<u64> =
            Ratio::new(seen_by_voting_power, total_voting_power);
        let newly_confirmed = fvp > threshold();
        (
            EthMsg {
                body: update.body,
                voting_power: fvp.into(),
                // the below `.collect()` is deterministic and will result in a
                // sorted vector as `update.seen_by` is a [`BTreeSet`]
                seen_by: update.seen_by.into_iter().collect(),
                seen: newly_confirmed,
            },
            (&eth_msg_keys).into_iter().collect(),
            true,
        )
    } else {
        tracing::debug!(
            %eth_msg_keys.prefix,
            "Ethereum event already exists in storage",
        );
        let body: EthereumEvent = read::value(store, &eth_msg_keys.body())?;
        let seen: bool = read::value(store, &eth_msg_keys.seen())?;
        let seen_by: Vec<Address> =
            read::value(store, &eth_msg_keys.seen_by())?;
        let voting_power: (u64, u64) =
            read::value(store, &eth_msg_keys.voting_power())?;

        let eth_msg = EthMsg {
            body,
            voting_power,
            seen_by,
            seen,
        };
        tracing::debug!("Read EthMsg - {:#?}", &eth_msg);
        calculate_diff(eth_msg, update, total_voting_power, voting_powers)
    };
    write_eth_msg(store, &eth_msg_keys, &eth_msg)?;
    Ok((changed, newly_confirmed))
}

fn calculate_diff(
    eth_msg: EthMsg,
    _update: EthMsgUpdate,
    _total_voting_power: VotingPower,
    _voting_powers: &HashMap<Address, VotingPower>,
) -> (EthMsg, BTreeSet<storage::Key>, bool) {
    tracing::warn!(
        "Updating Ethereum events is not yet implemented, so this Ethereum \
         event won't change"
    );
    (eth_msg, BTreeSet::default(), false)
}

fn threshold() -> Ratio<u64> {
    Ratio::new(2, 3)
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

    use namada::ledger::eth_bridge::storage::wrapped_erc20s;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
        arbitrary_single_transfer, arbitrary_voting_power,
    };
    use namada::types::ethereum_events::{EthereumEvent, TransferToNamada};
    use namada::types::token::Amount;

    use super::*;
    use crate::node::ledger::protocol::transactions::store::testing::FakeStorage;

    #[test]
    fn test_from_multi_signed_eth_event_for_eth_msg_update() {
        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let event = arbitrary_single_transfer(arbitrary_nonce(), receiver);
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: HashSet::from_iter(vec![sole_validator.clone()]),
        };
        let expected = EthMsgUpdate {
            body: event,
            seen_by: BTreeSet::from_iter(vec![sole_validator]),
        };

        let update: EthMsgUpdate = with_signers.into();

        assert_eq!(update, expected);
    }

    #[test]
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
        let total_voting_power = arbitrary_voting_power();
        let voting_powers = HashMap::from_iter(vec![(
            sole_validator.clone(),
            total_voting_power,
        )]);
        let mut storage = FakeStorage::default();

        let changed_keys = apply_updates(
            &mut storage,
            updates,
            total_voting_power,
            voting_powers,
        )?;

        let eth_msg_keys: eth_msgs::Keys = (&body).into();
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
