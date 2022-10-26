//! Code for handling
//! [`namada::types::transaction::protocol::ProtocolTxType::EthereumEvents`]
//! transactions.
mod eth_msgs;
mod events;

use std::collections::{BTreeSet, HashMap, HashSet};

use eth_msgs::{EthMsg, EthMsgUpdate};
use eyre::Result;
use namada::ledger::eth_bridge::storage::vote_tallies;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::types::address::Address;
use namada::types::storage::BlockHeight;
use namada::types::transaction::TxResult;
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;
use namada::types::voting_power::FractionalVotingPower;

use super::ChangedKeys;
use crate::node::ledger::protocol::transactions::utils;
use crate::node::ledger::protocol::transactions::votes::{
    calculate_new, calculate_updated, write, Votes,
};

impl utils::GetVoters for [MultiSignedEthEvent] {
    #[inline]
    fn get_voters(&self) -> HashSet<(Address, BlockHeight)> {
        self.iter().fold(HashSet::new(), |mut voters, event| {
            voters.extend(event.signers.iter().cloned());
            voters
        })
    }
}

/// Applies derived state changes to storage, based on Ethereum `events` which
/// were newly seen by some active validator(s) in the last epoch. For `events`
/// which have been seen by enough voting power, extra state changes may take
/// place, such as minting of wrapped ERC20s.
///
/// This function is deterministic based on some existing blockchain state and
/// the passed `events`.
pub(crate) fn apply_derived_tx<D, H>(
    storage: &mut Storage<D, H>,
    events: Vec<MultiSignedEthEvent>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if events.is_empty() {
        return Ok(TxResult::default());
    }
    tracing::info!(
        ethereum_events = events.len(),
        "Applying state updates derived from Ethereum events found in \
         protocol transaction"
    );

    let voting_powers = utils::get_voting_powers(storage, events.as_slice())?;

    let updates = events.into_iter().map(Into::<EthMsgUpdate>::into).collect();

    let changed_keys = apply_updates(storage, updates, voting_powers)?;

    Ok(TxResult {
        changed_keys,
        ..Default::default()
    })
}

/// Apply an Ethereum state update + act on any events which are confirmed
pub(super) fn apply_updates<D, H>(
    storage: &mut Storage<D, H>,
    updates: HashSet<EthMsgUpdate>,
    voting_powers: HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<ChangedKeys>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
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
            apply_update(storage, update.clone(), &voting_powers)?;
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
        let mut changed = events::act_on(storage, event)?;
        changed_keys.append(&mut changed);
    }
    Ok(changed_keys)
}

/// Apply an [`EthMsgUpdate`] to storage. Returns any keys changed and whether
/// the event was newly seen.
fn apply_update<D, H>(
    storage: &mut Storage<D, H>,
    update: EthMsgUpdate,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<(ChangedKeys, bool)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let eth_msg_keys = vote_tallies::Keys::from(&update.body);

    // we arbitrarily look at whether the seen key is present to
    // determine if the /eth_msg already exists in storage, but maybe there
    // is a less arbitrary way to do this
    let (exists_in_storage, _) = storage.has_key(&eth_msg_keys.seen())?;

    let mut seen_by = Votes::default();
    for (address, block_height) in update.seen_by.into_iter() {
        // TODO: more deterministic deduplication
        if let Some(present) = seen_by.insert(address, block_height) {
            tracing::warn!(?present, "Duplicate vote in digest");
        }
    }

    let (vote_tracking, changed, confirmed) = if !exists_in_storage {
        tracing::debug!(%eth_msg_keys.prefix, "Ethereum event not seen before by any validator");
        let vote_tracking = calculate_new(seen_by, voting_powers)?;
        let changed = eth_msg_keys.into_iter().collect();
        let confirmed = vote_tracking.seen;
        (vote_tracking, changed, confirmed)
    } else {
        tracing::debug!(
            %eth_msg_keys.prefix,
            "Ethereum event already exists in storage",
        );
        let mut votes = HashMap::default();
        seen_by.iter().for_each(|(address, block_height)| {
            let fvp = voting_powers
                .get(&(address.to_owned(), block_height.to_owned()))
                .unwrap();
            if let Some(already_present_fvp) =
                votes.insert(address.to_owned(), fvp.to_owned())
            {
                tracing::warn!(
                    ?address,
                    ?already_present_fvp,
                    new_fvp = ?fvp,
                    "Validator voted more than once, arbitrarily using later value",
                )
            }
        });
        let (vote_tracking, changed) =
            calculate_updated(storage, &eth_msg_keys, &votes)?;
        let confirmed =
            vote_tracking.seen && changed.contains(&eth_msg_keys.seen());
        (vote_tracking, changed, confirmed)
    };
    let eth_msg_post = EthMsg {
        body: update.body,
        votes: vote_tracking,
    };
    tracing::debug!("writing EthMsg - {:#?}", &eth_msg_post);
    write(
        storage,
        &eth_msg_keys,
        &eth_msg_post.body,
        &eth_msg_post.votes,
    )?;
    Ok((changed, confirmed))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use borsh::BorshDeserialize;
    use namada::ledger::eth_bridge::storage::wrapped_erc20s;
    use namada::ledger::pos::namada_proof_of_stake::epoched::Epoched;
    use namada::ledger::pos::namada_proof_of_stake::PosBase;
    use namada::ledger::pos::types::{ValidatorSet, WeightedValidator};
    use namada::ledger::storage::mockdb::MockDB;
    use namada::ledger::storage::testing::TestStorage;
    use namada::ledger::storage::traits::Sha256Hasher;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
        arbitrary_single_transfer, DAI_ERC20_ETH_ADDRESS,
    };
    use namada::types::ethereum_events::{EthereumEvent, TransferToNamada};
    use namada::types::token::Amount;

    use super::*;
    use crate::node::ledger::protocol::transactions::utils::GetVoters;

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
            seen_by: Votes::from([(sole_validator.clone(), BlockHeight(100))]),
        };
        let updates = HashSet::from_iter(vec![update]);
        let voting_powers = HashMap::from_iter(vec![(
            (sole_validator.clone(), BlockHeight(100)),
            FractionalVotingPower::new(1, 1).unwrap(),
        )]);
        let mut storage = TestStorage::default();

        let changed_keys = apply_updates(&mut storage, updates, voting_powers)?;

        let eth_msg_keys: vote_tallies::Keys<EthereumEvent> = (&body).into();
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

        let (body_bytes, _) = storage.read(&eth_msg_keys.body())?;
        let body_bytes = body_bytes.unwrap();
        assert_eq!(EthereumEvent::try_from_slice(&body_bytes)?, body);

        let (seen_bytes, _) = storage.read(&eth_msg_keys.seen())?;
        let seen_bytes = seen_bytes.unwrap();
        assert!(bool::try_from_slice(&seen_bytes)?);

        let (seen_by_bytes, _) = storage.read(&eth_msg_keys.seen_by())?;
        let seen_by_bytes = seen_by_bytes.unwrap();
        assert_eq!(
            Votes::try_from_slice(&seen_by_bytes)?,
            Votes::from([(sole_validator, BlockHeight(100))])
        );

        let (voting_power_bytes, _) =
            storage.read(&eth_msg_keys.voting_power())?;
        let voting_power_bytes = voting_power_bytes.unwrap();
        assert_eq!(<(u64, u64)>::try_from_slice(&voting_power_bytes)?, (1, 1));

        let (wrapped_erc20_balance_bytes, _) =
            storage.read(&wrapped_erc20_keys.balance(&receiver))?;
        let wrapped_erc20_balance_bytes = wrapped_erc20_balance_bytes.unwrap();
        assert_eq!(
            Amount::try_from_slice(&wrapped_erc20_balance_bytes)?,
            amount
        );

        let (wrapped_erc20_supply_bytes, _) =
            storage.read(&wrapped_erc20_keys.supply())?;
        let wrapped_erc20_supply_bytes = wrapped_erc20_supply_bytes.unwrap();
        assert_eq!(
            Amount::try_from_slice(&wrapped_erc20_supply_bytes)?,
            amount
        );

        Ok(())
    }

    /// Set up a `TestStorage` initialized at genesis with validators of equal
    /// power
    fn set_up_test_storage(
        active_validators: HashSet<Address>,
    ) -> Storage<MockDB, Sha256Hasher> {
        let mut storage = TestStorage::default();
        let validator_set = ValidatorSet {
            active: active_validators
                .into_iter()
                .map(|address| WeightedValidator {
                    voting_power: 100.into(),
                    address,
                })
                .collect(),
            inactive: BTreeSet::default(),
        };
        let validator_sets = Epoched::init_at_genesis(validator_set, 1);
        storage.write_validator_set(&validator_sets);
        storage
    }

    #[test]
    /// Test applying a single transfer via `apply_derived_tx`, where an event
    /// has enough voting power behind it for it to be applied at the same time
    /// that it is recorded in storage
    fn test_apply_derived_tx_new_event_mint_immediately() {
        let sole_validator = address::testing::established_address_2();
        let mut storage = set_up_test_storage(HashSet::from_iter(vec![
            sole_validator.clone(),
        ]));
        let receiver = address::testing::established_address_1();

        let event = EthereumEvent::TransfersToNamada {
            nonce: 1.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: receiver.clone(),
            }],
        };

        let result = apply_derived_tx(
            &mut storage,
            vec![MultiSignedEthEvent {
                event: event.clone(),
                signers: BTreeSet::from([(sole_validator, BlockHeight(100))]),
            }],
        );

        let tx_result = match result {
            Ok(tx_result) => tx_result,
            Err(err) => panic!("unexpected error: {:#?}", err),
        };

        assert_eq!(
            tx_result.gas_used, 0,
            "No gas should be used for a derived transaction"
        );
        let eth_msg_keys = vote_tallies::Keys::from(&event);
        let dai_keys = wrapped_erc20s::Keys::from(&DAI_ERC20_ETH_ADDRESS);
        assert_eq!(
            tx_result.changed_keys,
            BTreeSet::from_iter(vec![
                eth_msg_keys.body(),
                eth_msg_keys.seen(),
                eth_msg_keys.seen_by(),
                eth_msg_keys.voting_power(),
                dai_keys.balance(&receiver),
                dai_keys.supply(),
            ])
        );
        assert!(tx_result.vps_result.accepted_vps.is_empty());
        assert!(tx_result.vps_result.rejected_vps.is_empty());
        assert!(tx_result.vps_result.errors.is_empty());
        assert!(tx_result.initialized_accounts.is_empty());
        assert!(tx_result.ibc_event.is_none());
    }

    /// Test calling apply_derived_tx for an event that isn't backed by enough
    /// voting power to be acted on immediately
    #[test]
    fn test_apply_derived_tx_new_event_dont_mint() {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let mut storage = set_up_test_storage(HashSet::from_iter(vec![
            validator_a.clone(),
            validator_b,
        ]));
        let receiver = address::testing::established_address_1();

        let event = EthereumEvent::TransfersToNamada {
            nonce: 1.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver,
            }],
        };

        let result = apply_derived_tx(
            &mut storage,
            vec![MultiSignedEthEvent {
                event: event.clone(),
                signers: BTreeSet::from([(validator_a, BlockHeight(100))]),
            }],
        );
        let tx_result = match result {
            Ok(tx_result) => tx_result,
            Err(err) => panic!("unexpected error: {:#?}", err),
        };

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        assert_eq!(
            tx_result.changed_keys,
            BTreeSet::from_iter(vec![
                eth_msg_keys.body(),
                eth_msg_keys.seen(),
                eth_msg_keys.seen_by(),
                eth_msg_keys.voting_power(),
            ]),
            "The Ethereum event should have been recorded, but no minting \
             should have happened yet as it has only been seen by 1/2 the \
             voting power so far"
        );
    }

    #[test]
    /// Assert we don't return anything if we try to get the votes for an empty
    /// vec of events
    pub fn test_get_votes_for_events_empty() {
        let events = vec![];
        assert!(events.as_slice().get_voters().is_empty());
    }

    #[test]
    /// Test that we correctly get the votes from a vec of events
    pub fn test_get_votes_for_events() {
        let events = vec![
            MultiSignedEthEvent {
                event: arbitrary_single_transfer(
                    1.into(),
                    address::testing::established_address_1(),
                ),
                signers: BTreeSet::from([
                    (
                        address::testing::established_address_1(),
                        BlockHeight(100),
                    ),
                    (
                        address::testing::established_address_2(),
                        BlockHeight(102),
                    ),
                ]),
            },
            MultiSignedEthEvent {
                event: arbitrary_single_transfer(
                    2.into(),
                    address::testing::established_address_2(),
                ),
                signers: BTreeSet::from([
                    (
                        address::testing::established_address_1(),
                        BlockHeight(101),
                    ),
                    (
                        address::testing::established_address_3(),
                        BlockHeight(100),
                    ),
                ]),
            },
        ];
        let voters = events.as_slice().get_voters();
        assert_eq!(
            voters,
            HashSet::from_iter(vec![
                (address::testing::established_address_1(), BlockHeight(100)),
                (address::testing::established_address_1(), BlockHeight(101)),
                (address::testing::established_address_2(), BlockHeight(102)),
                (address::testing::established_address_3(), BlockHeight(100))
            ])
        )
    }
}
