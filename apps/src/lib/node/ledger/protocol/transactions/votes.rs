//! Logic and data types relating to tracking validators' votes for pieces of
//! data stored in the ledger, where those pieces of data should only be acted
//! on once they have received enough votes
use std::collections::{BTreeSet, HashMap};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};
use namada::ledger::eth_bridge::storage::vote_tracked;
use namada::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada::types::address::Address;
use namada::types::storage::{BlockHeight, Key};
use namada::types::voting_power::FractionalVotingPower;

use crate::node::ledger::protocol::transactions::read;

/// The keys changed while applying a protocol transaction
type ChangedKeys = BTreeSet<Key>;

#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
/// Represents all the information needed to track a piece of data that may be
/// voted for over multiple epochs
pub struct VoteTracking {
    /// The total voting power that's voted for this event across all epochs
    pub voting_power: FractionalVotingPower,
    /// The addresses of validators that voted for this event. We use a
    /// set type as validators should only be able to vote at most once,
    /// and [`BTreeSet`] specifically as we want this field to be
    /// deterministically ordered for storage.
    pub seen_by: BTreeSet<Address>,
    /// Whether this event has been acted on or not - this should only ever
    /// transition from `false` to `true`, once there is enough voting power
    pub seen: bool,
}

// TODO: refactor accept just votes
pub fn calculate_new(
    seen_by: &BTreeSet<(Address, BlockHeight)>,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<VoteTracking> {
    let mut seen_by_voting_power = FractionalVotingPower::default();
    for (validator, block_height) in seen_by {
        match voting_powers
            .get(&(validator.to_owned(), block_height.to_owned()))
        {
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
    Ok(VoteTracking {
        voting_power: seen_by_voting_power,
        seen_by: seen_by
            .iter()
            .map(|(validator, _)| validator.to_owned())
            .collect(),
        seen: newly_confirmed,
    })
}

pub fn calculate_updated<D, H, T>(
    store: &mut Storage<D, H>,
    keys: &vote_tracked::Keys<T>,
    votes: &HashMap<Address, FractionalVotingPower>,
) -> Result<(VoteTracking, ChangedKeys)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    let seen: bool = read::value(store, &keys.seen())?;
    let seen_by: BTreeSet<Address> = read::value(store, &keys.seen_by())?;
    let voting_power: FractionalVotingPower =
        read::value(store, &keys.voting_power())?;

    let vote_tracking_pre = VoteTracking {
        voting_power,
        seen_by,
        seen,
    };
    let vote_tracking_post = calculate_update(keys, &vote_tracking_pre, &votes);
    let changed_keys =
        validate_update(keys, &vote_tracking_pre, &vote_tracking_post)?;

    tracing::warn!(
        ?vote_tracking_pre,
        ?vote_tracking_post,
        "Calculated and validated vote tracking updates",
    );
    Ok((vote_tracking_post, changed_keys))
}

/// Takes an existing [`EthMsg`] and calculates the new [`EthMsg`] based on new
/// validators which have seen it. `voting_powers` should map validators who
/// have newly seen the event to their fractional voting power at a block height
/// at which they saw the event.
fn calculate_update<T>(
    keys: &vote_tracked::Keys<T>,
    vote_tracking_pre: &VoteTracking,
    votes: &HashMap<Address, FractionalVotingPower>,
) -> VoteTracking {
    let voters: BTreeSet<Address> = votes.keys().cloned().collect();

    // For any event and validator, only the first vote by that validator for
    // that event counts, later votes we encounter here can just be ignored. We
    // can warn here when we encounter duplicate votes but these are
    // reasonably likely to occur so this perhaps shouldn't be a warning unless
    // it is happening a lot
    for validator in vote_tracking_pre.seen_by.intersection(&voters) {
        tracing::warn!(
            ?keys.prefix,
            ?validator,
            "Encountered duplicate vote for an event by a validator, ignoring"
        );
    }
    let mut voting_power_post = vote_tracking_pre.voting_power.clone();
    let mut seen_by_post = vote_tracking_pre.seen_by.clone();
    for validator in voters.difference(&vote_tracking_pre.seen_by) {
        tracing::info!(
            ?keys.prefix,
            ?validator,
            "Recording validator as having voted for this event"
        );
        seen_by_post.insert(validator.to_owned());
        voting_power_post += votes.get(validator).expect(
            "voting powers map must have all validators from newly_seen_by",
        );
    }

    let seen_post = if voting_power_post > FractionalVotingPower::TWO_THIRDS {
        tracing::info!(
            ?keys.prefix,
            "Event has been seen by a quorum of validators",
        );
        true
    } else {
        tracing::debug!(
            ?keys.prefix,
            "Event is not yet seen by a quorum of validators",
        );
        false
    };

    VoteTracking {
        voting_power: voting_power_post,
        seen_by: seen_by_post,
        seen: seen_post,
    }
}

/// Validates that `post` is an updated version of `pre`, and returns keys which
/// changed. This function serves as a sort of validity predicate for this
/// native transaction, which is otherwise not checked by anything else.
fn validate_update<T>(
    keys: &vote_tracked::Keys<T>,
    pre: &VoteTracking,
    post: &VoteTracking,
) -> Result<ChangedKeys> {
    let mut keys_changed = ChangedKeys::default();

    let mut seen = false;
    if pre.seen != post.seen {
        // the only valid transition for `seen` is from `false` to `true`
        if pre.seen == true || post.seen == false {
            return Err(eyre!(
                "VoteTracking seen changed from {:#?} to {:#?}",
                &pre.seen,
                &post.seen,
            ));
        }
        keys_changed.insert(keys.seen());
        seen = true;
    }

    if pre.seen_by != post.seen_by {
        // if seen_by changes, it must be a strict superset of the previous
        // seen_by
        if !post.seen_by.is_superset(&pre.seen_by) {
            return Err(eyre!(
                "VoteTracking seen changed from {:#?} to {:#?}",
                &pre.seen_by,
                &post.seen_by,
            ));
        }
        keys_changed.insert(keys.seen_by());
    }

    if pre.voting_power != post.voting_power {
        // if voting_power changes, it must have increased
        if pre.voting_power >= post.voting_power {
            return Err(eyre!(
                "VoteTracking voting_power changed from {:#?} to {:#?}",
                &pre.voting_power,
                &post.voting_power,
            ));
        }
        keys_changed.insert(keys.voting_power());
    }

    if post.voting_power > FractionalVotingPower::TWO_THIRDS && !seen {
        if pre.voting_power >= post.voting_power {
            return Err(eyre!(
                "VoteTracking is not seen even though new voting_power is \
                 enough: {:#?}",
                &post.voting_power,
            ));
        }
    }

    Ok(keys_changed)
}

pub fn write<D, H, T>(
    storage: &mut Storage<D, H>,
    keys: &vote_tracked::Keys<T>,
    body: &T,
    vote_tracking: &VoteTracking,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshSerialize,
{
    storage.write(&keys.body(), &body.try_to_vec()?)?;
    storage.write(&keys.seen(), &vote_tracking.seen.try_to_vec()?)?;
    storage.write(&keys.seen_by(), &vote_tracking.seen_by.try_to_vec()?)?;
    storage.write(
        &keys.voting_power(),
        &vote_tracking.voting_power.try_to_vec()?,
    )?;
    Ok(())
}
