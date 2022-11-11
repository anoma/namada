//! Logic and data types relating to tallying validators' votes for pieces of
//! data stored in the ledger, where those pieces of data should only be acted
//! on once they have received enough votes
use std::collections::{BTreeMap, BTreeSet, HashMap};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};

use super::ChangedKeys;
use crate::ledger::eth_bridge::storage::vote_tallies;
use crate::ledger::protocol::transactions::read;
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, Storage, DB};
use crate::types::address::Address;
use crate::types::storage::BlockHeight;
use crate::types::voting_power::FractionalVotingPower;

pub(super) mod storage;

/// The addresses of validators that voted for something, and the block
/// heights at which they voted. We use a [`BTreeMap`] to enforce that a
/// validator (as uniquely identified by an [`Address`]) may vote at most once,
/// and their vote must be associated with a specific [`BlockHeight`]. Their
/// voting power at that block height is what is used when calculating whether
/// something has enough voting power behind it or not.
pub type Votes = BTreeMap<Address, BlockHeight>;

#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
/// Represents all the information needed to tally a piece of data that may be
/// voted for over multiple epochs
pub struct Tally {
    /// The total voting power that's voted for this event across all epochs
    pub voting_power: FractionalVotingPower,
    /// The votes which have been counted towards `voting_power`. Note that
    /// validators may submit multiple votes at different block heights for
    /// the same thing, but ultimately only one vote per validator will be
    /// used when tallying voting power.
    pub seen_by: Votes,
    /// Whether this event has been acted on or not - this should only ever
    /// transition from `false` to `true`, once there is enough voting power
    pub seen: bool,
}

/// Calculate a new [`Tally`] based on some validators' fractional voting powers
/// as specific block heights
pub fn calculate_new(
    seen_by: Votes,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<Tally> {
    let mut seen_by_voting_power = FractionalVotingPower::default();
    for (validator, block_height) in seen_by.iter() {
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
    Ok(Tally {
        voting_power: seen_by_voting_power,
        seen_by,
        seen: newly_confirmed,
    })
}

pub(super) struct VoteInfo {
    inner: HashMap<Address, (BlockHeight, FractionalVotingPower)>,
}

impl VoteInfo {
    pub fn new(
        votes: Votes,
        voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
    ) -> Self {
        let mut inner = HashMap::default();
        votes.into_iter().for_each(|(address, block_height)| {
            let fract_voting_power =
                voting_powers.get(&(address.clone(), block_height)).unwrap();
            if let Some((
                already_present_block_height,
                already_present_fract_voting_power,
            )) = inner.insert(
                address.clone(),
                (block_height, fract_voting_power.to_owned()),
            ) {
                tracing::warn!(
                    ?address,
                    ?already_present_block_height,
                    ?already_present_fract_voting_power,
                    new_fract_voting_power = ?fract_voting_power,
                    "Validator voted more than once, arbitrarily using later value"
                )
            }
        });
        Self { inner }
    }

    pub fn voters(&self) -> BTreeSet<Address> {
        self.inner.keys().cloned().collect()
    }

    pub fn get_vote_height(&self, validator: &Address) -> BlockHeight {
        // TODO: don't unwrap
        self.inner.get(validator).unwrap().0
    }

    pub fn get_vote_power(&self, validator: &Address) -> FractionalVotingPower {
        // TODO: don't unwrap
        self.inner.get(validator).unwrap().1.clone()
    }
}

/// Calculate an updated [`Tally`] based on one that is in storage under `keys`,
/// with some new `voters`.
pub(super) fn calculate_updated<D, H, T>(
    store: &mut Storage<D, H>,
    keys: &vote_tallies::Keys<T>,
    vote_info: &VoteInfo,
) -> Result<(Tally, ChangedKeys)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    let seen: bool = read::value(store, &keys.seen())?;
    let seen_by: Votes = read::value(store, &keys.seen_by())?;
    let voting_power: FractionalVotingPower =
        read::value(store, &keys.voting_power())?;

    let tally_pre = Tally {
        voting_power,
        seen_by,
        seen,
    };
    let tally_post = calculate_update(keys, &tally_pre, vote_info);
    let changed_keys = validate_update(keys, &tally_pre, &tally_post)?;

    tracing::warn!(
        ?tally_pre,
        ?tally_post,
        "Calculated and validated vote tracking updates",
    );
    Ok((tally_post, changed_keys))
}

/// Takes an existing [`Tally`] and calculates the new [`Tally`] based on new
/// validators which have seen it. `voting_powers` should map validators who
/// have newly seen the event to their fractional voting power at a block height
/// at which they saw the event.
fn calculate_update<T>(
    keys: &vote_tallies::Keys<T>,
    pre: &Tally,
    vote_info: &VoteInfo,
) -> Tally {
    let new_voters: BTreeSet<Address> = vote_info.voters();

    // For any event and validator, only the first vote by that validator for
    // that event counts, later votes we encounter here can just be ignored. We
    // can warn here when we encounter duplicate votes but these are
    // reasonably likely to occur so this perhaps shouldn't be a warning unless
    // it is happening a lot
    let already_voted: BTreeSet<_> = pre.seen_by.keys().cloned().collect();
    for validator in already_voted.intersection(&new_voters) {
        tracing::warn!(
            ?keys.prefix,
            ?validator,
            "Encountered duplicate vote for an event by a validator, ignoring"
        );
    }

    let mut voting_power_post = pre.voting_power.clone();
    let mut seen_by_post = pre.seen_by.clone();
    for validator in new_voters.difference(&already_voted) {
        tracing::info!(
            ?keys.prefix,
            ?validator,
            "Recording validator as having voted for this event"
        );
        seen_by_post
            .insert(validator.to_owned(), vote_info.get_vote_height(validator));
        voting_power_post += vote_info.get_vote_power(validator);
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

    Tally {
        voting_power: voting_power_post,
        seen_by: seen_by_post,
        seen: seen_post,
    }
}

/// Validates that `post` is an updated version of `pre`, and returns keys which
/// changed. This function serves as a sort of validity predicate for this
/// native transaction, which is otherwise not checked by anything else.
fn validate_update<T>(
    keys: &vote_tallies::Keys<T>,
    pre: &Tally,
    post: &Tally,
) -> Result<ChangedKeys> {
    let mut keys_changed = ChangedKeys::default();

    let mut seen = false;
    if pre.seen != post.seen {
        // the only valid transition for `seen` is from `false` to `true`
        if pre.seen || !post.seen {
            return Err(eyre!(
                "Tally seen changed from {:#?} to {:#?}",
                &pre.seen,
                &post.seen,
            ));
        }
        keys_changed.insert(keys.seen());
        seen = true;
    }
    let pre_seen_by: BTreeSet<_> = pre.seen_by.keys().cloned().collect();
    let post_seen_by: BTreeSet<_> = post.seen_by.keys().cloned().collect();

    if pre_seen_by != post_seen_by {
        // if seen_by changes, it must be a strict superset of the previous
        // seen_by
        if !post_seen_by.is_superset(&pre_seen_by) {
            return Err(eyre!(
                "Tally seen changed from {:#?} to {:#?}",
                &pre_seen_by,
                &post_seen_by,
            ));
        }
        keys_changed.insert(keys.seen_by());
    }

    if pre.voting_power != post.voting_power {
        // if voting_power changes, it must have increased
        if pre.voting_power >= post.voting_power {
            return Err(eyre!(
                "Tally voting_power changed from {:#?} to {:#?}",
                &pre.voting_power,
                &post.voting_power,
            ));
        }
        keys_changed.insert(keys.voting_power());
    }

    if post.voting_power > FractionalVotingPower::TWO_THIRDS
        && !seen
        && pre.voting_power >= post.voting_power
    {
        return Err(eyre!(
            "Tally is not seen even though new voting_power is enough: {:#?}",
            &post.voting_power,
        ));
    }

    Ok(keys_changed)
}

/// Deterministically constructs a [`Votes`] map from a set of validator
/// addresses and the block heights they signed something at. We arbitrarily
/// take the earliest block height for each validator address encountered.
pub fn dedupe(signers: BTreeSet<(Address, BlockHeight)>) -> Votes {
    signers.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::types::address;
    use crate::types::storage::BlockHeight;

    #[test]
    fn test_dedupe_empty() {
        let signers = BTreeSet::new();

        let deduped = dedupe(signers);

        assert_eq!(deduped, Votes::new());
    }

    #[test]
    fn test_dedupe_single_vote() {
        let sole_validator = address::testing::established_address_1();
        let votes = [(sole_validator, BlockHeight(100))];
        let signers = BTreeSet::from(votes.clone());

        let deduped = dedupe(signers);

        assert_eq!(deduped, Votes::from(votes));
    }

    #[test]
    fn test_dedupe_multiple_votes_same_voter() {
        let sole_validator = address::testing::established_address_1();
        let earliest_vote_height = 100;
        let earliest_vote =
            (sole_validator.clone(), BlockHeight(earliest_vote_height));
        let votes = [
            earliest_vote.clone(),
            (
                sole_validator.clone(),
                BlockHeight(earliest_vote_height + 1),
            ),
            (sole_validator, BlockHeight(earliest_vote_height + 100)),
        ];
        let signers = BTreeSet::from(votes);

        let deduped = dedupe(signers);

        assert_eq!(deduped, Votes::from([earliest_vote]));
    }

    #[test]
    fn test_dedupe_multiple_votes_multiple_voters() {
        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();
        let validator_1_earliest_vote_height = 100;
        let validator_1_earliest_vote = (
            validator_1.clone(),
            BlockHeight(validator_1_earliest_vote_height),
        );
        let validator_2_earliest_vote_height = 200;
        let validator_2_earliest_vote = (
            validator_2.clone(),
            BlockHeight(validator_2_earliest_vote_height),
        );
        let votes = [
            validator_1_earliest_vote.clone(),
            (
                validator_1.clone(),
                BlockHeight(validator_1_earliest_vote_height + 1),
            ),
            (
                validator_1,
                BlockHeight(validator_1_earliest_vote_height + 100),
            ),
            validator_2_earliest_vote.clone(),
            (
                validator_2.clone(),
                BlockHeight(validator_2_earliest_vote_height + 1),
            ),
            (
                validator_2,
                BlockHeight(validator_2_earliest_vote_height + 100),
            ),
        ];
        let signers = BTreeSet::from(votes);

        let deduped = dedupe(signers);

        assert_eq!(
            deduped,
            Votes::from([validator_1_earliest_vote, validator_2_earliest_vote])
        );
    }
}
