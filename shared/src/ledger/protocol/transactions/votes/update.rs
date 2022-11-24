use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::BorshDeserialize;
use eyre::{eyre, Result};

use super::{ChangedKeys, Tally, Votes};
use crate::ledger::eth_bridge::storage::vote_tallies;
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, Storage, DB};
use crate::types::address::Address;
use crate::types::storage::BlockHeight;
use crate::types::voting_power::FractionalVotingPower;

/// Wraps all the information about new votes to be applied to some existing
/// tally in storage.
pub(in super::super) struct NewVotes {
    inner: HashMap<Address, (BlockHeight, FractionalVotingPower)>,
}

impl NewVotes {
    /// Constructs a new [`NewVotes`]. For all `votes` provided, a corresponding
    /// [`FractionalVotingPower`] must be provided in `voting_powers` also,
    /// otherwise an error will be returned.
    pub fn new(
        votes: Votes,
        voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
    ) -> Result<Self> {
        let mut inner = HashMap::default();
        for (address, block_height) in votes {
            let fract_voting_power = match voting_powers
                .get(&(address.clone(), block_height))
            {
                Some(fract_voting_power) => fract_voting_power,
                None => {
                    return Err(eyre!(
                        "No fractional voting power provided for vote by \
                         validator {address} at block height {block_height}"
                    ));
                }
            };
            _ = inner
                .insert(address, (block_height, fract_voting_power.to_owned()));
        }
        Ok(Self { inner })
    }

    pub fn voters(&self) -> BTreeSet<Address> {
        self.inner.keys().cloned().collect()
    }

    /// Consumes `self` and returns a [`NewVotes`] with any addresses from
    /// `voters` removed, as well as the set of addresses that were actually
    /// removed. Useful for removing voters who have already voted for
    /// something.
    pub fn without_voters<'a>(
        self,
        voters: impl IntoIterator<Item = &'a Address>,
    ) -> (Self, HashSet<&'a Address>) {
        let mut inner = self.inner;
        let mut removed = HashSet::default();
        for voter in voters {
            inner.remove(voter);
            removed.insert(voter);
        }
        (Self { inner }, removed)
    }
}

impl IntoIterator for NewVotes {
    type IntoIter = std::collections::hash_set::IntoIter<Self::Item>;
    type Item = (Address, BlockHeight, FractionalVotingPower);

    fn into_iter(self) -> Self::IntoIter {
        let items: HashSet<_> = self
            .inner
            .into_iter()
            .map(|(address, (block_height, fract_voting_power))| {
                (address, block_height, fract_voting_power)
            })
            .collect();
        items.into_iter()
    }
}

/// Calculate an updated [`Tally`] based on one that is in storage under `keys`,
/// with new votes from `vote_info` applied, as well as the storage keys that
/// would change. If [`Tally`] is already `seen = true` in storage, then no
/// votes from `vote_info` should be applied, and the returned changed keys will
/// be empty.
pub(in super::super) fn calculate<D, H, T>(
    store: &mut Storage<D, H>,
    keys: &vote_tallies::Keys<T>,
    vote_info: NewVotes,
) -> Result<(Tally, ChangedKeys)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: BorshDeserialize,
{
    tracing::info!(
        ?keys.prefix,
        validators = ?vote_info.voters(),
        "Calculating validators' votes applied to an existing tally"
    );
    let tally_pre = super::storage::read(store, keys)?;
    if tally_pre.seen {
        return Ok((tally_pre, ChangedKeys::default()));
    }

    let (vote_info, duplicate_voters) =
        vote_info.without_voters(tally_pre.seen_by.keys());
    for voter in duplicate_voters {
        tracing::info!(
            ?keys.prefix,
            ?voter,
            "Ignoring duplicate voter"
        );
    }
    let tally_post = apply(&tally_pre, vote_info)
        .expect("We deduplicated voters already, so this should never error");

    let changed_keys = keys_changed(keys, &tally_pre, &tally_post);

    if tally_post.seen {
        tracing::info!(
            ?keys.prefix,
            "Tally has been seen by a quorum of validators",
        );
    } else {
        tracing::debug!(
            ?keys.prefix,
            "Tally is not yet seen by a quorum of validators",
        );
    };

    tracing::debug!(
        ?tally_pre,
        ?tally_post,
        "Calculated and validated vote tracking updates",
    );
    Ok((tally_post, changed_keys))
}

/// Takes an existing [`Tally`] and calculates the new [`Tally`] based on new
/// voters from `vote_info`. An error is returned if any validator which
/// previously voted is present in `vote_info`.
fn apply(tally: &Tally, vote_info: NewVotes) -> Result<Tally> {
    let mut voting_power_post = tally.voting_power.clone();
    let mut seen_by_post = tally.seen_by.clone();
    for (validator, vote_height, voting_power) in vote_info {
        if let Some(already_voted_height) =
            seen_by_post.insert(validator.clone(), vote_height)
        {
            return Err(eyre!(
                "Validator {validator} had already voted at height \
                 {already_voted_height}",
            ));
        };
        voting_power_post += voting_power;
    }

    let seen_post = voting_power_post > FractionalVotingPower::TWO_THIRDS;

    Ok(Tally {
        voting_power: voting_power_post,
        seen_by: seen_by_post,
        seen: seen_post,
    })
}

/// Straightforwardly calculates the keys that changed between `pre` and `post`.
fn keys_changed<T>(
    keys: &vote_tallies::Keys<T>,
    pre: &Tally,
    post: &Tally,
) -> ChangedKeys {
    let mut changed_keys = ChangedKeys::default();
    if pre.seen != post.seen {
        changed_keys.insert(keys.seen());
    };
    if pre.voting_power != post.voting_power {
        changed_keys.insert(keys.voting_power());
    };
    if pre.seen_by != post.seen_by {
        changed_keys.insert(keys.seen_by());
    };
    changed_keys
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::ledger::protocol::transactions::votes;
    use crate::ledger::protocol::transactions::votes::update::tests::helpers::{arbitrary_event, setup_tally};
    use crate::ledger::storage::testing::TestStorage;
    use crate::types::address;
    use crate::types::ethereum_events::EthereumEvent;

    mod helpers {
        use super::*;

        /// Returns an arbitrary piece of data that can have votes tallied
        /// against it.
        pub(super) fn arbitrary_event() -> EthereumEvent {
            EthereumEvent::TransfersToNamada {
                nonce: 0.into(),
                transfers: vec![],
            }
        }

        /// Writes an initial [`Tally`] to storage, based on the passed `votes`.
        pub(super) fn setup_tally(
            storage: &mut TestStorage,
            event: &EthereumEvent,
            keys: &vote_tallies::Keys<EthereumEvent>,
            votes: HashSet<(Address, BlockHeight, FractionalVotingPower)>,
        ) -> Result<Tally> {
            let voting_power: FractionalVotingPower =
                votes.iter().cloned().map(|(_, _, v)| v).sum();
            let tally = Tally {
                voting_power: voting_power.to_owned(),
                seen_by: votes.into_iter().map(|(a, h, _)| (a, h)).collect(),
                seen: voting_power > FractionalVotingPower::TWO_THIRDS,
            };
            votes::storage::write(storage, keys, event, &tally)?;
            Ok(tally)
        }
    }

    #[test]
    fn test_vote_info_new_empty() -> Result<()> {
        let voting_powers = HashMap::default();

        let vote_info = NewVotes::new(Votes::default(), &voting_powers)?;

        assert!(vote_info.voters().is_empty());
        assert_eq!(vote_info.into_iter().count(), 0);
        Ok(())
    }

    #[test]
    fn test_vote_info_new_single_voter() -> Result<()> {
        let validator = address::testing::established_address_1();
        let vote_height = BlockHeight(100);
        let voting_power = FractionalVotingPower::new(1, 3)?;
        let vote = (validator.clone(), vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote, voting_power.clone())]);

        let vote_info = NewVotes::new(votes, &voting_powers)?;

        assert_eq!(vote_info.voters(), BTreeSet::from([validator.clone()]));
        let votes: BTreeSet<_> = vote_info.into_iter().collect();
        assert_eq!(
            votes,
            BTreeSet::from([(validator, vote_height, voting_power,)]),
        );
        Ok(())
    }

    #[test]
    fn test_vote_info_new_error() -> Result<()> {
        let votes = Votes::from([(
            address::testing::established_address_1(),
            BlockHeight(100),
        )]);
        let voting_powers = HashMap::default();

        let result = NewVotes::new(votes, &voting_powers);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_vote_info_without_voters() -> Result<()> {
        let validator = address::testing::established_address_1();
        let vote_height = BlockHeight(100);
        let voting_power = FractionalVotingPower::new(1, 3)?;
        let vote = (validator.clone(), vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote, voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (vote_info, removed) = vote_info.without_voters(vec![&validator]);

        assert!(vote_info.voters().is_empty());
        assert_eq!(removed, HashSet::from([&validator]));
        Ok(())
    }

    #[test]
    fn test_apply_duplicate_votes() -> Result<()> {
        let mut storage = TestStorage::default();

        let validator = address::testing::established_address_1();
        let already_voted_height = BlockHeight(100);

        let event = arbitrary_event();
        let keys = vote_tallies::Keys::from(&event);
        let tally_pre = setup_tally(
            &mut storage,
            &event,
            &keys,
            HashSet::from([(
                validator.clone(),
                already_voted_height,
                FractionalVotingPower::new(1, 3)?,
            )]),
        )?;

        let votes = Votes::from([(validator.clone(), BlockHeight(1000))]);
        let voting_powers = HashMap::from([(
            (validator, BlockHeight(1000)),
            FractionalVotingPower::new(1, 3)?,
        )]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let result = apply(&tally_pre, vote_info);

        assert!(result.is_err());
        Ok(())
    }

    /// Tests that an unchanged tally is returned if the tally as in storage is
    /// already recorded as having been seen.
    #[test]
    fn test_calculate_already_seen() -> Result<()> {
        let mut storage = TestStorage::default();
        let event = arbitrary_event();
        let keys = vote_tallies::Keys::from(&event);
        let tally_pre = setup_tally(
            &mut storage,
            &event,
            &keys,
            HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                FractionalVotingPower::new(3, 4)?, // this is > 2/3
            )]),
        )?;

        let validator = address::testing::established_address_2();
        let vote_height = BlockHeight(100);
        let voting_power = FractionalVotingPower::new(1, 3)?;
        let vote = (validator, vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote, voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (tally_post, changed_keys) =
            calculate(&mut storage, &keys, vote_info)?;

        assert_eq!(tally_post, tally_pre);
        assert!(changed_keys.is_empty());
        Ok(())
    }

    /// Tests that an unchanged tally is returned if no votes are passed.
    #[test]
    fn test_calculate_empty() -> Result<()> {
        let mut storage = TestStorage::default();
        let event = arbitrary_event();
        let keys = vote_tallies::Keys::from(&event);
        let tally_pre = setup_tally(
            &mut storage,
            &event,
            &keys,
            HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                FractionalVotingPower::new(1, 3)?,
            )]),
        )?;
        votes::storage::write(&mut storage, &keys, &event, &tally_pre)?;
        let vote_info = NewVotes::new(Votes::default(), &HashMap::default())?;

        let (tally_post, changed_keys) =
            calculate(&mut storage, &keys, vote_info)?;

        assert_eq!(tally_post, tally_pre);
        assert!(changed_keys.is_empty());
        Ok(())
    }

    /// Tests the case where a single vote is applied, and the tally is still
    /// not yet seen.
    #[test]
    fn test_calculate_one_vote_not_seen() -> Result<()> {
        let mut storage = TestStorage::default();

        let event = arbitrary_event();
        let keys = vote_tallies::Keys::from(&event);
        let tally_pre = setup_tally(
            &mut storage,
            &event,
            &keys,
            HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                FractionalVotingPower::new(1, 3)?,
            )]),
        )?;
        votes::storage::write(&mut storage, &keys, &event, &tally_pre)?;

        let validator = address::testing::established_address_2();
        let vote_height = BlockHeight(100);
        let voting_power = FractionalVotingPower::new(1, 3)?;
        let vote = (validator, vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote.clone(), voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (tally_post, changed_keys) =
            calculate(&mut storage, &keys, vote_info)?;

        assert_eq!(
            tally_post,
            Tally {
                voting_power: FractionalVotingPower::new(2, 3)?,
                seen_by: BTreeMap::from([
                    (address::testing::established_address_1(), 10.into()),
                    vote,
                ]),
                seen: false,
            }
        );
        assert_eq!(
            changed_keys,
            BTreeSet::from([keys.voting_power(), keys.seen_by()])
        );
        Ok(())
    }

    /// Tests the case where a single vote is applied, and the tally is now
    /// seen.
    #[test]
    fn test_calculate_one_vote_seen() -> Result<()> {
        let mut storage = TestStorage::default();

        let event = arbitrary_event();
        let keys = vote_tallies::Keys::from(&event);
        let tally_pre = setup_tally(
            &mut storage,
            &event,
            &keys,
            HashSet::from([(
                address::testing::established_address_1(),
                BlockHeight(10),
                FractionalVotingPower::new(1, 3)?,
            )]),
        )?;
        votes::storage::write(&mut storage, &keys, &event, &tally_pre)?;

        let validator = address::testing::established_address_2();
        let vote_height = BlockHeight(100);
        let voting_power = FractionalVotingPower::new(2, 3)?;
        let vote = (validator, vote_height);
        let votes = Votes::from([vote.clone()]);
        let voting_powers = HashMap::from([(vote.clone(), voting_power)]);
        let vote_info = NewVotes::new(votes, &voting_powers)?;

        let (tally_post, changed_keys) =
            calculate(&mut storage, &keys, vote_info)?;

        assert_eq!(
            tally_post,
            Tally {
                voting_power: FractionalVotingPower::new(1, 1)?,
                seen_by: BTreeMap::from([
                    (address::testing::established_address_1(), 10.into()),
                    vote,
                ]),
                seen: true,
            }
        );
        assert_eq!(
            changed_keys,
            BTreeSet::from([keys.voting_power(), keys.seen_by(), keys.seen()])
        );
        Ok(())
    }

    #[test]
    fn test_keys_changed_all() -> Result<()> {
        let voting_power_a = FractionalVotingPower::new(1, 3)?;
        let voting_power_b = FractionalVotingPower::new(2, 3)?;

        let seen_a = false;
        let seen_b = true;

        let seen_by_a = BTreeMap::from([(
            address::testing::established_address_1(),
            BlockHeight(10),
        )]);
        let seen_by_b = BTreeMap::from([(
            address::testing::established_address_2(),
            BlockHeight(20),
        )]);

        let event = arbitrary_event();
        let keys = vote_tallies::Keys::from(&event);
        let pre = Tally {
            voting_power: voting_power_a,
            seen: seen_a,
            seen_by: seen_by_a,
        };
        let post = Tally {
            voting_power: voting_power_b,
            seen: seen_b,
            seen_by: seen_by_b,
        };
        let changed_keys = keys_changed(&keys, &pre, &post);

        assert_eq!(
            changed_keys,
            BTreeSet::from([keys.seen(), keys.seen_by(), keys.voting_power()])
        );
        Ok(())
    }

    #[test]
    fn test_keys_changed_none() -> Result<()> {
        let voting_power = FractionalVotingPower::new(1, 3)?;
        let seen = false;
        let seen_by = BTreeMap::from([(
            address::testing::established_address_1(),
            BlockHeight(10),
        )]);

        let event = arbitrary_event();
        let keys = vote_tallies::Keys::from(&event);
        let pre = Tally {
            voting_power,
            seen,
            seen_by,
        };
        let post = pre.clone();
        let changed_keys = keys_changed(&keys, &pre, &post);

        assert!(changed_keys.is_empty());
        Ok(())
    }
}
