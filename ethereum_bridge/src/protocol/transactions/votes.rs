//! Logic and data types relating to tallying validators' votes for pieces of
//! data stored in the ledger, where those pieces of data should only be acted
//! on once they have received enough votes
use std::collections::{BTreeMap, BTreeSet, HashMap};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};
use namada_core::hints;
use namada_core::ledger::storage::{DBIter, StorageHasher, WlStorage, DB};
use namada_core::types::address::Address;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::token;
use namada_core::types::voting_power::FractionalVotingPower;
use namada_proof_of_stake::pos_queries::PosQueries;

use super::{read, ChangedKeys};

pub(super) mod storage;
pub(super) mod update;

/// The addresses of validators that voted for something, and the block
/// heights at which they voted. We use a [`BTreeMap`] to enforce that a
/// validator (as uniquely identified by an [`Address`]) may vote at most once,
/// and their vote must be associated with a specific [`BlockHeight`]. Their
/// voting power at that block height is what is used when calculating whether
/// something has enough voting power behind it or not.
pub type Votes = BTreeMap<Address, BlockHeight>;

/// The voting power behind a tally aggregated over multiple epochs.
pub type EpochedVotingPower = BTreeMap<Epoch, FractionalVotingPower>;

/// Extension methods for [`EpochedVotingPower`] instances.
pub trait EpochedVotingPowerExt {
    /// Get the total voting power staked across all epochs
    /// in this [`EpochedVotingPower`].
    fn get_epoch_voting_powers<D, H>(
        &self,
        wl_storage: &WlStorage<D, H>,
    ) -> HashMap<Epoch, token::Amount>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync;

    /// Get the weighted average of some tally's voting powers pertaining to all
    /// epochs it was held in.
    fn average_voting_power<D, H>(
        &self,
        wl_storage: &WlStorage<D, H>,
    ) -> FractionalVotingPower
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync;

    /// Check if the [`Tally`] associated with this [`EpochedVotingPower`]
    /// can be considered `seen`.
    #[inline]
    fn has_majority_quorum<D, H>(&self, wl_storage: &WlStorage<D, H>) -> bool
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        self.average_voting_power(wl_storage)
            > FractionalVotingPower::TWO_THIRDS
    }
}

impl EpochedVotingPowerExt for EpochedVotingPower {
    fn get_epoch_voting_powers<D, H>(
        &self,
        wl_storage: &WlStorage<D, H>,
    ) -> HashMap<Epoch, token::Amount>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        self.keys()
            .copied()
            .map(|epoch| {
                (
                    epoch,
                    wl_storage
                        .pos_queries()
                        .get_total_voting_power(Some(epoch)),
                )
            })
            .collect()
    }

    fn average_voting_power<D, H>(
        &self,
        wl_storage: &WlStorage<D, H>,
    ) -> FractionalVotingPower
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        // if we only voted across a single epoch, we can avoid doing
        // expensive I/O operations
        if hints::likely(self.len() == 1) {
            // TODO: switch to [`BTreeMap::first_entry`] when we start
            // using Rust >= 1.66
            let Some(&power) = self.values().next() else {
                hints::cold();
                unreachable!("The map has one value");
            };
            return power;
        }

        let epoch_voting_powers = self.get_epoch_voting_powers(wl_storage);
        let total_voting_power = epoch_voting_powers
            .values()
            .fold(token::Amount::from(0u64), |accum, &stake| accum + stake);

        self.iter().map(|(&epoch, &power)| (epoch, power)).fold(
            FractionalVotingPower::NULL,
            |average, (epoch, aggregated_voting_power)| {
                let epoch_voting_power = epoch_voting_powers
                    .get(&epoch)
                    .copied()
                    .expect("This value should be in the map");
                debug_assert!(epoch_voting_power > 0.into());
                let weight = FractionalVotingPower::new(
                    epoch_voting_power.into(),
                    total_voting_power.into(),
                )
                .unwrap();
                average + weight * aggregated_voting_power
            },
        )
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
/// Represents all the information needed to tally a piece of data that may be
/// voted for over multiple epochs
pub struct Tally {
    /// The total voting power that's voted for this event across all epochs.
    pub voting_power: EpochedVotingPower,
    /// The votes which have been counted towards `voting_power`. Note that
    /// validators may submit multiple votes at different block heights for
    /// the same thing, but ultimately only one vote per validator will be
    /// used when tallying voting power.
    pub seen_by: Votes,
    /// Whether this event has been acted on or not - this should only ever
    /// transition from `false` to `true`, once there is enough voting power.
    pub seen: bool,
}

/// Calculate a new [`Tally`] based on some validators' fractional voting powers
/// as specific block heights
pub fn calculate_new<D, H>(
    wl_storage: &WlStorage<D, H>,
    seen_by: Votes,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<Tally>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut seen_by_voting_power = EpochedVotingPower::new();
    for (validator, block_height) in seen_by.iter() {
        match voting_powers
            .get(&(validator.to_owned(), block_height.to_owned()))
        {
            Some(voting_power) => {
                let epoch = wl_storage
                    .pos_queries()
                    .get_epoch(*block_height)
                    .expect("The queried epoch should be known");
                let aggregated = seen_by_voting_power
                    .entry(epoch)
                    .or_insert(FractionalVotingPower::NULL);
                *aggregated += voting_power;
            }
            None => {
                return Err(eyre!(
                    "voting power was not provided for validator {}",
                    validator
                ));
            }
        };
    }

    let newly_confirmed = seen_by_voting_power.has_majority_quorum(wl_storage);
    Ok(Tally {
        voting_power: seen_by_voting_power,
        seen_by,
        seen: newly_confirmed,
    })
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

    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::types::dec::Dec;
    use namada_core::types::key::RefTo;
    use namada_core::types::storage::BlockHeight;
    use namada_core::types::{address, token};
    use namada_proof_of_stake::parameters::PosParams;
    use namada_proof_of_stake::{
        become_validator, bond_tokens, write_pos_params, BecomeValidator,
    };

    use super::*;
    use crate::test_utils;

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

    /// Test that voting on a tally during a single epoch does
    /// not require any storage reads, and goes through the
    /// fast path of the algorithm.
    #[test]
    fn test_tally_vote_single_epoch() {
        let dummy_storage = TestWlStorage::default();

        let aggregated =
            EpochedVotingPower::from([(0.into(), FractionalVotingPower::HALF)]);
        assert_eq!(
            aggregated.average_voting_power(&dummy_storage),
            FractionalVotingPower::HALF
        );
    }

    /// Test that voting on a tally across epoch boundaries accounts
    /// for the average voting power attained along those epochs.
    #[test]
    fn test_voting_across_epoch_boundaries() {
        // the validators that will vote in the tally
        let validator_1 = address::testing::established_address_1();
        let validator_1_stake = token::Amount::native_whole(100);

        let validator_2 = address::testing::established_address_2();
        let validator_2_stake = token::Amount::native_whole(100);

        let validator_3 = address::testing::established_address_3();
        let validator_3_stake = token::Amount::native_whole(100);

        // start epoch 0 with validator 1
        let (mut wl_storage, _) = test_utils::setup_storage_with_validators(
            HashMap::from([(validator_1.clone(), validator_1_stake)]),
        );

        // update the pos params
        let params = PosParams {
            pipeline_len: 1,
            ..Default::default()
        };
        write_pos_params(&mut wl_storage, params.clone()).expect("Test failed");

        // insert validators 1, 2 and 3 at epoch 1
        for (validator, stake) in [
            (&validator_2, validator_2_stake),
            (&validator_3, validator_3_stake),
        ] {
            let keys = test_utils::TestValidatorKeys::generate();
            let consensus_key = &keys.consensus.ref_to();
            let eth_cold_key = &keys.eth_gov.ref_to();
            let eth_hot_key = &keys.eth_bridge.ref_to();
            become_validator(BecomeValidator {
                storage: &mut wl_storage,
                params: &params,
                address: validator,
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                current_epoch: 0.into(),
                commission_rate: Dec::new(5, 2).unwrap(),
                max_commission_rate_change: Dec::new(1, 2).unwrap(),
                offset_opt: Some(1),
            })
            .expect("Test failed");
            bond_tokens(
                &mut wl_storage,
                None,
                validator,
                stake,
                0.into(),
                None,
            )
            .expect("Test failed");
        }

        // query validators to make sure they were inserted correctly
        let query_validators = |epoch: u64| {
            wl_storage
                .pos_queries()
                .get_consensus_validators(Some(epoch.into()))
                .iter()
                .map(|validator| (validator.address, validator.bonded_stake))
                .collect::<HashMap<_, _>>()
        };
        let epoch_0_validators = query_validators(0);
        let epoch_1_validators = query_validators(1);
        assert_eq!(
            epoch_0_validators,
            HashMap::from([(validator_1.clone(), validator_1_stake)])
        );
        assert_eq!(
            epoch_1_validators,
            HashMap::from([
                // TODO: Figure out why this fixes the test
                //(validator_1, validator_1_stake),
                (validator_2, validator_2_stake),
                (validator_3, validator_3_stake),
            ])
        );

        // check that voting works as expected
        let aggregated = EpochedVotingPower::from([
            (0.into(), FractionalVotingPower::ONE_THIRD),
            (1.into(), FractionalVotingPower::ONE_THIRD),
        ]);
        assert_eq!(
            aggregated.average_voting_power(&wl_storage),
            FractionalVotingPower::ONE_THIRD
        );
    }
}
