use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use eyre::eyre;
use itertools::Itertools;
use namada::ledger::pos::types::{VotingPower, WeightedValidator};
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::types::address::Address;
use namada::types::storage::BlockHeight;
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;
use namada::types::voting_power::FractionalVotingPower;

use crate::node::ledger::shell::queries::QueriesExt;

pub(super) fn get_active_validators<D, H>(
    storage: &Storage<D, H>,
    block_heights: HashSet<BlockHeight>,
) -> BTreeMap<BlockHeight, BTreeSet<WeightedValidator<Address>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut active_validators = BTreeMap::default();
    for height in block_heights.into_iter() {
        let epoch = storage.get_epoch(height).expect(
            "The epoch of the last block height should always be known",
        );
        _ = active_validators
            .insert(height, storage.get_active_validators(Some(epoch)));
    }
    active_validators
}

/// Extract all the voters and the block heights at which they voted from the
/// given events.
pub(super) fn get_votes_for_events<'a>(
    events: impl Iterator<Item = &'a MultiSignedEthEvent>,
) -> HashSet<(Address, BlockHeight)> {
    events.fold(HashSet::new(), |mut validators, event| {
        validators.extend(event.signers.iter().cloned());
        validators
    })
}

/// Gets the voting power of `selected` from `all_active`. Errors if a
/// `selected` validator is not found in `all_active`.
pub(super) fn get_voting_powers_for_selected(
    all_active: &BTreeMap<BlockHeight, BTreeSet<WeightedValidator<Address>>>,
    selected: HashSet<(Address, BlockHeight)>,
) -> eyre::Result<HashMap<(Address, BlockHeight), FractionalVotingPower>> {
    let total_voting_powers = sum_voting_powers_for_block_heights(all_active);
    let voting_powers = selected
        .into_iter()
        .map(
            |(addr, height)| -> eyre::Result<(
                (Address, BlockHeight),
                FractionalVotingPower,
            )> {
                let active_validators =
                    all_active.get(&height).ok_or_else(|| {
                        eyre!("No active validators found for height {height}")
                    })?;
                let individual_voting_power = active_validators
                    .iter()
                    .find(|&v| v.address == addr)
                    .ok_or_else(|| {
                        eyre!(
                            "No active validator found with address {addr} \
                             for height {height}"
                        )
                    })?
                    .voting_power;
                let total_voting_power = total_voting_powers
                    .get(&height)
                    .ok_or_else(|| {
                        eyre!(
                            "No total voting power provided for height \
                             {height}"
                        )
                    })?
                    .to_owned();
                Ok((
                    (addr, height),
                    FractionalVotingPower::new(
                        individual_voting_power.into(),
                        total_voting_power.into(),
                    )?,
                ))
            },
        )
        .try_collect()?;
    Ok(voting_powers)
}

pub(super) fn sum_voting_powers_for_block_heights(
    validators: &BTreeMap<BlockHeight, BTreeSet<WeightedValidator<Address>>>,
) -> BTreeMap<BlockHeight, VotingPower> {
    validators
        .iter()
        .map(|(h, vs)| (h.to_owned(), sum_voting_powers(vs)))
        .collect()
}

pub(super) fn sum_voting_powers(
    validators: &BTreeSet<WeightedValidator<Address>>,
) -> VotingPower {
    validators
        .iter()
        .map(|validator| u64::from(validator.voting_power))
        .sum::<u64>()
        .into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use assert_matches::assert_matches;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_single_transfer, arbitrary_voting_power,
    };

    use super::*;

    #[test]
    /// Test getting the voting power for the sole active validator from the set
    /// of active validators
    fn test_get_voting_powers_for_selected_sole_validator() {
        let sole_validator = address::testing::established_address_1();
        let voting_power = arbitrary_voting_power();
        let weighted_sole_validator = WeightedValidator {
            voting_power,
            address: sole_validator.clone(),
        };
        let validators = HashSet::from_iter(vec![(
            sole_validator.clone(),
            BlockHeight(100),
        )]);
        let active_validators = BTreeMap::from_iter(vec![(
            BlockHeight(100),
            BTreeSet::from_iter(vec![weighted_sole_validator]),
        )]);

        let result =
            get_voting_powers_for_selected(&active_validators, validators);

        let voting_powers = match result {
            Ok(voting_powers) => voting_powers,
            Err(error) => panic!("error: {:?}", error),
        };
        assert_eq!(voting_powers.len(), 1);
        assert_matches!(
            voting_powers.get(&(sole_validator, BlockHeight(100))),
            Some(v) if *v == FractionalVotingPower::new(1, 1).unwrap()
        );
    }

    #[test]
    /// Test that an error is returned if a validator is not found in the set of
    /// active validators
    fn test_get_voting_powers_for_selected_missing_validator() {
        let present_validator = address::testing::established_address_1();
        let missing_validator = address::testing::established_address_2();
        let voting_power = arbitrary_voting_power();
        let weighted_present_validator = WeightedValidator {
            voting_power,
            address: present_validator.clone(),
        };
        let validators = HashSet::from_iter(vec![
            (present_validator, BlockHeight(100)),
            (missing_validator, BlockHeight(100)),
        ]);
        let active_validators = BTreeMap::from_iter(vec![(
            BlockHeight(100),
            BTreeSet::from_iter(vec![weighted_present_validator]),
        )]);

        let result =
            get_voting_powers_for_selected(&active_validators, validators);

        assert!(result.is_err());
    }

    #[test]
    /// Assert we error if we are passed an `(Address, BlockHeight)` but are not
    /// given a corrseponding set of validators for the block height
    fn test_get_voting_powers_for_selected_no_active_validators_for_height() {
        let all_active = BTreeMap::default();
        let selected = HashSet::from_iter(vec![(
            address::testing::established_address_1(),
            BlockHeight(100),
        )]);

        let result = get_voting_powers_for_selected(&all_active, selected);

        assert!(result.is_err());
    }

    #[test]
    /// Test getting the voting powers for two active validators from the set of
    /// active validators
    fn test_get_voting_powers_for_selected_two_validators() {
        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();
        let voting_power_1 = VotingPower::from(100);
        let voting_power_2 = VotingPower::from(200);
        let weighted_validator_1 = WeightedValidator {
            voting_power: voting_power_1,
            address: validator_1.clone(),
        };
        let weighted_validator_2 = WeightedValidator {
            voting_power: voting_power_2,
            address: validator_2.clone(),
        };
        let validators = HashSet::from_iter(vec![
            (validator_1.clone(), BlockHeight(100)),
            (validator_2.clone(), BlockHeight(100)),
        ]);
        let active_validators = BTreeMap::from_iter(vec![(
            BlockHeight(100),
            BTreeSet::from_iter(vec![
                weighted_validator_1,
                weighted_validator_2,
            ]),
        )]);

        let result =
            get_voting_powers_for_selected(&active_validators, validators);

        let voting_powers = match result {
            Ok(voting_powers) => voting_powers,
            Err(error) => panic!("error: {:?}", error),
        };
        assert_eq!(voting_powers.len(), 2);
        assert_matches!(
            voting_powers.get(&(validator_1, BlockHeight(100))),
            Some(v) if *v == FractionalVotingPower::new(100, 300).unwrap()
        );
        assert_matches!(
            voting_powers.get(&(validator_2, BlockHeight(100))),
            Some(v) if *v == FractionalVotingPower::new(200, 300).unwrap()
        );
    }

    #[test]
    /// Test summing the voting powers for a set of validators containing only
    /// one validator
    fn test_sum_voting_powers_sole_validator() {
        let sole_validator = address::testing::established_address_1();
        let voting_power = arbitrary_voting_power();
        let weighted_sole_validator = WeightedValidator {
            voting_power,
            address: sole_validator,
        };
        let validators = BTreeSet::from_iter(vec![weighted_sole_validator]);

        let total = sum_voting_powers(&validators);

        assert_eq!(total, voting_power);
    }

    #[test]
    /// Test summing the voting powers for a set of validators containing two
    /// validators
    fn test_sum_voting_powers_two_validators() {
        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();
        let voting_power_1 = VotingPower::from(100);
        let voting_power_2 = VotingPower::from(200);
        let weighted_validator_1 = WeightedValidator {
            voting_power: voting_power_1,
            address: validator_1,
        };
        let weighted_validator_2 = WeightedValidator {
            voting_power: voting_power_2,
            address: validator_2,
        };
        let validators = BTreeSet::from_iter(vec![
            weighted_validator_1,
            weighted_validator_2,
        ]);

        let total = sum_voting_powers(&validators);

        assert_eq!(total, VotingPower::from(300));
    }

    #[test]
    /// Assert we don't return anything if we try to get the votes for an empty
    /// vec of events
    pub fn test_get_votes_for_events_empty() {
        let events = vec![];
        let votes = get_votes_for_events(events.iter());
        assert!(votes.is_empty());
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
        let votes = get_votes_for_events(events.iter());
        assert_eq!(
            votes,
            HashSet::from_iter(vec![
                (address::testing::established_address_1(), BlockHeight(100)),
                (address::testing::established_address_1(), BlockHeight(101)),
                (address::testing::established_address_2(), BlockHeight(102)),
                (address::testing::established_address_3(), BlockHeight(100))
            ])
        )
    }
}
