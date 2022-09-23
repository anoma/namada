use std::collections::{BTreeSet, HashMap, HashSet};

use eyre::eyre;
use namada::ledger::pos::types::{VotingPower, WeightedValidator};
use namada::types::address::Address;
use namada::types::storage::BlockHeight;
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;
use namada::types::voting_power::FractionalVotingPower;

/// Gets all the voters from the given events.
pub(super) fn get_voters_for_events<'a>(
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
    all_active: &BTreeSet<WeightedValidator<Address>>,
    selected: HashSet<Address>,
) -> eyre::Result<HashMap<Address, FractionalVotingPower>> {
    let total_voting_power = sum_voting_powers(all_active);
    let voting_powers: HashMap<Address, FractionalVotingPower> = all_active
        .iter()
        .filter(|validator| selected.contains(&validator.address))
        .map(|validator| {
            // TODO: get rid of .unwrap() call in here
            (
                validator.address.to_owned(),
                FractionalVotingPower::new(
                    validator.voting_power.into(),
                    total_voting_power.into(),
                )
                .unwrap(),
            )
        })
        .collect();
    for validator in &selected {
        if voting_powers.get(validator).is_none() {
            return Err(eyre!(
                "couldn't get voting power for validator {}",
                validator,
            ));
        }
    }
    Ok(voting_powers)
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
    use namada::types::ethereum_events::testing::arbitrary_voting_power;

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
        let validators = HashSet::from_iter(vec![sole_validator.clone()]);
        let active_validators =
            BTreeSet::from_iter(vec![weighted_sole_validator]);

        let result =
            get_voting_powers_for_selected(&active_validators, validators);

        let voting_powers = match result {
            Ok(voting_powers) => voting_powers,
            Err(error) => panic!("error: {:?}", error),
        };
        assert_eq!(voting_powers.len(), 1);
        assert_matches!(voting_powers.get(&sole_validator), Some(v) if *v == FractionalVotingPower::new(1, 1).unwrap());
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
        let validators =
            HashSet::from_iter(vec![present_validator, missing_validator]);
        let active_validators =
            BTreeSet::from_iter(vec![weighted_present_validator]);

        let result =
            get_voting_powers_for_selected(&active_validators, validators);

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
        let validators =
            HashSet::from_iter(vec![validator_1.clone(), validator_2.clone()]);
        let active_validators = BTreeSet::from_iter(vec![
            weighted_validator_1,
            weighted_validator_2,
        ]);

        let result =
            get_voting_powers_for_selected(&active_validators, validators);

        let voting_powers = match result {
            Ok(voting_powers) => voting_powers,
            Err(error) => panic!("error: {:?}", error),
        };
        assert_eq!(voting_powers.len(), 2);
        assert_matches!(voting_powers.get(&validator_1), Some(v) if *v == FractionalVotingPower::new(100, 300).unwrap());
        assert_matches!(voting_powers.get(&validator_2), Some(v) if *v == FractionalVotingPower::new(200, 300).unwrap());
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
}
