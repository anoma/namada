use std::collections::{BTreeSet, HashMap, HashSet};

use eyre::eyre;
use namada::ledger::pos::types::{VotingPower, WeightedValidator};
use namada::types::address::Address;
use namada::types::ethereum_events::vote_extensions::MultiSignedEthEvent;

/// Gets all the voters from the given events.
pub(crate) fn get_all_voters<'a>(
    events: impl Iterator<Item = &'a MultiSignedEthEvent>,
) -> HashSet<Address> {
    events.fold(HashSet::new(), |mut validators, event| {
        validators.extend(event.signers.iter().map(|addr| addr.to_owned()));
        validators
    })
}

/// Gets the voting power of `selected` from `validators`. Errors if a
/// `selected` validator is not found in `validators`.
pub(crate) fn for_selected(
    validators: &BTreeSet<WeightedValidator<Address>>,
    selected: HashSet<Address>,
) -> eyre::Result<HashMap<Address, VotingPower>> {
    let voting_powers: HashMap<Address, VotingPower> = validators
        .iter()
        .filter(|validator| selected.contains(&validator.address))
        .map(|validator| (validator.address.to_owned(), validator.voting_power))
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

pub(crate) fn sum(
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

    use namada::types::address;
    use namada::types::ethereum_events::testing::arbitrary_voting_power;

    use super::*;

    #[test]
    fn test_for_selected_sole_validator() {
        let sole_validator = address::testing::established_address_1();
        let voting_power = arbitrary_voting_power();
        let weighted_sole_validator = WeightedValidator {
            voting_power,
            address: sole_validator.clone(),
        };
        let validators = HashSet::from_iter(vec![sole_validator.clone()]);
        let active_validators =
            BTreeSet::from_iter(vec![weighted_sole_validator]);

        let result = for_selected(&active_validators, validators);

        let voting_powers = match result {
            Ok(voting_powers) => voting_powers,
            Err(error) => panic!("error: {:?}", error),
        };
        assert_eq!(voting_powers.len(), 1);
        assert!(
            matches!(voting_powers.get(&sole_validator), Some(v) if *v == voting_power)
        )
    }

    #[test]
    fn test_for_selected_missing_validator() {
        let present_validator = address::testing::established_address_1();
        let missing_validator = address::testing::established_address_2();
        let voting_power = arbitrary_voting_power();
        let weighted_present_validator = WeightedValidator {
            voting_power,
            address: present_validator.clone(),
        };
        let validators = HashSet::from_iter(vec![
            present_validator.clone(),
            missing_validator.clone(),
        ]);
        let active_validators =
            BTreeSet::from_iter(vec![weighted_present_validator]);

        let result = for_selected(&active_validators, validators);

        assert!(result.is_err());
    }

    #[test]
    fn test_for_selected_two_validators() {
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

        let result = for_selected(&active_validators, validators);

        let voting_powers = match result {
            Ok(voting_powers) => voting_powers,
            Err(error) => panic!("error: {:?}", error),
        };
        assert_eq!(voting_powers.len(), 2);
        assert!(
            matches!(voting_powers.get(&validator_1), Some(v) if *v == voting_power_1)
        );
        assert!(
            matches!(voting_powers.get(&validator_2), Some(v) if *v == voting_power_2)
        );
    }

    #[test]
    fn test_sum_sole_validator() {
        let sole_validator = address::testing::established_address_1();
        let voting_power = arbitrary_voting_power();
        let weighted_sole_validator = WeightedValidator {
            voting_power,
            address: sole_validator.clone(),
        };
        let validators = BTreeSet::from_iter(vec![weighted_sole_validator]);

        let total = sum(&validators);

        assert_eq!(total, voting_power);
    }

    #[test]
    fn test_sum_two_validators() {
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
        let validators = BTreeSet::from_iter(vec![
            weighted_validator_1,
            weighted_validator_2,
        ]);

        let total = sum(&validators);

        assert_eq!(total, VotingPower::from(300));
    }
}
