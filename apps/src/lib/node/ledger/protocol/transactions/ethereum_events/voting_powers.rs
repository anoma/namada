use std::collections::{BTreeSet, HashMap, HashSet};

use eyre::eyre;
use namada::ledger::pos::types::{VotingPower, WeightedValidator};
use namada::types::address::Address;

pub(crate) fn get_voting_powers_for_selected(
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

pub(crate) fn sum_voting_powers(
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
        assert!(
            matches!(voting_powers.get(&sole_validator), Some(v) if *v == voting_power)
        )
    }

    #[test]
    fn test_sum_voting_powers_sole_validator() {
        let sole_validator = address::testing::established_address_1();
        let voting_power = arbitrary_voting_power();
        let weighted_sole_validator = WeightedValidator {
            voting_power,
            address: sole_validator.clone(),
        };
        let validators = BTreeSet::from_iter(vec![weighted_sole_validator]);

        let total = sum_voting_powers(&validators);

        assert_eq!(total, voting_power);
    }
}
