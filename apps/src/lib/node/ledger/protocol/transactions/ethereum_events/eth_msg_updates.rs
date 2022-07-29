use std::collections::BTreeSet;

use namada::types::ethereum_events::vote_extensions::MultiSignedEthEvent;
use namada::types::ethereum_events::EthMsgUpdate;

pub(crate) fn from_multisigneds(
    multisigneds: Vec<MultiSignedEthEvent>,
) -> BTreeSet<EthMsgUpdate> {
    multisigneds.into_iter().map(from_multisigned).collect()
}

// Derive the [`EthMsgUpdate`] for some given [`MultiSignedEthEvent`]. This
// function is non-deterministic. The returned [`EthMsgUpdate`]'s `seen_by`
// field may be in any order.
pub(crate) fn from_multisigned(
    multisigned: MultiSignedEthEvent,
) -> EthMsgUpdate {
    let body = multisigned.event;

    let seen_by = multisigned.signers.into_iter().collect();

    EthMsgUpdate { body, seen_by }
}

#[cfg(test)]
mod test {
    use std::collections::{BTreeSet, HashSet};

    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_nonce, arbitrary_single_transfer,
    };
    use namada::types::ethereum_events::vote_extensions::MultiSignedEthEvent;

    use super::*;

    #[test]
    fn test_from_multisigneds_empty() {
        let updates = from_multisigneds(vec![]);

        assert!(updates.is_empty());
    }

    #[test]
    fn test_from_multisigned_one_validator_one_transfer() {
        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let event = arbitrary_single_transfer(arbitrary_nonce(), receiver);
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: HashSet::from_iter(vec![sole_validator.clone()]),
        };
        let expected = EthMsgUpdate {
            body: event.clone(),
            seen_by: BTreeSet::from_iter(vec![sole_validator]),
        };

        let update = from_multisigned(with_signers);

        assert_eq!(update, expected);
    }

    #[test]
    fn test_from_multisigned_two_validators_one_transfer() {
        let validator_a = address::testing::established_address_1();
        let validator_b = address::testing::established_address_3();
        let receiver = address::testing::established_address_2();
        let event = arbitrary_single_transfer(arbitrary_nonce(), receiver);
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: HashSet::from_iter(vec![
                validator_a.clone(),
                validator_b.clone(),
            ]),
        };
        let expected = EthMsgUpdate {
            body: event.clone(),
            seen_by: BTreeSet::from_iter(vec![
                validator_b.clone(),
                validator_a.clone(),
            ]),
        };

        let update = from_multisigned(with_signers);

        assert_eq!(update, expected);
    }

    #[test]
    fn test_from_multisigneds_one_validator_two_transfers() {
        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let nonce = 1;
        let event_a = arbitrary_single_transfer(nonce.into(), receiver.clone());
        let event_b =
            arbitrary_single_transfer((nonce + 1).into(), receiver.clone());
        let with_signers = vec![
            MultiSignedEthEvent {
                event: event_b.clone(),
                signers: HashSet::from_iter(vec![sole_validator.clone()]),
            },
            MultiSignedEthEvent {
                event: event_a.clone(),
                signers: HashSet::from_iter(vec![sole_validator.clone()]),
            },
        ];
        let expected = BTreeSet::from_iter(vec![
            EthMsgUpdate {
                body: event_b.clone(),
                seen_by: BTreeSet::from_iter(vec![sole_validator.clone()]),
            },
            EthMsgUpdate {
                body: event_a.clone(),
                seen_by: BTreeSet::from_iter(vec![sole_validator.clone()]),
            },
        ]);

        let updates = from_multisigneds(with_signers);

        assert_eq!(updates, expected);
    }

    #[test]
    fn test_from_multisigneds_two_validators_two_transfers() {
        let validator_a = address::testing::established_address_1();
        let validator_b = address::testing::established_address_3();
        let receiver = address::testing::established_address_2();
        let nonce = 1;
        let event_a = arbitrary_single_transfer(nonce.into(), receiver.clone());
        let event_b =
            arbitrary_single_transfer((nonce + 1).into(), receiver.clone());
        let with_signers = vec![
            MultiSignedEthEvent {
                event: event_b.clone(),
                signers: HashSet::from_iter(vec![
                    validator_a.clone(),
                    validator_b.clone(),
                ]),
            },
            MultiSignedEthEvent {
                event: event_a.clone(),
                signers: HashSet::from_iter(vec![
                    validator_a.clone(),
                    validator_b.clone(),
                ]),
            },
        ];
        let expected = BTreeSet::from_iter(vec![
            EthMsgUpdate {
                body: event_b.clone(),
                seen_by: BTreeSet::from_iter(vec![
                    validator_b.clone(),
                    validator_a.clone(),
                ]),
            },
            EthMsgUpdate {
                body: event_a.clone(),
                seen_by: BTreeSet::from_iter(vec![
                    validator_b.clone(),
                    validator_a.clone(),
                ]),
            },
        ]);

        let updates = from_multisigneds(with_signers);

        assert_eq!(updates, expected);
    }
}
