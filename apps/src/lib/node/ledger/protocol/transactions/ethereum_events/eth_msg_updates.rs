use namada::types::ethereum_events::vote_extensions::MultiSignedEthEvent;
use namada::types::ethereum_events::EthMsgUpdate;

// Derive the [`EthMsgUpdate`] for some given [`MultiSignedEthEvent`].
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
}
