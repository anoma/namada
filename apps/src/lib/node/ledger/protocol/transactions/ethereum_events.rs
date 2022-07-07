use anoma::types::address::Address;
use anoma::types::ethereum_events::{EthereumEvent, MultiSignedEthEvent};
use borsh::{BorshDeserialize, BorshSerialize};
use num_rational::Ratio;

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) struct EthMsg {
    body: EthereumEvent,
    seen_by: Vec<Address>,
    voting_power: (u64, u64),
    seen: bool,
}

pub(crate) fn calculate_eth_msgs_state(
    multisigneds: Vec<MultiSignedEthEvent>,
) -> Vec<EthMsg> {
    let mut eth_msgs = Vec::with_capacity(multisigneds.len());
    for multisigned in multisigneds {
        let body = multisigned.event.data;
        let mut total_voting_power = 0;
        let mut seen_by = vec![];
        for (signer, voting_power) in multisigned.signers {
            seen_by.push(signer);
            total_voting_power += voting_power; // TODO: overflow checks?
        }
        const DENOMINATOR: u64 = 1000; // TODO: what is the denominator?

        let voting_power = (total_voting_power, DENOMINATOR);
        let seen =
            Ratio::new(voting_power.0, voting_power.1) > Ratio::new(2, 3);
        eth_msgs.push(EthMsg {
            body,
            seen_by,
            voting_power,
            seen,
        });
    }
    eth_msgs
}

#[cfg(test)]
mod test {
    use anoma::proto::MultiSigned;
    use anoma::types::address;
    use anoma::types::ethereum_events::{EthereumEvent, MultiSignedEthEvent};

    use super::calculate_eth_msgs_state;
    use crate::node::ledger::protocol::transactions::ethereum_events::EthMsg;

    #[test]
    fn test_calculate_eth_msgs_state() {
        let est1 = address::testing::established_address_1();
        let event = EthereumEvent::TransfersToNamada(vec![]);
        assert_eq!(calculate_eth_msgs_state(vec![]), vec![]);
        assert_eq!(
            calculate_eth_msgs_state(vec![MultiSignedEthEvent {
                signers: vec![(est1.clone(), 1)],
                event: MultiSigned {
                    data: EthereumEvent::TransfersToNamada(vec![]),
                    sigs: vec![]
                }
            }]),
            vec![EthMsg {
                body: event,
                seen_by: vec![est1.clone()],
                voting_power: (1, 1000),
                seen: false,
            }]
        );
    }
}
