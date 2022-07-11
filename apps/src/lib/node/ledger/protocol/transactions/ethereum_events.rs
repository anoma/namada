use anoma::types::address::Address;
use anoma::types::ethereum_events::vote_extensions::{
    FractionalVotingPower, MultiSignedEthEvent,
};
use anoma::types::ethereum_events::EthereumEvent;
use borsh::{BorshDeserialize, BorshSerialize};
use num_rational::Ratio;

fn threshold() -> Ratio<u64> {
    Ratio::new(2, 3)
}

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) struct EthMsg {
    body: EthereumEvent,
    seen_by: Vec<Address>,
    voting_power: FractionalVotingPower,
    seen: bool,
}

pub(crate) fn calculate_eth_msgs_state(
    multisigneds: Vec<MultiSignedEthEvent>,
) -> Vec<EthMsg> {
    let mut eth_msgs = Vec::with_capacity(multisigneds.len());
    for multisigned in multisigneds {
        let (body, _) = multisigned.event.data;
        let mut total_voting_power = FractionalVotingPower::zero();
        let mut seen_by = vec![];
        for (signer, voting_power) in multisigned.signers {
            seen_by.push(signer);
            total_voting_power =
                (*voting_power + *total_voting_power).try_into().unwrap();
        }

        let seen = *total_voting_power > threshold();
        eth_msgs.push(EthMsg {
            body,
            seen_by,
            voting_power: total_voting_power,
            seen,
        });
    }
    eth_msgs
}

#[cfg(test)]
mod test {
    use anoma::proto::MultiSigned;
    use anoma::types::address;
    use anoma::types::ethereum_events::vote_extensions::{
        FractionalVotingPower, MultiSignedEthEvent,
    };
    use anoma::types::ethereum_events::EthereumEvent;
    use anoma::types::storage::BlockHeight;

    use super::calculate_eth_msgs_state;
    use crate::node::ledger::protocol::transactions::ethereum_events::EthMsg;

    #[test]
    fn test_calculate_eth_msgs_state() {
        let est1 = address::testing::established_address_1();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
        };
        assert_eq!(calculate_eth_msgs_state(vec![]), vec![]);
        assert_eq!(
            calculate_eth_msgs_state(vec![MultiSignedEthEvent {
                signers: vec![(
                    est1.clone(),
                    FractionalVotingPower::new(1, 3).unwrap()
                )],
                event: MultiSigned {
                    data: (
                        EthereumEvent::TransfersToNamada {
                            nonce: 0.into(),
                            transfers: vec![]
                        },
                        BlockHeight(100)
                    ),
                    sigs: vec![]
                }
            }]),
            vec![EthMsg {
                body: event,
                seen_by: vec![est1.clone()],
                voting_power: FractionalVotingPower::new(1, 3).unwrap(),
                seen: false,
            }]
        );
    }
}
