use anoma::types::address::Address;
use anoma::types::ethereum_events::vote_extensions::{
    FractionalVotingPower, MultiSignedEthEvent,
};
use anoma::types::ethereum_events::EthereumEvent;
use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{eyre, Result};
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
) -> Result<Vec<EthMsg>> {
    let mut eth_msgs = Vec::with_capacity(multisigneds.len());
    for multisigned in multisigneds {
        let (body, _) = multisigned.event.data;
        match &body {
            EthereumEvent::TransfersToNamada {
                nonce: _,
                transfers,
            } => {
                if transfers.is_empty() {
                    return Err(eyre!("empty transfer batch"));
                }
            }
            _ => return Err(eyre!("unexpected Ethereum event")),
        }
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
    Ok(eth_msgs)
}

#[cfg(test)]
mod test {
    use anoma::proto::MultiSigned;
    use anoma::types::address;
    use anoma::types::ethereum_events::vote_extensions::{
        FractionalVotingPower, MultiSignedEthEvent,
    };
    use anoma::types::ethereum_events::{EthereumEvent, Uint};
    use anoma::types::key::{common, ed25519};
    use anoma::types::storage::BlockHeight;
    use rand::prelude::ThreadRng;

    use super::calculate_eth_msgs_state;

    fn arbitrary_fractional_voting_power() -> FractionalVotingPower {
        FractionalVotingPower::new(1, 3).unwrap()
    }

    fn arbitrary_nonce() -> Uint {
        123.into()
    }

    fn arbitrary_block_height() -> BlockHeight {
        BlockHeight(100)
    }

    /// This will actually generate a new random secret key each time it's
    /// called
    fn arbitrary_secret_key() -> common::SecretKey {
        let mut rng: ThreadRng = rand::thread_rng();
        let sk: common::SecretKey = {
            use anoma::types::key::{SecretKey, SigScheme};
            ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
        };
        sk
    }

    #[test]
    fn test_calculate_eth_msgs_state_empty() {
        assert!(calculate_eth_msgs_state(vec![]).unwrap().is_empty())
    }

    #[test]
    fn test_calculate_eth_msgs_state_rejects_unexpected_ethereum_events() {
        // TODO
    }

    #[test]
    fn test_calculate_eth_msgs_state_rejects_empty_transfers_to_namada() {
        let validator = address::testing::established_address_1();
        let empty_transfers = EthereumEvent::TransfersToNamada {
            nonce: arbitrary_nonce(),
            transfers: vec![],
        };
        let sk = arbitrary_secret_key();
        let heighted = (empty_transfers, arbitrary_block_height());
        let signed =
            MultiSigned::<(EthereumEvent, BlockHeight)>::new(&sk, heighted);
        // ed25519::Signature::from(_)
        let aggregated = vec![MultiSignedEthEvent {
            signers: vec![(
                validator.clone(),
                arbitrary_fractional_voting_power(),
            )],
            event: signed,
        }];
        assert!(calculate_eth_msgs_state(aggregated).is_err());
    }

    // TODO: test signatures match signers
    // TODO: test one valid event
}
