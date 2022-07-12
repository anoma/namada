use anoma::types::address::Address;
use anoma::types::ethereum_events::vote_extensions::{
    FractionalVotingPower, MultiSignedEthEvent,
};
use anoma::types::ethereum_events::EthereumEvent;
use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{eyre, Result};

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) struct EthMsgDiff {
    body: EthereumEvent,
    seen_by: Vec<Address>,
    voting_power: FractionalVotingPower,
}

pub(crate) fn calculate_eth_msg_diffs(
    multisigneds: Vec<MultiSignedEthEvent>,
) -> Result<Vec<EthMsgDiff>> {
    let mut eth_msgs = Vec::with_capacity(multisigneds.len());
    for multisigned in multisigneds {
        eth_msgs.push(calculate_eth_msg_diff(multisigned)?);
    }
    Ok(eth_msgs)
}

pub(crate) fn calculate_eth_msg_diff(multisigned: MultiSignedEthEvent) -> Result<EthMsgDiff> {
    let (body, _) = multisigned.event.data;
    if !body.is_valid() {
        return Err(eyre!("invalid event: {:#?}", body));
    }
    let mut total_voting_power = FractionalVotingPower::zero();
    let mut seen_by = vec![];
    for (signer, voting_power) in multisigned.signers {
        seen_by.push(signer);
        total_voting_power =
            (*voting_power + *total_voting_power).try_into().unwrap();
    }

    Ok(EthMsgDiff {
        body,
        seen_by,
        voting_power: total_voting_power,
    })
}

#[cfg(test)]
mod test {
    use anoma::proto::MultiSigned;
    use anoma::types::address;
    use anoma::types::ethereum_events::vote_extensions::{
        FractionalVotingPower, MultiSignedEthEvent,
    };
    use anoma::types::ethereum_events::{
        EthAddress, EthereumEvent, TransferToNamada, Uint,
    };
    use anoma::types::key::{common, ed25519};
    use anoma::types::storage::BlockHeight;
    use anoma::types::token::Amount;
    use rand::prelude::ThreadRng;

    use super::*;

    const DAI_ERC20_ETH_ADDRESS: &str =
        "0x6B175474E89094C44Da98b954EedeAC495271d0F";

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

    fn arbitrary_eth_address() -> EthAddress {
        let bytes: [u8; 20] =
            hex::decode(DAI_ERC20_ETH_ADDRESS[2..].as_bytes())
                .unwrap()
                .try_into()
                .unwrap();

        EthAddress(bytes)
    }

    #[test]
    fn calculate_eth_msg_diffs_empty() {
        assert!(calculate_eth_msg_diffs(vec![]).unwrap().is_empty())
    }

    #[test]
    fn calculate_eth_msg_diff_accepts_all_ethereum_events() {
        // TODO
    }

    #[test]
    fn calculate_eth_msg_diff_rejects_empty_transfers_to_namada() {
        let validator = address::testing::established_address_1();
        let empty_transfers = EthereumEvent::TransfersToNamada {
            nonce: arbitrary_nonce(),
            transfers: vec![],
        };
        let sk = arbitrary_secret_key();
        let heighted = (empty_transfers, arbitrary_block_height());
        let signed =
            MultiSigned::<(EthereumEvent, BlockHeight)>::new(&sk, heighted);
        let with_signers = MultiSignedEthEvent {
            signers: vec![(
                validator.clone(),
                arbitrary_fractional_voting_power(),
            )],
            event: signed,
        };
        assert!(calculate_eth_msg_diff(with_signers).is_err());
    }

    #[test]
    fn calculate_eth_msg_diff_accepts_one_validator_one_transfer() {
        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let single_transfer = EthereumEvent::TransfersToNamada {
            nonce: arbitrary_nonce(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: arbitrary_eth_address(),
                receiver,
            }],
        };
        let sk = arbitrary_secret_key();
        let heighted = (single_transfer.clone(), arbitrary_block_height());
        let signed =
            MultiSigned::<(EthereumEvent, BlockHeight)>::new(&sk, heighted);
        let with_signers = MultiSignedEthEvent {
            signers: vec![(
                sole_validator.clone(),
                FractionalVotingPower::full(),
            )],
            event: signed,
        };
        let expected = EthMsgDiff {
            body: single_transfer.clone(),
            seen_by: vec![sole_validator],
            voting_power: FractionalVotingPower::full(),
        };

        let eth_msg = calculate_eth_msg_diff(with_signers);

        let eth_msg = eth_msg.unwrap();
        assert_eq!(eth_msg, expected);
    }

    // TODO: test signatures match signers
}
