use anoma::types::ethereum_events::vote_extensions::MultiSignedEthEvent;
use anoma::types::ethereum_events::EthMsgDiff;
use borsh::BorshSerialize;
use eyre::{eyre, Context, Result};

pub(crate) fn calculate_eth_msg_diffs(
    multisigneds: Vec<MultiSignedEthEvent>,
) -> Result<Vec<EthMsgDiff>> {
    let mut eth_msgs = Vec::with_capacity(multisigneds.len());
    for multisigned in multisigneds {
        eth_msgs.push(calculate_eth_msg_diff(multisigned)?);
    }
    Ok(eth_msgs)
}

pub(crate) fn calculate_eth_msg_diff(
    multisigned: MultiSignedEthEvent,
) -> Result<EthMsgDiff> {
    let (body, _) = multisigned.event.data;
    if !body.is_valid() {
        return Err(eyre!("invalid event: {:#?}", body));
    }

    let mut seen_by = vec![];
    for (signer, _) in multisigned.signers {
        // we disregard voting power, as we will look it up directly from
        // storage
        seen_by.push(signer);
    }

    Ok(EthMsgDiff { body, seen_by })
}

pub(crate) fn construct_tx_data(diffs: Vec<EthMsgDiff>) -> Result<Vec<u8>> {
    // TODO: when can .try_to_vec() ever fail?
    diffs
        .try_to_vec()
        .wrap_err_with(|| eyre!("couldn't serialize diffs"))
}

#[cfg(test)]
mod test {
    use anoma::proto::MultiSigned;
    use anoma::types::address;
    use anoma::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_block_height, arbitrary_eth_address,
        arbitrary_fractional_voting_power, arbitrary_nonce,
        arbitrary_secret_key,
    };
    use anoma::types::ethereum_events::vote_extensions::{
        FractionalVotingPower, MultiSignedEthEvent,
    };
    use anoma::types::ethereum_events::{EthereumEvent, TransferToNamada};
    use anoma::types::storage::BlockHeight;

    use super::*;

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
                amount: arbitrary_amount(),
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
        };

        let eth_msg = calculate_eth_msg_diff(with_signers);

        let eth_msg = eth_msg.unwrap();
        assert_eq!(eth_msg, expected);
    }
}
