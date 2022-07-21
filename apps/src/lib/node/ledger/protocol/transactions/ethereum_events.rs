use borsh::BorshSerialize;
use eyre::{eyre, Context, Result};
use namada::types::ethereum_events::vote_extensions::MultiSignedEthEvent;
use namada::types::ethereum_events::EthMsgDiff;

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
    let body = multisigned.event;

    let mut seen_by = vec![];
    for signer in multisigned.signers {
        seen_by.push(signer);
    }

    Ok(EthMsgDiff { body, seen_by })
}

pub(crate) fn construct_tx_data(diffs: Vec<EthMsgDiff>) -> Result<Vec<u8>> {
    diffs
        .try_to_vec()
        .wrap_err_with(|| eyre!("couldn't serialize diffs"))
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
    };
    use namada::types::ethereum_events::vote_extensions::MultiSignedEthEvent;
    use namada::types::ethereum_events::{EthereumEvent, TransferToNamada};

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
        let with_signers = MultiSignedEthEvent {
            event: empty_transfers,
            signers: HashSet::from_iter(vec![(validator.clone())]),
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
        let with_signers = MultiSignedEthEvent {
            event: single_transfer.clone(),
            signers: HashSet::from_iter(vec![(sole_validator.clone())]),
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
