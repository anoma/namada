//! code that should be executed within a transaction
use std::error::Error;

use borsh::BorshDeserialize;
use namada::types::ethereum_events::TxEthBridgeData;

use crate::imports::tx::log_string;

const TX_NAME: &str = "tx_eth_bridge";

fn log(msg: impl AsRef<str>) {
    log_string(format!("[{}] {}", TX_NAME, msg.as_ref()))
}

pub fn apply(tx_data: Vec<u8>) {
    if let Err(err) = apply_aux(tx_data) {
        log(format!("ERROR: {:?}", err));
        panic!("{:?}", err)
    }
}

pub fn apply_aux(tx_data: Vec<u8>) -> Result<(), Box<dyn Error>> {
    log(format!("got data - {} bytes", tx_data.len()));

    let data: TxEthBridgeData = BorshDeserialize::try_from_slice(&tx_data)?;
    log(format!(
        "deserialized data - number of updates to apply = {}, \
         total_voting_power = {}, voting_powers = {:#?}",
        data.updates.len(),
        data.total_voting_power,
        data.voting_powers,
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use borsh::BorshSerialize;
    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
        arbitrary_voting_power,
    };
    use namada::types::ethereum_events::{
        EthMsgUpdate, EthereumEvent, TransferToNamada, TxEthBridgeData,
    };
    use namada_tests::tx::tx_host_env;

    use super::*;

    #[test]
    fn test_apply_tx() {
        let sole_validator = address::testing::gen_established_address();
        let receiver = address::testing::established_address_2();

        let update = EthMsgUpdate {
            body: EthereumEvent::TransfersToNamada {
                nonce: arbitrary_nonce(),
                transfers: vec![TransferToNamada {
                    amount: arbitrary_amount(),
                    asset: arbitrary_eth_address(),
                    receiver,
                }],
            },
            seen_by: BTreeSet::from_iter(vec![sole_validator.clone()]),
        };
        let updates = vec![update];
        let total_voting_power = arbitrary_voting_power();
        let voting_powers =
            HashMap::from_iter(vec![(sole_validator, total_voting_power)]);
        let tx_data = TxEthBridgeData {
            updates,
            total_voting_power,
            voting_powers,
        }
        .try_to_vec()
        .unwrap();
        tx_host_env::init();

        let result = apply_aux(tx_data);

        if let Err(err) = result {
            panic!("apply_aux error: {:?}", err);
        }
        let env = tx_host_env::take();
        assert_eq!(env.all_touched_storage_keys().len(), 0);
    }

    #[test]
    fn test_apply_tx_bad_tx_data() {
        let tx_data = b"bad data".try_to_vec().unwrap();
        tx_host_env::init();

        let result = apply_aux(tx_data);

        assert!(result.is_err());
    }
}
