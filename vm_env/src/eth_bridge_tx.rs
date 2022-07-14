//! code that should be executed within a transaction
use std::error::Error;

use anoma::ledger::eth_bridge::storage;
use anoma::types::ethereum_events::EthMsgDiff;
use borsh::BorshDeserialize;

use crate::imports::tx::log_string;

const TX_NAME: &str = "tx_eth_bridge";

fn log(msg: &str) {
    log_string(format!("[{}] {}", TX_NAME, msg))
}

pub fn apply(tx_data: Vec<u8>) {
    if let Err(err) = apply_aux(tx_data) {
        log(&format!("ERROR: {:?}", err));
        panic!("{:?}", err)
    }
}

pub fn apply_aux(tx_data: Vec<u8>) -> Result<(), Box<dyn Error>> {
    log(&format!("got data - {} bytes", tx_data.len()));
    log(&format!("/eth_msgs key - {}", storage::eth_msgs_key()));

    let diffs: Vec<EthMsgDiff> = BorshDeserialize::try_from_slice(&tx_data)?;
    log(&format!("deserialized diffs - length = {}", diffs.len()));
    Ok(())

    // TODO: extract Vec<EthMsgDiffs>
    // TODO: look at /eth_msgs storage, calculate new state
    // TODO: write new state
}

#[cfg(test)]
mod tests {
    use anoma::types::address;
    use anoma::types::ethereum_events::testing::{
        arbitrary_amount, arbitrary_eth_address, arbitrary_nonce,
    };
    use anoma::types::ethereum_events::{
        EthMsgDiff, EthereumEvent, TransferToNamada,
    };
    use anoma_tests::tx::tx_host_env;
    use borsh::BorshSerialize;

    use super::*;
    #[test]
    fn test_happy_path() {
        let sole_validator = address::testing::gen_established_address();
        let receiver = address::testing::established_address_2();

        let diff = EthMsgDiff {
            body: EthereumEvent::TransfersToNamada {
                nonce: arbitrary_nonce(),
                transfers: vec![TransferToNamada {
                    amount: arbitrary_amount(),
                    asset: arbitrary_eth_address(),
                    receiver,
                }],
            },
            seen_by: vec![sole_validator],
        };
        let tx_data = vec![diff].try_to_vec().unwrap();
        tx_host_env::init();

        let result = apply_aux(tx_data);

        if let Err(err) = result {
            panic!("apply_aux error: {:?}", err);
        }
        let env = tx_host_env::take();
        // TODO: we should touch 4 keys for storage update
        assert_eq!(env.all_touched_storage_keys().len(), 0);
        // TODO: check specific keys e.g. /eth_msg/$msg_hash/body
    }
}
