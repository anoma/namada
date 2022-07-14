//! code that should be executed within a transaction
use std::error::Error;

use anoma::ledger::eth_bridge::storage;
use anoma::proto::Tx;
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
    Tx::try_from_slice(&tx_data)?;
    Ok(())

    // TODO: extract Vec<EthMsgDiffs>
    // TODO: look at /eth_msgs storage, calculate new state
    // TODO: write new state
}
