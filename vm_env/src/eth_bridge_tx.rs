//! code that should be executed within a transaction
use anoma::ledger::eth_bridge::storage;

use crate::imports::vp::log_string;

const TX_NAME: &str = "tx_eth_bridge";

fn log(msg: &str) {
    log_string(format!("[{}] {}", TX_NAME, msg))
}

pub fn apply(tx_data: Vec<u8>) {
    // tx_data shouldn't be signed, as any full node should be able to apply
    // this transaction to their storage out-of-band
    log(&format!("got data - {} bytes", tx_data.len()));
    log(&format!("/eth_msgs key - {}", storage::eth_msgs_key()))

    // TODO: extract Vec<EthMsgDiffs>
    // TODO: look at /eth_msgs storage, calculate new state
    // TODO: write new state
}
