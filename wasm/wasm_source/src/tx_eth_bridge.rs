//! A tx which is applied during FinalizeBlock to update /eth_msgs storage
use anoma_tx_prelude::*;

const TX_NAME: &str = "tx_eth_bridge";

fn log(msg: &str) {
    log_string(format!("[{}] {}", TX_NAME, msg))
}

#[transaction]
fn apply_tx(tx_data: Vec<u8>) {
    // tx_data shouldn't be signed, as any full node should be able to apply
    // this transaction to their storage out-of-band
    log(&format!("got data - {} bytes", tx_data.len()))

    // TODO: extract Vec<EthMsgDiffs>
    // TODO: look at /eth_msgs storage, calculate new state
    // TODO: write new state
}
