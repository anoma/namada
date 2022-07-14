//! A tx which is applied during FinalizeBlock to update /eth_msgs storage
use anoma_tx_prelude::{eth_bridge_tx, transaction};

#[transaction]
fn apply_tx(tx_data: Vec<u8>) {
    eth_bridge_tx::apply(tx_data);
}
