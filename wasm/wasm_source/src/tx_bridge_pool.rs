//! A tx for adding a transfer request across the Ethereum bridge
//! into the bridge pool.
use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use eth_bridge_pool::{GasFee, PendingTransfer};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(tx_data: Vec<u8>) {
    let signed = SignedTxData::try_from_slice(&tx_data[..]).unwrap();
    let transfer =  PendingTransfer::try_from_slice(
        &signed.data.unwrap()[..]
    )
    .unwrap();
    // pay the gas fees
    let GasFee {
        amount,
        ref payer,
    } = transfer.gas_fees;
    token::transfer(payer, &BRIDGE_POOL_ADDRESS, &address::xan(), amount);
    // add transfer into the pool
    let pending_key = bridge_pool::get_pending_key();
    let mut pending: HashSet<PendingTransfer> = read(&pending_key).unwrap();
    pending.insert(transfer);
    write(pending_key, pending.try_to_vec().unwrap());
}