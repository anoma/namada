use anoma_data_template::*;
use anoma_vm_env::{transaction, tx_prelude::*};

transaction! {
    fn apply_tx(tx_data: vm_memory::Data) {
        let tx = TxData::try_from_slice(&tx_data[..]).unwrap();
        log_string(format!("apply_tx called with tx_data: {:#?}", tx));
        for Transfer {
            source,
            target,
            token,
            amount,
        } in tx.transfers
        {
            token_transfer(&source, &target, &token, amount)
        }
    }
}
