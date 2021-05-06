use anoma_vm_env::{transaction, tx_prelude::*};

transaction! {
    fn apply_tx(tx_data: vm_memory::Data) {
        let signed = key::ed25519::SignedTxData::try_from_slice(&tx_data[..]).unwrap();
        let transfer = token::Transfer::try_from_slice(&signed.data[..]).unwrap();
        log_string(format!("apply_tx called with transfer: {:#?}", transfer));
        let token::Transfer {source, target, token, amount} = transfer;
        token::transfer(&source, &target, &token, amount)
    }
}
