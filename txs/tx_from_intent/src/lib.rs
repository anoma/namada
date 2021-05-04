use anoma_vm_env::{transaction, tx_prelude::*};

transaction! {
    fn apply_tx(tx_data: vm_memory::Data) {
        let signed = key::ed25519::SignedTxData::try_from_slice(&tx_data[..]).unwrap();
        let transfers = intent::IntentTransfers::try_from_slice(&signed.data[..]).unwrap();
        log_string(format!("apply_tx called with intent transfers: {:#?}", transfers));

        // make sure that the matchmaker has to validate this tx
        insert_verifier(address::matchmaker());

        let token::Transfer {source, target, token, amount} = transfers.transfer_1;
        token::transfer(&source, &target, &token, amount);
        let token::Transfer {source, target, token, amount} = transfers.transfer_2;
        token::transfer(&source, &target, &token, amount)
    }
}
