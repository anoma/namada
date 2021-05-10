use anoma_vm_env::{transaction, tx_prelude::*};

transaction! {
    fn apply_tx(tx_data: vm_memory::Data) {
        let signed = key::ed25519::SignedTxData::try_from_slice(&tx_data[..]).unwrap();
        let update_vp = UpdateVp::try_from_slice(&signed.data[..]).unwrap();
        log_string(format!("update VP for: {:#?}", update_vp.addr));
        update_validity_predicate(update_vp.addr, update_vp.vp_code)
    }
}
