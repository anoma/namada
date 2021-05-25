use anoma_vm_env::tx_prelude::*;

#[transaction]
fn apply_tx(tx_data: vm_memory::Data) {
    log_string(format!("apply_tx called with data: {:#?}", tx_data));
}
