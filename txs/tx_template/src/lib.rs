use anoma_vm_env::tx_prelude::*;
use anoma_vm_macro::transaction;

#[transaction]
fn apply_tx(tx_data: vm_memory::Data) {
    log_string(format!("apply_tx called with data: {:#?}", tx_data));
}
