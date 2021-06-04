use std::collections::HashSet;

/// The matchmaker's host, used to communicate back from the VM
pub trait MmHost {
    fn remove_intents(&self, intents_id: HashSet<Vec<u8>>);
    fn inject_tx(&self, tx_data: Vec<u8>);
    fn update_data(&self, data: Vec<u8>);
}
