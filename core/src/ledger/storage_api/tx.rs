//! Tx storage_api functions

use super::StorageRead;
use crate::ledger::parameters::storage::get_max_tx_bytes_key;
use crate::ledger::storage_api;

/// Validate the size of a tx.
pub fn validate_tx_bytes<S>(
    storage: &S,
    tx_size: usize,
) -> storage_api::Result<bool>
where
    S: StorageRead,
{
    let max_tx_bytes: u32 = storage
        .read(&get_max_tx_bytes_key())?
        .expect("The max tx bytes param should be present in storage");
    Ok(tx_size <= max_tx_bytes as usize)
}
