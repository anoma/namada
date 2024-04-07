use namada_storage::{StorageRead, StorageWrite};

use crate::ADDRESS;

/// Initialize the storage owned by the Ethereum Bridge VP.
///
/// This means that the amount of escrowed Nam is
/// initialized to 0.
pub fn init_storage<S>(storage: &mut S)
where
    S: StorageRead + StorageWrite,
{
    namada_trans_token::init_bridge_storage(storage, &ADDRESS);
}
