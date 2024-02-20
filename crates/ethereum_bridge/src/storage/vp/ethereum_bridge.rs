use namada_storage::{StorageRead, StorageWrite};
use namada_trans_token::storage_key::balance_key;
use namada_trans_token::Amount;

use crate::ADDRESS;

/// Initialize the storage owned by the Ethereum Bridge VP.
///
/// This means that the amount of escrowed Nam is
/// initialized to 0.
pub fn init_storage<S>(storage: &mut S)
where
    S: StorageRead + StorageWrite,
{
    let escrow_key =
        balance_key(&storage.get_native_token().unwrap(), &ADDRESS);
    storage.write(&escrow_key, Amount::default()).expect(
        "Initializing the escrow balance of the Ethereum Bridge VP shouldn't \
         fail.",
    );
}
