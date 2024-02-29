use namada_core::ethereum_events::Uint;
use namada_storage::{StorageRead, StorageWrite};
use namada_trans_token::storage_key::balance_key;
use namada_trans_token::Amount;

use crate::storage::bridge_pool::{get_nonce_key, BRIDGE_POOL_ADDRESS};

/// Initialize the storage owned by the Bridge Pool VP.
///
/// This means that the amount of escrowed gas fees is
/// initialized to 0.
pub fn init_storage<S>(storage: &mut S)
where
    S: StorageRead + StorageWrite,
{
    let escrow_key =
        balance_key(&storage.get_native_token().unwrap(), &BRIDGE_POOL_ADDRESS);
    storage.write(&escrow_key, Amount::default()).expect(
        "Initializing the escrow balance of the Bridge pool VP shouldn't fail.",
    );
    storage
        .write(&get_nonce_key(), Uint::from(0))
        .expect("Initializing the Bridge pool nonce shouldn't fail.");
}
