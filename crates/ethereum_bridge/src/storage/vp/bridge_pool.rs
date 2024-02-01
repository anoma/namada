use namada_core::ethereum_events::Uint;
use namada_state::{DBIter, StorageHasher, WlStorage, DB};
use namada_storage::StorageWrite;
use namada_trans_token::storage_key::balance_key;
use namada_trans_token::Amount;

use crate::storage::bridge_pool::{get_nonce_key, BRIDGE_POOL_ADDRESS};

/// Initialize the storage owned by the Bridge Pool VP.
///
/// This means that the amount of escrowed gas fees is
/// initialized to 0.
pub fn init_storage<D, H>(wl_storage: &mut WlStorage<D, H>)
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    let escrow_key =
        balance_key(&wl_storage.storage.native_token, &BRIDGE_POOL_ADDRESS);
    wl_storage.write(&escrow_key, Amount::default()).expect(
        "Initializing the escrow balance of the Bridge pool VP shouldn't fail.",
    );
    wl_storage
        .write(&get_nonce_key(), Uint::from(0))
        .expect("Initializing the Bridge pool nonce shouldn't fail.");
}
