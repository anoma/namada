use namada_core::borsh::BorshSerializeExt;
use namada_core::ledger::eth_bridge::ADDRESS;
use namada_core::types::hash::StorageHasher;
use namada_state::{DBIter, WlStorage, DB};
use namada_storage::StorageWrite;
use namada_trans_token::storage_key::balance_key;
use namada_trans_token::Amount;

/// Initialize the storage owned by the Ethereum Bridge VP.
///
/// This means that the amount of escrowed Nam is
/// initialized to 0.
pub fn init_storage<D, H>(wl_storage: &mut WlStorage<D, H>)
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    let escrow_key = balance_key(&wl_storage.storage.native_token, &ADDRESS);
    wl_storage
        .write_bytes(&escrow_key, Amount::default().serialize_to_vec())
        .expect(
            "Initializing the escrow balance of the Ethereum Bridge VP \
             shouldn't fail.",
        );
}
