use borsh_ext::BorshSerializeExt;
use namada_core::ledger::storage::{self as ledger_storage, StorageHasher};
use namada_core::ledger::storage_api::StorageWrite;
use namada_core::types::token::{balance_key, Amount};

/// Initialize the storage owned by the Ethereum Bridge VP.
///
/// This means that the amount of escrowed Nam is
/// initialized to 0.
pub fn init_storage<D, H>(wl_storage: &mut ledger_storage::WlStorage<D, H>)
where
    D: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
{
    let escrow_key = balance_key(
        &wl_storage.storage.native_token,
        &namada_core::ledger::eth_bridge::ADDRESS,
    );
    wl_storage
        .write_bytes(&escrow_key, Amount::default().serialize_to_vec())
        .expect(
            "Initializing the escrow balance of the Ethereum Bridge VP \
             shouldn't fail.",
        );
}
