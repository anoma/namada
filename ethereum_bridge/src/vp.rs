use borsh::BorshSerialize;
use namada_core::ledger::storage::{self as ledger_storage, StorageHasher};
use namada_core::types::address::nam;
use namada_core::types::token::{balance_key, Amount};

/// Initialize the storage owned by the Ethereum Bridge VP.
///
/// This means that the amount of escrowed Nam is
/// initialized to 0.
pub fn init_storage<D, H>(storage: &mut ledger_storage::Storage<D, H>)
where
    D: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
{
    let escrow_key =
        balance_key(&nam(), &namada_core::ledger::eth_bridge::ADDRESS);
    storage
        .write(
            &escrow_key,
            Amount::default()
                .try_to_vec()
                .expect("Serializing an amount shouldn't fail."),
        )
        .expect(
            "Initializing the escrow balance of the Ethereum Bridge VP \
             shouldn't fail.",
        );
}
