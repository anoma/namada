use borsh::BorshSerialize;
use namada_core::ledger::eth_bridge::storage::bridge_pool::BRIDGE_POOL_ADDRESS;
use namada_core::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada_core::types::address::nam;
use namada_core::types::token::{balance_key, Amount};

/// Initialize the storage owned by the Bridge Pool VP.
///
/// This means that the amount of escrowed gas fees is
/// initialized to 0.
pub fn init_storage<D, H>(storage: &mut Storage<D, H>)
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    let escrow_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
    storage
        .write(
            &escrow_key,
            Amount::default()
                .try_to_vec()
                .expect("Serializing an amount shouldn't fail."),
        )
        .expect(
            "Initializing the escrow balance of the Bridge pool VP shouldn't \
             fail.",
        );
}
