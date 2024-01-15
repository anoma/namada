//! IBC integration

pub use namada_core::ledger::ibc::storage;
use namada_core::ledger::ibc::storage::{
    channel_counter_key, client_counter_key, connection_counter_key,
};
use namada_core::ledger::storage::WlStorage;
use namada_core::ledger::storage_api::StorageWrite;

use crate::ledger::storage::{self as ledger_storage, StorageHasher};

/// Initialize storage in the genesis block.
pub fn init_genesis_storage<DB, H>(storage: &mut WlStorage<DB, H>)
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
{
    // In ibc-go, u64 like a counter is encoded with big-endian:
    // https://github.com/cosmos/ibc-go/blob/89ffaafb5956a5ea606e1f1bf249c880bea802ed/modules/core/04-channel/keeper/keeper.go#L115

    // the client counter
    let key = client_counter_key();
    let value = 0_u64.to_be_bytes().to_vec();
    storage
        .write_bytes(&key, value)
        .expect("Unable to write the initial client counter");

    // the connection counter
    let key = connection_counter_key();
    let value = 0_u64.to_be_bytes().to_vec();
    storage
        .write_bytes(&key, value)
        .expect("Unable to write the initial connection counter");

    // the channel counter
    let key = channel_counter_key();
    let value = 0_u64.to_be_bytes().to_vec();
    storage
        .write_bytes(&key, value)
        .expect("Unable to write the initial channel counter");
}
