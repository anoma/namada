//! IBC integration

use namada_core::event::EmitEvents;
use namada_core::token::Amount;
use namada_ibc::storage::{
    channel_counter_key, client_counter_key, connection_counter_key,
    deposit_prefix, withdraw_prefix,
};
pub use namada_ibc::{parameters, storage};
use namada_state::{
    DBIter, Key, State, StorageError, StorageHasher, StorageRead, StorageWrite,
    WlState, DB,
};

/// Initialize storage in the genesis block.
pub fn init_genesis_storage<S>(storage: &mut S)
where
    S: State,
{
    // In ibc-go, u64 like a counter is encoded with big-endian:
    // https://github.com/cosmos/ibc-go/blob/89ffaafb5956a5ea606e1f1bf249c880bea802ed/modules/core/04-channel/keeper/keeper.go#L115

    let init_value = 0_u64;

    // the client counter
    let key = client_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial client counter");

    // the connection counter
    let key = connection_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial connection counter");

    // the channel counter
    let key = channel_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial channel counter");
}

/// Update IBC-related data when finalizing block
pub fn finalize_block<D, H>(
    state: &mut WlState<D, H>,
    _events: &mut impl EmitEvents,
    is_new_epoch: bool,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if is_new_epoch {
        clear_throughputs(state)?;
    }
    Ok(())
}

/// Clear the per-epoch throughputs (deposit and withdraw)
fn clear_throughputs<D, H>(
    state: &mut WlState<D, H>,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    for prefix in [deposit_prefix(), withdraw_prefix()] {
        let keys: Vec<Key> = state
            .iter_prefix(&prefix)?
            .map(|(key, _, _)| {
                Key::parse(key).expect("The key should be parsable")
            })
            .collect();
        for key in keys {
            state.write(&key, Amount::from(0))?;
        }
    }

    Ok(())
}
