//! Validity predicate environment contains functions that can be called from
//! inside validity predicates.

use crate::ledger::gas::VpGasMeter;
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{self, write_log, Storage, StorageHasher};
use crate::types::storage::{BlockHash, BlockHeight, Key};

/// Add a gas cost incured in a validity predicate
pub fn vp_add_gas(gas_meter: &mut VpGasMeter, used_gas: u64) {
    if let Err(err) = gas_meter.add(used_gas) {
        tracing::warn!(
            "Stopping transaction execution because of gas error: {}",
            err
        );
        unreachable!()
    }
}

/// Storage read prior state (before tx execution). It will try to read from the
/// storage.
pub fn vp_read_pre<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    key: &Key,
) -> Option<Vec<u8>>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (value, gas) = storage.read(&key).expect("storage read failed");
    vp_add_gas(gas_meter, gas);
    value
}

/// Storage read posterior state (after tx execution). It will try to read from
/// the write log first and if no entry found then from the storage.
pub fn vp_read_post<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    write_log: &WriteLog,
    key: &Key,
) -> Option<Vec<u8>>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    // Try to read from the write log first
    let (log_val, gas) = write_log.read(&key);
    vp_add_gas(gas_meter, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { ref value }) => {
            Some(value.clone())
        }
        Some(&write_log::StorageModification::Delete) => {
            // Given key has been deleted
            None
        }
        Some(&write_log::StorageModification::InitAccount {
            ref vp, ..
        }) => {
            // Read the VP of a new account
            Some(vp.clone())
        }
        None => {
            // When not found in write log, try to read from the storage
            let (value, gas) = storage.read(&key).expect("storage read failed");
            vp_add_gas(gas_meter, gas);
            value
        }
    }
}

/// Storage `has_key` in prior state (before tx execution). It will try to read
/// from the storage.
pub fn vp_has_key_pre<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    key: &Key,
) -> bool
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (present, gas) = storage.has_key(key).expect("storage has_key failed");
    vp_add_gas(gas_meter, gas);
    present
}

/// Storage `has_key` in posterior state (after tx execution). It will try to
/// check the write log first and if no entry found then the storage.
pub fn vp_has_key_post<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    write_log: &WriteLog,
    key: &Key,
) -> bool
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    // Try to read from the write log first
    let (log_val, gas) = write_log.read(&key);
    vp_add_gas(gas_meter, gas);
    match log_val {
        Some(&write_log::StorageModification::Write { .. }) => true,
        Some(&write_log::StorageModification::Delete) => {
            // The given key has been deleted
            false
        }
        Some(&write_log::StorageModification::InitAccount { .. }) => true,
        None => {
            // When not found in write log, try to check the storage
            let (present, gas) =
                storage.has_key(&key).expect("storage has_key failed");
            vp_add_gas(gas_meter, gas);
            present
        }
    }
}

/// Getting the chain ID.
pub fn vp_get_chain_id<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> String
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (chain_id, gas) = storage.get_chain_id();
    vp_add_gas(gas_meter, gas);
    chain_id
}

/// Getting the block height. The height is that of the block to which the
/// current transaction is being applied.
pub fn vp_get_block_height<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> BlockHeight
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (height, gas) = storage.get_block_height();
    vp_add_gas(gas_meter, gas);
    height
}

/// Getting the block hash. The height is that of the block to which the
/// current transaction is being applied.
pub fn vp_get_block_hash<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> BlockHash
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (hash, gas) = storage.get_block_hash();
    vp_add_gas(gas_meter, gas);
    hash
}

// TODO add prefix iterators and eval
