//! Validity predicate environment contains functions that can be called from
//! inside validity predicates.

use crate::ledger::gas::VpGasMeter;
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{self, write_log, Storage, StorageHasher};
use crate::types::storage::{BlockHash, BlockHeight, Key};

/// Add a gas cost incured in a validity predicate
pub fn add_gas(gas_meter: &mut VpGasMeter, used_gas: u64) {
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
pub fn read_pre<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    key: &Key,
) -> Option<Vec<u8>>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (value, gas) = storage.read(&key).expect("storage read failed");
    add_gas(gas_meter, gas);
    value
}

/// Storage read posterior state (after tx execution). It will try to read from
/// the write log first and if no entry found then from the storage.
pub fn read_post<DB, H>(
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
    add_gas(gas_meter, gas);
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
            add_gas(gas_meter, gas);
            value
        }
    }
}

/// Storage `has_key` in prior state (before tx execution). It will try to read
/// from the storage.
pub fn has_key_pre<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
    key: &Key,
) -> bool
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (present, gas) = storage.has_key(key).expect("storage has_key failed");
    add_gas(gas_meter, gas);
    present
}

/// Storage `has_key` in posterior state (after tx execution). It will try to
/// check the write log first and if no entry found then the storage.
pub fn has_key_post<DB, H>(
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
    add_gas(gas_meter, gas);
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
            add_gas(gas_meter, gas);
            present
        }
    }
}

/// Getting the chain ID.
pub fn get_chain_id<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> String
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (chain_id, gas) = storage.get_chain_id();
    add_gas(gas_meter, gas);
    chain_id
}

/// Getting the block height. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_block_height<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> BlockHeight
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (height, gas) = storage.get_block_height();
    add_gas(gas_meter, gas);
    height
}

/// Getting the block hash. The height is that of the block to which the
/// current transaction is being applied.
pub fn get_block_hash<DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &Storage<DB, H>,
) -> BlockHash
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (hash, gas) = storage.get_block_hash();
    add_gas(gas_meter, gas);
    hash
}

/// Storage prefix iterator. It will try to get an iterator from the storage.
pub fn iter_prefix<'a, DB, H>(
    gas_meter: &mut VpGasMeter,
    storage: &'a Storage<DB, H>,
    prefix: &Key,
) -> <DB as storage::DBIter<'a>>::PrefixIter
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
{
    let (iter, gas) = storage.iter_prefix(prefix);
    add_gas(gas_meter, gas);
    iter
}

/// Storage prefix iterator for prior state (before tx execution). It will try
/// to read from the storage.
pub fn iter_pre_next<DB>(
    gas_meter: &mut VpGasMeter,
    iter: &mut <DB as storage::DBIter<'_>>::PrefixIter,
) -> Option<(String, Vec<u8>)>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    if let Some((key, val, gas)) = iter.next() {
        add_gas(gas_meter, gas);
        return Some((key, val));
    }
    None
}

/// Storage prefix iterator next for posterior state (after tx execution). It
/// will try to read from the write log first and if no entry found then from
/// the storage.
pub fn iter_post_next<DB>(
    gas_meter: &mut VpGasMeter,
    write_log: &WriteLog,
    iter: &mut <DB as storage::DBIter<'_>>::PrefixIter,
) -> Option<(String, Vec<u8>)>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
{
    for (key, val, iter_gas) in iter {
        let (log_val, log_gas) = write_log.read(
            &Key::parse(key.clone()).expect("Cannot parse the key string"),
        );
        add_gas(gas_meter, iter_gas + log_gas);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                return Some((key, value.clone()));
            }
            Some(&write_log::StorageModification::Delete) => {
                // check the next because the key has already deleted
                continue;
            }
            Some(&write_log::StorageModification::InitAccount { .. }) => {
                // a VP of a new account doesn't need to be iterated
                continue;
            }
            None => return Some((key, val)),
        }
    }
    None
}
