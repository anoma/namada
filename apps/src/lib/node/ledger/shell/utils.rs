use borsh::BorshDeserialize;
use namada::ledger::storage_api::{self, StorageRead};
use namada::types::storage::Key;

pub(super) fn force_read<S, T>(storage: &S, key: &Key) -> storage_api::Result<T>
where
    S: StorageRead,
    T: BorshDeserialize,
{
    storage
        .read::<T>(key)
        .transpose()
        .expect("Storage key must be present.")
}
