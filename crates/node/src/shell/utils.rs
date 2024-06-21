use borsh::BorshDeserialize;
use namada_sdk::state::{self, StorageRead};
use namada_sdk::storage::Key;

pub(super) fn force_read<S, T>(
    storage: &S,
    key: &Key,
) -> state::StorageResult<T>
where
    S: StorageRead,
    T: BorshDeserialize,
{
    storage
        .read::<T>(key)
        .transpose()
        .expect("Storage key must be present.")
}
