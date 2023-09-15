//! Helpers for writing to storage
use borsh::{BorshDeserialize, BorshSerialize};
use eyre::Result;
use namada_core::ledger::storage::{DBIter, StorageHasher, WlStorage, DB};
use namada_core::ledger::storage_api::StorageWrite;
use namada_core::types::storage;
use namada_core::types::token::Amount;

/// Reads the `Amount` from key, applies update then writes it back
pub fn amount<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    key: &storage::Key,
    update: impl FnOnce(&mut Amount),
) -> Result<Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut amount = super::read::amount_or_default(wl_storage, key)?;
    update(&mut amount);
    wl_storage.write_bytes(key, borsh::to_vec(&amount)?)?;
    Ok(amount)
}

#[allow(dead_code)]
/// Reads an arbitrary value, applies update then writes it back
pub fn value<D, H, T: BorshSerialize + BorshDeserialize>(
    wl_storage: &mut WlStorage<D, H>,
    key: &storage::Key,
    update: impl FnOnce(&mut T),
) -> Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut value = super::read::value(wl_storage, key)?;
    update(&mut value);
    wl_storage.write_bytes(key, borsh::to_vec(&value)?)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use borsh::BorshDeserialize;
    use borsh_ext::BorshSerializeExt;
    use eyre::{eyre, Result};
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
    use namada_core::types::storage;

    #[test]
    /// Test updating a value
    fn test_value() -> Result<()> {
        let key = storage::Key::parse("some arbitrary key")
            .expect("could not set up test");
        let value = 21u64;
        let mut wl_storage = TestWlStorage::default();
        let serialized = value.serialize_to_vec();
        wl_storage
            .write_bytes(&key, serialized)
            .expect("could not set up test");

        super::value(&mut wl_storage, &key, |v: &mut i32| *v *= 2)?;

        let new_val = wl_storage.read_bytes(&key)?;
        let new_val = match new_val {
            Some(new_val) => <i32>::try_from_slice(&new_val)?,
            None => return Err(eyre!("no value found")),
        };
        assert_eq!(new_val, 42);
        Ok(())
    }
}
