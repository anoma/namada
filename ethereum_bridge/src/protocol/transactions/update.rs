//! Helpers for writing to storage
use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{eyre, Result};
use namada_core::ledger::storage::{DBIter, StorageHasher, WlStorage, DB};
use namada_core::ledger::storage_api::StorageWrite;
use namada_core::types::address::nam;
use namada_core::types::storage;
use namada_core::types::token::{is_balance_key, Amount, TokenAmount};

/// Reads the `Amount` from key, applies update then writes it back
pub fn amount<D, H, T>(
    wl_storage: &mut WlStorage<D, H>,
    key: &storage::Key,
    update: impl FnOnce(Option<T>) -> T,
) -> Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: TokenAmount + TryInto<Amount>,
    <T as TryInto<Amount>>::Error: Debug,
{
    let amount = update(super::read::maybe_value(wl_storage, key)?);
    if is_balance_key(&nam(), key).is_some() {
        let to_write = amount.try_into().map_err(|e| {
            eyre!("Failed to convert to type `Amount`: {:?}", e)
        })?;
        wl_storage.write_bytes(key, to_write.try_to_vec()?)?;
    } else {
        wl_storage.write_bytes(key, amount.try_to_vec()?)?;
    }
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
    wl_storage.write_bytes(key, value.try_to_vec()?)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use borsh::{BorshDeserialize, BorshSerialize};
    use eyre::{eyre, Result};
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
    use namada_core::types::storage;

    #[test]
    /// Test updating a value
    fn test_value() -> Result<()> {
        let key = storage::Key::parse("some arbitrary key")
            .expect("could not set up test");
        let value = 21;
        let mut wl_storage = TestWlStorage::default();
        let serialized = value.try_to_vec().expect("could not set up test");
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
