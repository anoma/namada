//! Helpers for writing to storage
use borsh::{BorshDeserialize, BorshSerialize};
use eyre::Result;
use namada::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada::types::storage;
use namada::types::token::Amount;

/// Reads the `Amount` from key, applies update then writes it back
pub fn amount<D, H>(
    store: &mut Storage<D, H>,
    key: &storage::Key,
    update: impl FnOnce(&mut Amount),
) -> Result<Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut amount = super::read::amount_or_default(store, key)?;
    update(&mut amount);
    store.write(key, amount.try_to_vec()?)?;
    Ok(amount)
}

#[allow(dead_code)]
/// Reads an arbitrary value, applies update then writes it back
pub fn value<D, H, T: BorshSerialize + BorshDeserialize>(
    store: &mut Storage<D, H>,
    key: &storage::Key,
    update: impl FnOnce(&mut T),
) -> Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut value = super::read::value(store, key)?;
    update(&mut value);
    store.write(key, value.try_to_vec()?)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use borsh::{BorshDeserialize, BorshSerialize};
    use eyre::{eyre, Result};
    use namada::ledger::storage::testing::TestStorage;
    use namada::types::storage;

    #[test]
    /// Test updating a value
    fn test_value() -> Result<()> {
        let key = storage::Key::parse("some arbitrary key")
            .expect("could not set up test");
        let value = 21;
        let mut storage = TestStorage::default();
        let serialized = value.try_to_vec().expect("could not set up test");
        storage
            .write(&key, serialized)
            .expect("could not set up test");

        super::value(&mut storage, &key, |v: &mut i32| *v *= 2)?;

        let (new_val, _) = storage.read(&key)?;
        let new_val = match new_val {
            Some(new_val) => <i32>::try_from_slice(&new_val)?,
            None => return Err(eyre!("no value found")),
        };
        assert_eq!(new_val, 42);
        Ok(())
    }
}
