//! Helpers for writing to storage
use borsh::{BorshDeserialize, BorshSerialize};
use eyre::Result;
use namada::types::storage;
use namada::types::token::Amount;

use super::Store;

/// Reads the `Amount` from key, applies update then writes it back
pub(super) fn amount(
    store: &mut impl Store,
    key: &storage::Key,
    update: impl Fn(&mut Amount),
) -> Result<Amount> {
    let mut amount = super::read::amount_or_default(store, key)?;
    update(&mut amount);
    store.write(key, amount.try_to_vec()?)?;
    Ok(amount)
}

#[allow(dead_code)]
/// Reads an arbitrary value, applies update then writes it back
pub(super) fn value<T: BorshSerialize + BorshDeserialize>(
    store: &mut impl Store,
    key: &storage::Key,
    update: impl Fn(&mut T),
) -> Result<T> {
    let mut value = super::read::value(store, key)?;
    update(&mut value);
    store.write(key, value.try_to_vec()?)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use borsh::{BorshDeserialize, BorshSerialize};
    use eyre::{eyre, Result};
    use namada::types::storage;

    use crate::node::ledger::protocol::transactions::store::testing::FakeStorage;
    use crate::node::ledger::protocol::transactions::store::Store;

    #[test]
    fn test_value() -> Result<()> {
        let key = storage::Key::parse("some arbitrary key")
            .expect("could not set up test");
        let value = 21;
        let mut fake_storage = FakeStorage::default();
        let serialized = value.try_to_vec().expect("could not set up test");
        fake_storage
            .write(&key, serialized)
            .expect("could not set up test");

        super::value(&mut fake_storage, &key, |v: &mut i32| *v *= 2)?;

        let new_val = fake_storage.read(&key)?;
        let new_val = match new_val {
            Some(new_val) => <i32>::try_from_slice(&new_val)?,
            None => return Err(eyre!("no value found")),
        };
        assert_eq!(new_val, 42);
        Ok(())
    }
}
