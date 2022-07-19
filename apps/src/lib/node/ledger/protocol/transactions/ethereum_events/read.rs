//! Helpers for reading from storage
use borsh::BorshDeserialize;
use eyre::{eyre, Result};
use namada::types::storage;
use namada::types::token::Amount;

use super::Store;

/// Returns the stored Amount, or 0 if not stored
pub(super) fn amount_or_default(
    store: &impl Store,
    key: &storage::Key,
) -> Result<Amount> {
    let amount = match maybe_value(store, key)? {
        Some(amount) => amount,
        None => Amount::from(0),
    };
    Ok(amount)
}

/// Read some arbitrary value from storage, erroring if it's not found
pub(super) fn value<T: BorshDeserialize>(
    store: &impl Store,
    key: &storage::Key,
) -> Result<T> {
    maybe_value(store, key)?.ok_or_else(|| eyre!("no value found at {}", key))
}

/// Try to read some arbitrary value from storage, returning `None` if nothing
/// is read. This will still error if there is data stored at `key` but it is
/// not deserializable to `T`.
pub(super) fn maybe_value<T: BorshDeserialize>(
    storage: &impl Store,
    key: &storage::Key,
) -> Result<Option<T>> {
    let maybe_val = storage.read(key)?;
    let bytes = match maybe_val {
        Some(bytes) => bytes,
        None => return Ok(None),
    };
    let deserialized = T::try_from_slice(&bytes[..])?;
    Ok(Some(deserialized))
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use borsh::BorshSerialize;
    use namada::types::storage;
    use namada::types::token::Amount;

    use crate::node::ledger::protocol::transactions::ethereum_events::read;
    use crate::node::ledger::protocol::transactions::store::testing::FakeStorage;
    use crate::node::ledger::protocol::transactions::store::Store;

    #[test]
    fn test_amount_returns_zero_for_uninitialized_storage() {
        let fake_storage = FakeStorage::default();
        let a = read::amount_or_default(
            &fake_storage,
            &storage::Key::parse(
                "some arbitrary key with no stored
        value",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(a, Amount::from(0));
    }

    #[test]
    fn test_amount_returns_stored_amount() {
        let key = storage::Key::parse("some arbitrary key").unwrap();
        let amount = Amount::from(1_000_000);
        let mut fake_storage = FakeStorage::default();
        fake_storage
            .write(&key, amount.try_to_vec().unwrap())
            .unwrap();

        let a = read::amount_or_default(&fake_storage, &key).unwrap();
        assert_eq!(a, amount);
    }

    #[test]
    fn test_amount_errors_if_not_amount() {
        let key = storage::Key::parse("some arbitrary key").unwrap();
        let amount = "not an Amount type";
        let mut fake_storage = FakeStorage::default();
        fake_storage.write(&key, amount.as_bytes()).unwrap();

        assert_matches!(read::amount_or_default(&fake_storage, &key), Err(_));
    }
}
