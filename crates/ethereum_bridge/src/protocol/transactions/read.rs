//! Helpers for reading from storage
use borsh::BorshDeserialize;
use eyre::{eyre, Result};
use namada_core::storage;
use namada_core::token::Amount;
use namada_state::{DBIter, StorageHasher, WlState, DB};
use namada_storage::StorageRead;

/// Returns the stored Amount, or 0 if not stored
pub(super) fn amount_or_default<D, H>(
    state: &WlState<D, H>,
    key: &storage::Key,
) -> Result<Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    Ok(maybe_value(state, key)?.unwrap_or_default())
}

/// Read some arbitrary value from storage, erroring if it's not found
pub(super) fn value<D, H, T: BorshDeserialize>(
    state: &WlState<D, H>,
    key: &storage::Key,
) -> Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    maybe_value(state, key)?.ok_or_else(|| eyre!("no value found at {}", key))
}

/// Try to read some arbitrary value from storage, returning `None` if nothing
/// is read. This will still error if there is data stored at `key` but it is
/// not deserializable to `T`.
pub(super) fn maybe_value<D, H, T: BorshDeserialize>(
    state: &WlState<D, H>,
    key: &storage::Key,
) -> Result<Option<T>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let maybe_val = state.read_bytes(key)?;
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
    use namada_core::storage;
    use namada_core::token::Amount;
    use namada_state::testing::TestState;
    use namada_storage::StorageWrite;

    use crate::protocol::transactions::read;

    #[test]
    fn test_amount_returns_zero_for_uninitialized_storage() {
        let fake_storage = TestState::default();
        let amt = read::amount_or_default(
            &fake_storage,
            &storage::Key::parse("some arbitrary key with no stored value")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(amt, Amount::from(0));
    }

    #[test]
    fn test_amount_returns_stored_amount() {
        let key = storage::Key::parse("some arbitrary key").unwrap();
        let amount = Amount::from(1_000_000);
        let mut fake_storage = TestState::default();
        fake_storage.write(&key, amount).unwrap();

        let amt = read::amount_or_default(&fake_storage, &key).unwrap();
        assert_eq!(amt, amount);
    }

    #[test]
    fn test_amount_errors_if_not_amount() {
        let key = storage::Key::parse("some arbitrary key").unwrap();
        let amount = "not an Amount type";
        let mut fake_storage = TestState::default();
        fake_storage.write(&key, amount).unwrap();

        assert_matches!(read::amount_or_default(&fake_storage, &key), Err(_));
    }
}
