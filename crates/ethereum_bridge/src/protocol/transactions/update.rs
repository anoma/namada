//! Helpers for writing to storage
use eyre::Result;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::hash::StorageHasher;
use namada_core::storage;
use namada_core::token::{Amount, AmountError};
use namada_state::{DBIter, WlState, DB};
use namada_storage::StorageWrite;

/// Reads the `Amount` from key, applies update then writes it back
pub fn amount<D, H>(
    state: &mut WlState<D, H>,
    key: &storage::Key,
    update: impl FnOnce(&mut Amount) -> Result<(), AmountError>,
) -> Result<Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut amount = super::read::amount_or_default(state, key)?;
    update(&mut amount)?;
    state.write(key, amount)?;
    Ok(amount)
}

#[allow(dead_code)]
/// Reads an arbitrary value, applies update then writes it back
pub fn value<D, H, T: BorshSerialize + BorshDeserialize>(
    state: &mut WlState<D, H>,
    key: &storage::Key,
    update: impl FnOnce(&mut T),
) -> Result<T>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut value = super::read::value(state, key)?;
    update(&mut value);
    state.write(key, &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use eyre::eyre;
    use namada_state::testing::TestState;
    use namada_storage::StorageRead;

    use super::*;

    #[test]
    /// Test updating a value
    fn test_value() -> Result<()> {
        let key = storage::Key::parse("some arbitrary key")
            .expect("could not set up test");
        let value = 21i32;
        let mut state = TestState::default();
        state.write(&key, value).expect("could not set up test");

        super::value(&mut state, &key, |v: &mut i32| *v *= 2)?;

        let new_val = state.read_bytes(&key)?;
        let new_val = match new_val {
            Some(new_val) => <i32>::try_from_slice(&new_val)?,
            None => return Err(eyre!("no value found")),
        };
        assert_eq!(new_val, 42);
        Ok(())
    }
}
