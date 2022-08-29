//! Lazy dynamically-sized vector.

use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use derivative::Derivative;
use thiserror::Error;

use super::super::Result;
use super::LazyCollection;
use crate::ledger::storage_api::validation::{self, Data};
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::ledger::vp_env::VpEnv;
use crate::types::storage;

/// Subkey pointing to the length of the LazyVec
pub const LEN_SUBKEY: &str = "len";
/// Subkey corresponding to the data elements of the LazyVec
pub const DATA_SUBKEY: &str = "data";

/// Using `u64` for vector's indices
pub type Index = u64;

/// Lazy dynamically-sized vector.
///
/// This can be used as an alternative to `std::collections::Vec`. In the lazy
/// vector, the elements do not reside in memory but are instead read and
/// written to storage sub-keys of the storage `key` used to construct the
/// vector.
pub struct LazyVec<T> {
    key: storage::Key,
    phantom: PhantomData<T>,
}

/// Possible sub-keys of a [`LazyVec`]
pub enum SubKey {
    /// Length sub-key
    Len,
    /// Data sub-key, further sub-keyed by its index
    Data(Index),
}

/// Possible sub-keys of a [`LazyVec`], together with their [`validation::Data`]
/// that contains prior and posterior state.
#[derive(Debug)]
pub enum SubKeyWithData<T> {
    /// Length sub-key
    Len(Data<Index>),
    /// Data sub-key, further sub-keyed by its index
    Data(Index, Data<T>),
}

/// Possible actions that can modify a [`LazyVec`]. This roughly corresponds to
/// the methods that have `StorageWrite` access.
pub enum Action<T> {
    /// Push a value `T` into a [`LazyVec<T>`]
    Push(T),
    /// Pop a value `T` from a [`LazyVec<T>`]
    Pop(T),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Incorrect difference in LazyVec's length")]
    InvalidLenDiff,
    #[error("An empty LazyVec must be deleted from storage")]
    EmptyVecShouldBeDeleted,
    #[error("Push at a wrong index. Got {got}, expected {expected}.")]
    UnexpectedPushIndex { got: Index, expected: Index },
    #[error("Pop at a wrong index. Got {got}, expected {expected}.")]
    UnexpectedPopIndex { got: Index, expected: Index },
    #[error(
        "Update (combination of pop and push) at a wrong index. Got {got}, \
         expected {expected}."
    )]
    UnexpectedUpdateIndex { got: Index, expected: Index },
    #[error("An index has overflown its representation: {0}")]
    IndexOverflow(<usize as TryInto<Index>>::Error),
    #[error("Unexpected underflow in `{0} - {0}`")]
    UnexpectedUnderflow(Index, Index),
}

/// [`LazyVec`] validation result
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

/// [`LazyVec`] validation builder from storage changes. The changes can be
/// accumulated with `LazyVec::validate()` and then turned into a list
/// of valid actions on the vector with `ValidationBuilder::build()`.
#[derive(Debug, Derivative)]
// https://mcarton.github.io/rust-derivative/latest/Default.html#custom-bound
#[derivative(Default(bound = ""))]
pub struct ValidationBuilder<T> {
    /// The accumulator of found changes under the vector
    pub changes: Vec<SubKeyWithData<T>>,
}

impl<T> LazyCollection for LazyVec<T> {
    /// Create or use an existing vector with the given storage `key`.
    fn new(key: storage::Key) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }
}

// Generic `LazyVec` methods that require no bounds on values `T`
impl<T> LazyVec<T> {
    /// Reads the number of elements in the vector.
    #[allow(clippy::len_without_is_empty)]
    pub fn len<S>(&self, storage: &S) -> Result<u64>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let len = storage.read(&self.get_len_key())?;
        Ok(len.unwrap_or_default())
    }

    /// Returns `true` if the vector contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        Ok(self.len(storage)? == 0)
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of vector's elements storage
    fn get_data_key(&self, index: Index) -> storage::Key {
        self.get_data_prefix().push(&index.to_string()).unwrap()
    }

    /// Get the sub-key of vector's length storage
    fn get_len_key(&self) -> storage::Key {
        self.key.push(&LEN_SUBKEY.to_owned()).unwrap()
    }
}

// `LazyVec` methods with borsh encoded values `T`
impl<T> LazyVec<T>
where
    T: BorshSerialize + BorshDeserialize + 'static,
{
    /// Appends an element to the back of a collection.
    pub fn push<S>(&self, storage: &mut S, val: T) -> Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let len = self.len(storage)?;
        let data_key = self.get_data_key(len);
        storage.write(&data_key, val)?;
        storage.write(&self.get_len_key(), len + 1)
    }

    /// Removes the last element from a vector and returns it, or `Ok(None)` if
    /// it is empty.
    ///
    /// Note that an empty vector is completely removed from storage.
    pub fn pop<S>(&self, storage: &mut S) -> Result<Option<T>>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let len = self.len(storage)?;
        if len == 0 {
            Ok(None)
        } else {
            let index = len - 1;
            let data_key = self.get_data_key(index);
            if len == 1 {
                storage.delete(&self.get_len_key())?;
            } else {
                storage.write(&self.get_len_key(), index)?;
            }
            let popped_val = storage.read(&data_key)?;
            storage.delete(&data_key)?;
            Ok(popped_val)
        }
    }

    /// Read an element at the index or `Ok(None)` if out of bounds.
    pub fn get<S>(&self, storage: &S, index: Index) -> Result<Option<T>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        storage.read(&self.get_data_key(index))
    }

    /// An iterator visiting all elements. The iterator element type is
    /// `Result<T>`, because iterator's call to `next` may fail with e.g. out of
    /// gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead<'iter>,
    ) -> Result<impl Iterator<Item = Result<T>> + 'iter> {
        let iter = storage_api::iter_prefix(storage, &self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (_key, val) = key_val_res?;
            Ok(val)
        }))
    }

    /// Check if the given storage key is a LazyVec sub-key and if so return
    /// which one
    pub fn is_sub_key(&self, key: &storage::Key) -> Option<SubKey> {
        if let Some((prefix, storage::DbKeySeg::StringSeg(last))) =
            key.split_last()
        {
            if let Ok(index) = Index::from_str(last) {
                if let Some((prefix, storage::DbKeySeg::StringSeg(snd_last))) =
                    prefix.split_last()
                {
                    if snd_last == DATA_SUBKEY && prefix.eq_owned(&self.key) {
                        return Some(SubKey::Data(index));
                    }
                }
            } else if last == LEN_SUBKEY && prefix.eq_owned(&self.key) {
                return Some(SubKey::Len);
            }
        }
        None
    }

    /// Accumulate storage changes inside a [`ValidationBuilder`]
    pub fn validate<ENV>(
        &self,
        builder: &mut Option<ValidationBuilder<T>>,
        env: &ENV,
        key_changed: storage::Key,
    ) -> std::result::Result<(), ENV::Error>
    where
        ENV: VpEnv,
    {
        if let Some(sub) = self.is_sub_key(&key_changed) {
            let change = match sub {
                SubKey::Len => {
                    let data = validation::read_data(env, &key_changed)?;
                    data.map(SubKeyWithData::Len)
                }
                SubKey::Data(index) => {
                    let data = validation::read_data(env, &key_changed)?;
                    data.map(|data| SubKeyWithData::Data(index, data))
                }
            };
            if let Some(change) = change {
                let builder =
                    builder.get_or_insert(ValidationBuilder::default());
                builder.changes.push(change)
            }
        }
        Ok(())
    }
}

impl<T> ValidationBuilder<T> {
    /// Validate storage changes and if valid, build from them a list of
    /// actions.
    ///
    /// The validation rules for a [`LazyVec`] are:
    ///   - A difference in the vector's length must correspond to the
    ///     difference in how many elements where pushed versus how many
    ///     elements were popped.
    ///   - An empty vector must be deleted from storage
    ///   - In addition, we check that indices of any changes are within an
    ///     expected range (i.e. the vectors indices should always be
    ///     monotonically increasing from zero)
    pub fn build(self) -> ValidationResult<Vec<Action<T>>> {
        let mut actions = vec![];

        // We need to accumlate some values for what's changed
        let mut post_gt_pre = false;
        let mut len_diff: u64 = 0;
        let mut len_pre: u64 = 0;
        let mut added = BTreeSet::<Index>::default();
        let mut updated = BTreeSet::<Index>::default();
        let mut deleted = BTreeSet::<Index>::default();

        for change in self.changes {
            match change {
                SubKeyWithData::Len(data) => match data {
                    Data::Add { post } => {
                        if post == 0 {
                            return Err(
                                ValidationError::EmptyVecShouldBeDeleted,
                            );
                        }
                        post_gt_pre = true;
                        len_diff = post;
                    }
                    Data::Update { pre, post } => {
                        if post == 0 {
                            return Err(
                                ValidationError::EmptyVecShouldBeDeleted,
                            );
                        }
                        if post > pre {
                            post_gt_pre = true;
                            len_diff = post - pre;
                        } else {
                            len_diff = pre - post;
                        }
                        len_pre = pre;
                    }
                    Data::Delete { pre } => {
                        len_diff = pre;
                        len_pre = pre;
                    }
                },
                SubKeyWithData::Data(index, data) => match data {
                    Data::Add { post } => {
                        actions.push(Action::Push(post));
                        added.insert(index);
                    }
                    Data::Update { pre, post } => {
                        actions.push(Action::Pop(pre));
                        actions.push(Action::Push(post));
                        updated.insert(index);
                    }
                    Data::Delete { pre } => {
                        actions.push(Action::Pop(pre));
                        deleted.insert(index);
                    }
                },
            }
        }
        let added_len: u64 = deleted
            .len()
            .try_into()
            .map_err(ValidationError::IndexOverflow)?;
        let deleted_len: u64 = deleted
            .len()
            .try_into()
            .map_err(ValidationError::IndexOverflow)?;

        if len_diff != 0
            && !(if post_gt_pre {
                deleted_len + len_diff == added_len
            } else {
                added_len + len_diff == deleted_len
            })
        {
            return Err(ValidationError::InvalidLenDiff);
        }

        let mut last_added = Option::None;
        // Iterate additions in increasing order of indices
        for index in added {
            if let Some(last_added) = last_added {
                // Following additions should be at monotonically increasing
                // indices
                let expected = last_added + 1;
                if expected != index {
                    return Err(ValidationError::UnexpectedPushIndex {
                        got: index,
                        expected,
                    });
                }
            } else if index != len_pre {
                // The first addition must be at the pre length value.
                // If something is deleted and a new value is added
                // in its place, it will go through `Data::Update`
                // instead.
                return Err(ValidationError::UnexpectedPushIndex {
                    got: index,
                    expected: len_pre,
                });
            }
            last_added = Some(index);
        }

        let mut last_deleted = Option::None;
        // Also iterate deletions in increasing order of indices
        for index in deleted {
            if let Some(last_added) = last_deleted {
                // Following deletions should be at monotonically increasing
                // indices
                let expected = last_added + 1;
                if expected != index {
                    return Err(ValidationError::UnexpectedPopIndex {
                        got: index,
                        expected,
                    });
                }
            }
            last_deleted = Some(index);
        }
        if let Some(index) = last_deleted {
            if len_pre > 0 {
                let expected = len_pre - 1;
                if index != expected {
                    // The last deletion must be at the pre length value minus 1
                    return Err(ValidationError::UnexpectedPopIndex {
                        got: index,
                        expected: len_pre,
                    });
                }
            }
        }

        // And finally iterate updates in increasing order of indices
        let mut last_updated = Option::None;
        for index in updated {
            if let Some(last_updated) = last_updated {
                // Following additions should be at monotonically increasing
                // indices
                let expected = last_updated + 1;
                if expected != index {
                    return Err(ValidationError::UnexpectedUpdateIndex {
                        got: index,
                        expected,
                    });
                }
            }
            last_updated = Some(index);
        }
        if let Some(index) = last_updated {
            let expected = len_pre.checked_sub(deleted_len).ok_or(
                ValidationError::UnexpectedUnderflow(len_pre, deleted_len),
            )?;
            if index != expected {
                // The last update must be at the pre length value minus
                // deleted_len.
                // If something is added and then deleted in a
                // single tx, it will never be visible here.
                return Err(ValidationError::UnexpectedUpdateIndex {
                    got: index,
                    expected: len_pre,
                });
            }
        }

        Ok(actions)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::storage::testing::TestStorage;

    #[test]
    fn test_lazy_vec_basics() -> storage_api::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_vec = LazyVec::<u32>::new(key);

        // The vec should be empty at first
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Push a new value and check that it's added
        lazy_vec.push(&mut storage, 15_u32)?;
        assert!(!lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 1);
        assert_eq!(lazy_vec.iter(&storage)?.next().unwrap()?, 15_u32);
        assert_eq!(lazy_vec.get(&storage, 0)?.unwrap(), 15_u32);
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Pop the last value and check that the vec is empty again
        let popped = lazy_vec.pop(&mut storage)?.unwrap();
        assert_eq!(popped, 15_u32);
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        Ok(())
    }
}
