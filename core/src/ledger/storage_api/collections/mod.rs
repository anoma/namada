//! Lazy data structures for storage access where elements are not all loaded
//! into memory. This serves to minimize gas costs, avoid unbounded iteration
//! in some cases, and ease the validation of storage changes in VPs.
//!
//! Rather than finding the diff of the state before and after (which requires
//! iteration over both of the states that also have to be decoded), VPs will
//! just receive the storage sub-keys that have experienced changes without
//! having to check any of the unchanged elements.

use std::fmt::Debug;

use borsh::BorshDeserialize;
use derivative::Derivative;
use thiserror::Error;

pub mod lazy_map;
pub mod lazy_vec;

pub use lazy_map::LazyMap;
pub use lazy_vec::LazyVec;

// use super::StorageRead;
use crate::ledger::storage_api;
use crate::ledger::vp_env::VpEnv;
use crate::types::storage;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("A storage key was unexpectedly empty")]
    UnexpectedlyEmptyStorageKey,
}

/// Simple lazy collection with borsh deserializable elements
#[derive(Debug)]
pub struct Simple;

/// Lazy collection with a nested lazy collection
#[derive(Debug)]
pub struct Nested;

/// A lazy collection of storage values is a handler with some storage prefix
/// that is given to its `fn new()`. The values are typically nested under this
/// prefix and they can be changed individually (e.g. without reading in the
/// whole collection) and their changes directly indicated to the validity
/// predicates, which do not need to iterate the whole collection pre/post to
/// find diffs.
///
/// An empty collection must be deleted from storage.
pub trait LazyCollection {
    /// Actions on the collection determined from changed storage keys by
    /// `Self::validate`
    type Action;

    /// Possible sub-keys in the collection
    type SubKey: Debug;

    /// Possible sub-keys together with the data read from storage
    type SubKeyWithData: Debug;

    /// A type of a value in the inner-most collection
    type Value: BorshDeserialize;

    /// Create or use an existing vector with the given storage `key`.
    fn open(key: storage::Key) -> Self;

    /// Check if the given storage key is a valid LazyVec sub-key and if so
    /// return which one. Returns:
    /// - `Ok(Some(_))` if it's a valid sub-key
    /// - `Ok(None)` if it's not a sub-key
    /// - `Err(_)` if it's an invalid sub-key
    fn is_valid_sub_key(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<Self::SubKey>>;

    /// Try to read and decode the data for each change storage key in prior and
    /// posterior state. If there is no value in neither prior or posterior
    /// state (which is a possible state when transaction e.g. writes and then
    /// deletes one storage key, but it is treated as a no-op as it doesn't
    /// affect result of validation), returns `Ok(None)`.
    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> storage_api::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>;

    // /// Attempting an iter method
    // fn iter<E>(
    //     storage: &impl StorageRead,
    // ) -> storage_api::Result<impl Iterator<Item = Result<E>>>;

    /// Validate changed sub-keys associated with their data and return back
    /// a vector of `Self::Action`s, if the changes are valid
    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> storage_api::Result<Vec<Self::Action>>;

    /// Accumulate storage changes inside a `ValidationBuilder`. This is
    /// typically done by the validity predicate while looping through the
    /// changed keys. If the resulting `builder` is not `None`, one must
    /// call `fn build()` on it to get the validation result.
    /// This function will return `Ok(true)` if the storage key is a valid
    /// sub-key of this collection, `Ok(false)` if the storage key doesn't match
    /// the prefix of this collection, or error if the prefix matches this
    /// collection, but the key itself is not recognized.
    fn accumulate<ENV>(
        &self,
        env: &ENV,
        builder: &mut Option<ValidationBuilder<Self::SubKeyWithData>>,
        key_changed: &storage::Key,
    ) -> storage_api::Result<bool>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        if let Some(sub) = self.is_valid_sub_key(key_changed)? {
            let change = Self::read_sub_key_data(env, key_changed, sub)?;
            if let Some(change) = change {
                let builder =
                    builder.get_or_insert(ValidationBuilder::default());
                builder.changes.push(change);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Execute validation on the validation builder, to be called when
    /// `accumulate` instantiates the builder to `Some(_)`, after all the
    /// changes storage keys have been processed.
    fn validate(
        builder: ValidationBuilder<Self::SubKeyWithData>,
    ) -> storage_api::Result<Vec<Self::Action>> {
        Self::validate_changed_sub_keys(builder.changes)
    }
}

/// Validation builder from storage changes. The changes can
/// be accumulated with `LazyCollection::accumulate()` and then turned into a
/// list of valid actions on the collection with `LazyCollection::validate()`.
#[derive(Debug, Derivative)]
// https://mcarton.github.io/rust-derivative/latest/Default.html#custom-bound
#[derivative(Default(bound = ""))]
pub struct ValidationBuilder<Change> {
    /// The accumulator of found changes under the vector
    pub changes: Vec<Change>,
}
