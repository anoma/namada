//! Lazy data structures for storage access where elements are not all loaded
//! into memory. This serves to minimize gas costs, avoid unbounded iteration
//! in some cases, and ease the validation of storage changes in VPs.
//!
//! Rather than finding the diff of the state before and after (which requires
//! iteration over both of the states that also have to be decoded), VPs will
//! just receive the storage sub-keys that have experienced changes without
//! having to check any of the unchanged elements.

use std::fmt::Debug;

use namada_core::borsh::BorshDeserialize;
use thiserror::Error;

pub mod lazy_map;
pub mod lazy_set;
pub mod lazy_vec;

pub use lazy_map::LazyMap;
pub use lazy_set::LazySet;
pub use lazy_vec::LazyVec;
use namada_core::storage;

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
    /// Possible sub-keys in the collection
    type SubKey: Debug;

    /// A type of a value in the inner-most collection
    type Value: BorshDeserialize + Debug;

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
    ) -> crate::Result<Option<Self::SubKey>>;

    /// Check if the given storage key is a valid data key.
    ///
    /// For most collections, this is the same as `is_valid_sub_key`, but for
    /// example for `LazyVec`, which has an additional sub-key for length of the
    /// vec, only the element data sub-keys would return `true`.
    fn is_data_sub_key(&self, key: &storage::Key) -> bool;
}
