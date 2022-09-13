//! Lazy data structures for storage access where elements are not all loaded
//! into memory. This serves to minimize gas costs, avoid unbounded iteration
//! in some cases, and ease the validation of storage changes in VPs.
//!
//! Rather than finding the diff of the state before and after (which requires
//! iteration over both of the states that also have to be decoded), VPs will
//! just receive the storage sub-keys that have experienced changes without
//! having to check any of the unchanged elements.

use thiserror::Error;

mod hasher;
pub mod lazy_hashmap;
pub mod lazy_hashset;
pub mod lazy_map;
pub mod lazy_set;
pub mod lazy_vec;

pub use lazy_hashmap::LazyHashMap;
pub use lazy_hashset::LazyHashSet;
pub use lazy_map::LazyMap;
pub use lazy_set::LazySet;
pub use lazy_vec::LazyVec;

use crate::types::storage;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("A storage key was unexpectedly empty")]
    UnexpectedlyEmptyStorageKey,
}

/// A lazy collection of storage values is a handler with some storage prefix
/// that is given to its `fn new()`. The values are typically nested under this
/// prefix and they can be changed individually (e.g. without reading in the
/// whole collection) and their changes directly indicated to the validity
/// predicates, which do not need to iterate the whole collection pre/post to
/// find diffs.
///
/// An empty collection must be deleted from storage.
pub trait LazyCollection {
    /// Create or use an existing vector with the given storage `key`.
    fn open(key: storage::Key) -> Self;
}
