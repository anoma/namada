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

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReadError {
    #[error("A storage key was unexpectedly empty")]
    UnexpectedlyEmptyStorageKey,
}
