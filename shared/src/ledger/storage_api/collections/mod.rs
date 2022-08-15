//! Lazy data structures for storage access where elements are not all loaded
//! into memory. This serves to minimize gas costs, avoid unbounded iteration
//! in some cases, and ease the validation of storage changes in the VP.
//!
//! Rather than finding the diff of the state before and after, the VP will
//! just receive the storage sub-keys that have experienced changes.
//!
//! CONTINUE TO UPDATE THE ABOVE

mod hasher;
pub mod lazy_map;
pub mod lazy_set;
pub mod lazy_vec;
