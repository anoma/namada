//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log is flushed every other `N` block heights, or every other `E`
//! `FinalizeBlock` events, where `N` and `E` are configurable parameters.

pub mod dumb_queries;
