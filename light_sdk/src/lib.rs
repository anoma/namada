//! The Namada light SDK is a simplified version of the SDK aimed at making
//! interaction with the protocol easier and faster. The library is developed
//! with ease-of-use and interoperability in mind so that it should be possible
//! to wrap it for usage in an FFI context.
//!
//! The [`namada_core`] crate of Namada is also re-exported to allow access to
//! its types.
//!
//! # Structure
//!
//! This SDK is divided into three modules:
//!
//! - transaction: contains functions to construct all the transactions
//!                currently supported by the protocol
//! - reading: exposes queries to retrieve data from a Namada node
//! - writing: provides a function for broadcasting a tx and getting
//!            the result from the ledger

pub mod reading;
pub mod transaction;
pub mod writing;
pub use namada_core;
