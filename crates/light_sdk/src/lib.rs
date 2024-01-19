//! The Namada light SDK is a simplified version of the SDK aimed at making
//! interaction with the protocol easier and faster. The library is developed
//! with ease-of-use and interoperability in mind so that it should be possible
//! to wrap it for usage in an FFI context.
//!
//! The [`namada_sdk`] crate of Namada is also re-exported to allow access
//! to its types.
//!
//! # Structure
//!
//! This SDK is divided into three modules:
//!
//! - [`transaction`]: contains functions to construct all the transactions
//!   currently supported by the protocol
//! - [`reading`]: exposes queries to retrieve data from a Namada node
//! - [`writing`]: exposes functions to send data to a Namada node
//!
//! Both the [`reading`] and [`writing`] modules are further divided into a
//! blocking and asynchronous submodules.

pub mod reading;
pub mod transaction;
pub mod writing;
pub use namada_sdk;
