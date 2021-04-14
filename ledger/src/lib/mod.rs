//! Shared code for the node, client etc.

pub mod address;
pub mod bookkeeper;
pub mod bytes;
pub mod cli;
pub mod config;
pub mod genesis;
pub mod protobuf;
pub mod types;

// This is here only to include the std's docs in our docs.
// Taken from <https://github.com/rust-lang/rfcs/issues/2324#issuecomment-502437904>.
#[doc(inline)]
pub use std;
