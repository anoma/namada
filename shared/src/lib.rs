//! The shared code for the Anoma ledger, gossip and wasms.

#![warn(missing_docs)]

pub mod bytes;
pub mod gossip;
pub mod ledger;
pub mod proto;
pub mod types;
pub mod vm;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
