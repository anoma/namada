extern crate core;

pub mod oracle;
pub mod protocol;
pub mod storage;
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

pub use namada_core::ledger::eth_bridge::ADDRESS;
