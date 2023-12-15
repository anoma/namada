//! Pgf library code

use crate::types::address::{Address, InternalAddress};

/// Pgf CLI
pub mod cli;
/// Pgf inflation code
pub mod inflation;
/// Pgf parameters
pub mod parameters;
/// Pgf storage
pub mod storage;

/// The Pgf internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);
