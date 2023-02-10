//! Pgf library code

use crate::types::address::{Address, InternalAddress};

/// pgf parameters
pub mod parameters;
/// pgf storage
pub mod storage;

/// The pgf internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);
