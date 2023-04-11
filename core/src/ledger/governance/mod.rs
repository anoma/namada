//! Governance library code

use crate::types::address::{Address, InternalAddress};

/// governance parameters
pub mod parameters;
/// governance storage
pub mod storage;
/// governnce utils functions
pub mod utils;
/// governance cli structure and functions
pub mod cli;

/// The governance internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Governance);
