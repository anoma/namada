//! Governance library code

use crate::types::address::{Address, InternalAddress};

/// governance cli structure and functions
pub mod cli;
/// governance parameters
pub mod parameters;
/// governance storage
pub mod storage;
/// governnce utils functions
pub mod utils;

/// The governance internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Governance);
