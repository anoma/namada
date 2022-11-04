//! Governance library code

use crate::types::address::{Address, InternalAddress};

/// governance parameters
pub mod parameters;
/// governance storage
pub mod storage;

/// The governance internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Governance);
