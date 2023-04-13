//! Governance library code

use crate::types::address::{self, Address};

/// governance parameters
pub mod parameters;
/// governance storage
pub mod storage;

/// The governance internal address
pub const ADDRESS: Address = address::GOV;
