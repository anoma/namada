//! Governance library code

use namada_core::types::address::{self, Address};

/// governance CLI structures
pub mod cli;
/// governance parameters
pub mod parameters;
/// governance storage
pub mod storage;
/// Governance utility functions/structs
pub mod utils;

/// The governance internal address
pub const ADDRESS: Address = address::GOV;
