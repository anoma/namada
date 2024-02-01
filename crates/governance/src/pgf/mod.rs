//! Pgf library code

use namada_core::address::{Address, InternalAddress};

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

/// Upper limit on the number of reward distribution per steawrd
pub const REWARD_DISTRIBUTION_LIMIT: u64 = 100;
