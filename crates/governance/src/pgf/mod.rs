//! PGF library code

use namada_core::address::{Address, InternalAddress};

/// PGF CLI
pub mod cli;
/// PGF inflation code
pub mod inflation;
/// PGF parameters
pub mod parameters;
/// PGF storage
pub mod storage;

/// The PGF internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

/// Upper limit on the number of reward distribution per steawrd
pub const REWARD_DISTRIBUTION_LIMIT: u64 = 100;
