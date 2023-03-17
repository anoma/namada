use crate::types::address::{Address, InternalAddress};

/// pgf counsil treasury storage
pub mod storage;

/// The pgf counsil treasury internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::PgfCouncilTreasury);