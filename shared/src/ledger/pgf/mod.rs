use namada_core::types::address::{Address, InternalAddress};

pub mod utils;
pub mod vp;

/// The pgf internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

/// The maximum number of charaters attached to a cunsil
pub const MAX_COUNSIL_DATA: u64 = 4096;
