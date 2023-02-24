//! Public good fundings integration as a native validity predicate
//!  
use namada_core::types::address::{Address, InternalAddress};

pub mod utils;
pub mod vp;

/// The pgf internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);
