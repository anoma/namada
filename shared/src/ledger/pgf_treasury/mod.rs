//! Public goods funding treasury reserved for the council
use namada_core::types::address::{Address, InternalAddress};

pub mod vp;
pub mod utils;

/// The pgf council treasury internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);
