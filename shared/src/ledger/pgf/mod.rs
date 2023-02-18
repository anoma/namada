use namada_core::types::address::{Address, InternalAddress};

pub mod vp;
pub mod utils;

/// The governance internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);