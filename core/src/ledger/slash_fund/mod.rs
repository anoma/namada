//! SlashFund library code

use crate::types::address::{Address, InternalAddress};

/// Internal SlashFund address
pub const ADDRESS: Address = Address::Internal(InternalAddress::SlashFund);

pub mod storage;
