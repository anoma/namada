//! Functionality to do with checking whether a transaction is authorized by the
//! "owner" of some key under this account
use eyre::Result;

use super::store;
use crate::types::address::Address;

pub(super) fn is_authorized(
    reader: impl store::Reader,
    tx_data: &[u8],
    owner: &Address,
) -> Result<bool> {
    Ok(false)
}
