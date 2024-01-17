//! Namada transparent and shielded token types, storage keys and storage
//! fns.

pub use namada_shielded_token::*;
pub use namada_trans_token::*;

pub mod storage_key {
    pub use namada_shielded_token::storage_key::*;
    pub use namada_trans_token::storage_key::*;
}

use namada_core::types::address::Address;
use namada_storage::{Result, StorageRead, StorageWrite};
pub use namada_trans_token::Parameters;

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S>(
    params: &Parameters,
    storage: &mut S,
    address: &Address,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    namada_trans_token::write_params(params, storage, address)?;
    namada_shielded_token::write_params(params, storage, address)
}
