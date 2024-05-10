//! Namada transparent and shielded token types, storage keys and storage
//! fns.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects
)]

pub use namada_shielded_token::*;
pub use namada_trans_token::*;

pub mod storage_key {
    pub use namada_shielded_token::storage_key::*;
    pub use namada_trans_token::storage_key::*;
}

use namada_core::address::Address;
#[cfg(any(test, feature = "testing"))]
pub use namada_core::token::testing;
use namada_events::EmitEvents;
use namada_storage::{Result, StorageRead, StorageWrite};

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S>(
    params: &Option<ShieldedParams>,
    storage: &mut S,
    address: &Address,
    denom: &Denomination,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    namada_trans_token::write_params(storage, address)?;
    if let Some(params) = params {
        namada_shielded_token::write_params(params, storage, address, denom)?;
    }
    Ok(())
}

pub fn finalize_block<S>(
    storage: &mut S,
    _events: &mut impl EmitEvents,
    is_new_epoch: bool,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
{
    if is_new_epoch {
        conversion::update_allowed_conversions(storage)?;
    }
    Ok(())
}
