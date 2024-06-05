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
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::hash::Hash;
use namada_macros::BorshDeserializer;
pub use namada_shielded_token::*;
pub use namada_trans_token::*;
use serde::{Deserialize, Serialize};

/// Token storage keys
pub mod storage_key {
    pub use namada_shielded_token::storage_key::*;
    pub use namada_trans_token::storage_key::*;
}

use namada_core::address::Address;
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

/// Apply token logic for finalizing block (i.e. shielded token rewards)
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

/// Arguments for a transparent token transfer
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct TransparentTransfer {
    /// Source address will spend the tokens
    pub source: Address,
    /// Target address will receive the tokens
    pub target: Address,
    /// Token's address
    pub token: Address,
    /// The amount of tokens
    pub amount: DenominatedAmount,
}

/// Arguments for a shielded token transfer
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct ShieldedTransfer {
    /// Hash of tx section that contains the MASP transaction
    pub section_hash: Hash,
}

/// Arguments for a shielding transfer (from a transparent token to a shielded
/// token)
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct ShieldingTransfer {
    /// Source address will spend the tokens
    pub source: Address,
    /// Token's address
    pub token: Address,
    /// The amount of tokens
    pub amount: DenominatedAmount,
    /// Hash of tx section that contains the MASP transaction
    pub shielded_section_hash: Hash,
}

/// Arguments for an unshielding transfer (from a shielded token to a
/// transparent token)
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct UnshieldingTransfer {
    /// Target address will receive the tokens
    pub target: Address,
    /// Token's address
    pub token: Address,
    /// The amount of tokens
    pub amount: DenominatedAmount,
    /// Hash of tx section that contains the MASP transaction
    pub shielded_section_hash: Hash,
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and strategies for tokens
pub mod testing {
    use namada_core::address::testing::{
        arb_established_address, arb_non_internal_address,
    };
    use namada_core::address::Address;
    pub use namada_core::token::*;
    pub use namada_trans_token::testing::*;
    use proptest::prelude::*;

    use super::TransparentTransfer;

    prop_compose! {
        /// Generate a transparent transfer
        pub fn arb_transparent_transfer()(
            source in arb_non_internal_address(),
            target in arb_non_internal_address(),
            token in arb_established_address().prop_map(Address::Established),
            amount in arb_denominated_amount(),
        ) -> TransparentTransfer {
            TransparentTransfer {
                source,
                target,
                token,
                amount,
            }
        }
    }
}
