//! Namada shielded token.

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

pub mod conversion;

#[cfg(feature = "masp")]
pub mod masp;
mod storage;
pub mod storage_key;
pub mod utils;
pub mod validation;
pub mod vp;

use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
pub use namada_core::dec::Dec;
pub use namada_core::masp::{
    MaspEpoch, MaspTransaction, MaspTxId, MaspValue, Precision,
};
use namada_core::uint::Uint;
pub use namada_state::{
    ConversionLeaf, ConversionState, Error, Key, OptionExt, Result, ResultExt,
    StorageRead, StorageWrite, WithConversionState,
};
use serde::{Deserialize, Serialize};
pub use storage::*;

#[cfg(feature = "masp")]
pub use crate::masp::shielded_wallet::ShieldedWallet;

/// An object with multiple representations
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Deserialize,
    Serialize,
)]
// This object can be deserialized from either form
#[serde(untagged)]
pub enum Poly<X, Y> {
    /// The primary way this object can be represented
    Left(X),
    /// The secondry way this object can be represented
    Right(Y),
}

/// Support conversions directly into the primary representation
impl<X, Y> From<X> for Poly<X, Y> {
    fn from(x: X) -> Self {
        Self::Left(x)
    }
}

impl<X, Y> Poly<X, Y> {
    /// Switch the primary and secondry representations
    pub fn switch(self) -> Poly<Y, X> {
        match self {
            Self::Left(x) => Poly::Right(x),
            Self::Right(y) => Poly::Left(y),
        }
    }

    /// Convert to the given type without regard for the representaation
    pub fn into<Z: From<X> + From<Y>>(self) -> Z {
        match self {
            Self::Left(x) => x.into(),
            Self::Right(y) => y.into(),
        }
    }
}

/// Token parameters for each kind of asset held on chain
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Deserialize,
    Serialize,
)]
pub struct ShieldedParams {
    /// Maximum reward rate
    pub max_reward_rate: Dec,
    /// Shielded Pool nominal derivative gain
    pub kd_gain_nom: Dec,
    /// Shielded Pool nominal proportional gain for the given token
    pub kp_gain_nom: Dec,
    /// Target amount for the given token that is locked in the shielded pool
    pub locked_amount_target: Poly<Uint, u64>,
    /// Precision of shielded rewards for the token
    pub precision: Option<Poly<Precision, u64>>,
}

impl Default for ShieldedParams {
    fn default() -> Self {
        Self {
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            kp_gain_nom: Dec::from_str("0.25").unwrap(),
            kd_gain_nom: Dec::from_str("0.25").unwrap(),
            locked_amount_target: Poly::from(10_000_u64).switch(),
            precision: None,
        }
    }
}
