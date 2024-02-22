//! Namada shielded token.

pub mod conversion;
mod storage;
pub mod storage_key;
pub mod utils;

use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::dec::Dec;
pub use namada_storage::conversion_state::{
    ConversionState, WithConversionState,
};
use serde::{Deserialize, Serialize};
pub use storage::*;

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
    /// TODO: should this be a Uint or DenominatedAmount???
    pub locked_amount_target: u64,
}

impl Default for ShieldedParams {
    fn default() -> Self {
        Self {
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            kp_gain_nom: Dec::from_str("0.25").unwrap(),
            kd_gain_nom: Dec::from_str("0.25").unwrap(),
            locked_amount_target: 10_000_u64,
        }
    }
}
