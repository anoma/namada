//! Protocol parameters types

use std::collections::BTreeMap;

use super::address::Address;
use super::chain::ProposalBytes;
use super::dec::Dec;
use super::hash::Hash;
use super::time::DurationSecs;
use super::token;
use crate::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

/// Protocol parameters
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
)]
pub struct Parameters {
    /// Max payload size, in bytes, for a mempool tx.
    pub max_tx_bytes: u32,
    /// Epoch duration (read only)
    pub epoch_duration: EpochDuration,
    /// Maximum expected time per block (read only)
    pub max_expected_time_per_block: DurationSecs,
    /// Max payload size, in bytes, for a tx batch proposal.
    pub max_proposal_bytes: ProposalBytes,
    /// Max gas for block
    pub max_block_gas: u64,
    /// Allowed validity predicate hashes (read only)
    pub vp_allowlist: Vec<String>,
    /// Allowed tx hashes (read only)
    pub tx_allowlist: Vec<String>,
    /// Implicit accounts validity predicate WASM code hash
    pub implicit_vp_code_hash: Option<Hash>,
    /// Expected number of epochs per year (read only)
    pub epochs_per_year: u64,
    /// Maximum number of signature per transaction
    pub max_signatures_per_transaction: u8,
    /// PoS staked ratio (read + write for every epoch)
    pub staked_ratio: Dec,
    /// PoS inflation amount from the last epoch (read + write for every epoch)
    pub pos_inflation_amount: token::Amount,
    /// Fee unshielding gas limit
    pub fee_unshielding_gas_limit: u64,
    /// Fee unshielding descriptions limit
    pub fee_unshielding_descriptions_limit: u64,
    /// Map of the cost per gas unit for every token allowed for fee payment
    pub minimum_gas_price: BTreeMap<Address, token::Amount>,
}

/// Epoch duration. A new epoch begins as soon as both the `min_num_of_blocks`
/// and `min_duration` have passed since the beginning of the current epoch.
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
)]
pub struct EpochDuration {
    /// Minimum number of blocks in an epoch
    pub min_num_of_blocks: u64,
    /// Minimum duration of an epoch
    pub min_duration: DurationSecs,
}
