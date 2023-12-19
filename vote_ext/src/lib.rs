//! This module contains types necessary for processing vote extensions.

pub mod bridge_pool_roots;
pub mod ethereum_events;
pub mod validator_set_update;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

use crate::proto::Signed;

/// This type represents the data we pass to the extension of
/// a vote at the PreCommit phase of Tendermint.
#[derive(
    Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct VoteExtension {
    /// Vote extension data related with Ethereum events.
    pub ethereum_events: Option<Signed<ethereum_events::Vext>>,
    /// A signature of the Ethereum bridge pool root and nonce.
    pub bridge_pool_root: Option<bridge_pool_roots::SignedVext>,
    /// Vote extension data related with validator set updates.
    pub validator_set_update: Option<validator_set_update::SignedVext>,
}
