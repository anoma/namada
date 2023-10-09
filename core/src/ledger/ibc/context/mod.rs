//! IBC Contexts

pub mod common;
pub mod execution;
pub mod router;
pub mod storage;
pub mod token_transfer;
pub mod transfer_mod;
pub mod validation;

use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::time::Duration;

use ibc_derive::ConsensusState;

use crate::ibc::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use crate::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use crate::ibc::core::ics23_commitment::specs::ProofSpecs;
use crate::ibc::core::ics24_host::identifier::ChainId as IbcChainId;

/// IBC context to handle IBC-related data
#[derive(Debug)]
pub struct IbcContext<C>
where
    C: common::IbcCommonContext,
{
    /// Context
    pub inner: Rc<RefCell<C>>,
    /// Validation parameters for IBC VP
    pub validation_params: ValidationParams,
}

impl<C> IbcContext<C>
where
    C: common::IbcCommonContext,
{
    /// Make new IBC context
    pub fn new(inner: Rc<RefCell<C>>) -> Self {
        Self {
            inner,
            validation_params: ValidationParams::default(),
        }
    }
}

#[derive(Debug)]
/// Parameters for validation
pub struct ValidationParams {
    /// Chain ID
    pub chain_id: IbcChainId,
    /// IBC proof specs
    pub proof_specs: ProofSpecs,
    /// Unbonding period
    pub unbonding_period: Duration,
    /// Upgrade path
    pub upgrade_path: Vec<String>,
}

impl Default for ValidationParams {
    fn default() -> Self {
        Self {
            chain_id: IbcChainId::new("non-init-chain", 0)
                .expect("Convert the default chain ID shouldn't fail"),
            proof_specs: ProofSpecs::default(),
            unbonding_period: Duration::default(),
            upgrade_path: Vec::default(),
        }
    }
}

// TODO: #[derive(ClientState)]
type AnyClientState = TmClientState;

/// ConsensusState for light clients
#[derive(ConsensusState)]
pub enum AnyConsensusState {
    /// Tendermint consensus state
    Tendermint(TmConsensusState),
}

impl From<TmConsensusState> for AnyConsensusState {
    fn from(cs: TmConsensusState) -> Self {
        Self::Tendermint(cs)
    }
}

impl TryFrom<AnyConsensusState> for TmConsensusState {
    type Error = crate::ibc::core::ics02_client::error::ClientError;

    fn try_from(any: AnyConsensusState) -> Result<Self, Self::Error> {
        match any {
            AnyConsensusState::Tendermint(cs) => Ok(cs),
        }
    }
}
