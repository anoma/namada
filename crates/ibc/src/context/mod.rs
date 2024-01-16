//! IBC Contexts

pub mod client;
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

use namada_core::ibc::core::commitment_types::specs::ProofSpecs;
use namada_core::ibc::core::host::types::identifiers::ChainId as IbcChainId;

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
            chain_id: IbcChainId::new("non-init-chain")
                .expect("Convert the default chain ID shouldn't fail"),
            proof_specs: ProofSpecs::default(),
            unbonding_period: Duration::default(),
            upgrade_path: Vec::default(),
        }
    }
}
