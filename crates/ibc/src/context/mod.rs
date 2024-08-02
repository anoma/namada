//! IBC Contexts

pub mod client;
pub mod common;
pub mod execution;
pub mod nft_transfer;
pub mod nft_transfer_mod;
pub mod router;
pub mod storage;
pub mod token_transfer;
pub mod transfer_mod;
pub mod validation;

use std::cell::RefCell;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Duration;

use ibc::core::commitment_types::specs::ProofSpecs;
use ibc::core::host::types::identifiers::ChainId as IbcChainId;
use namada_core::hash::Sha256Hasher;
use namada_state::merkle_tree::ics23_specs::proof_specs;

/// IBC context to handle IBC-related data
#[derive(Debug)]
pub struct IbcContext<C, Params>
where
    C: common::IbcCommonContext,
{
    /// Context
    pub inner: Rc<RefCell<C>>,
    /// Validation parameters for IBC VP
    pub validation_params: ValidationParams,
    /// Marker for DI types
    pub _marker: PhantomData<Params>,
}

impl<C, Params> IbcContext<C, Params>
where
    C: common::IbcCommonContext,
{
    /// Make new IBC context
    pub fn new(inner: Rc<RefCell<C>>) -> Self {
        Self {
            inner,
            validation_params: ValidationParams::default(),
            _marker: PhantomData,
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
                .expect("Converting the default chain ID shouldn't fail"),
            proof_specs: proof_specs::<Sha256Hasher>()
                .try_into()
                .expect("Converting the proof specs shouldn't fail"),
            unbonding_period: Duration::default(),
            upgrade_path: Vec::default(),
        }
    }
}
