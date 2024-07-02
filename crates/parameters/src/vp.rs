//! Native VP for protocol parameters

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::Key;
use namada_state::StateRead;
use namada_systems::governance;
use namada_tx::BatchedTxRef;
use namada_vp::native_vp::{
    self, Ctx, CtxPreStorageRead, NativeVp, VpEvaluator,
};
use thiserror::Error;

use crate::storage;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Parameters VP error: Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Parameters functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Parameters VP
pub struct ParametersVp<'ctx, S, CA, EVAL, Gov>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA, EVAL>,
    /// Generic types for DI
    pub _marker: PhantomData<Gov>,
}

impl<'view, 'ctx: 'view, S, CA, EVAL, Gov> NativeVp<'view>
    for ParametersVp<'ctx, S, CA, EVAL, Gov>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    Gov: governance::Read<CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>>,
{
    type Error = Error;

    fn validate_tx(
        &'view self,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        keys_changed.iter().try_for_each(|key| {
            let key_type: KeyType = key.into();
            let data = if let Some(data) = batched_tx.tx.data(batched_tx.cmt) {
                data
            } else {
                return Err(native_vp::Error::new_const(
                    "Token parameter changes require tx data to be present",
                )
                .into());
            };
            match key_type {
                KeyType::PARAMETER | KeyType::UNKNOWN_PARAMETER => {
                    Gov::is_proposal_accepted(&self.ctx.pre(), &data)
                        .map_err(Error::NativeVpError)?
                        .ok_or_else(|| {
                            native_vp::Error::new_alloc(format!(
                                "Attempted to change a protocol parameter \
                                 from outside of a governance proposal, or \
                                 from a non-accepted governance proposal: \
                                 {key}",
                            ))
                            .into()
                        })
                }
                KeyType::UNKNOWN => Ok(()),
            }
        })
    }
}

impl<'ctx, S, CA, EVAL, Gov> ParametersVp<'ctx, S, CA, EVAL, Gov>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    Gov: governance::Read<CtxPreStorageRead<'ctx, 'ctx, S, CA, EVAL>>,
{
    /// Instantiate parameters VP
    pub fn new(ctx: Ctx<'ctx, S, CA, EVAL>) -> Self {
        Self {
            ctx,
            _marker: PhantomData,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
enum KeyType {
    #[allow(clippy::upper_case_acronyms)]
    PARAMETER,
    #[allow(clippy::upper_case_acronyms)]
    #[allow(non_camel_case_types)]
    UNKNOWN_PARAMETER,
    #[allow(clippy::upper_case_acronyms)]
    UNKNOWN,
}

impl From<&Key> for KeyType {
    fn from(value: &Key) -> Self {
        if storage::is_protocol_parameter_key(value) {
            KeyType::PARAMETER
        } else if storage::is_parameter_key(value) {
            KeyType::UNKNOWN_PARAMETER
        } else {
            KeyType::UNKNOWN
        }
    }
}
