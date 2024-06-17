//! Native VP for protocol parameters

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::governance;
use namada_core::storage::Key;
use namada_state::{StateRead, StorageError};
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
pub struct ParametersVp<'a, S, CA, EVAL, Gov>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA, EVAL>,
    /// Governance type
    pub gov: PhantomData<Gov>,
}

impl<'a, S, CA, EVAL, Gov> NativeVp<'a> for ParametersVp<'a, S, CA, EVAL, Gov>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    Gov: governance::Read<
            CtxPreStorageRead<'a, 'a, S, CA, EVAL>,
            Err = StorageError,
        >,
{
    type Error = Error;

    fn validate_tx(
        &'a self,
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
