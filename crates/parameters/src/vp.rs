//! Native VP for protocol parameters

use std::collections::BTreeSet;

use namada_core::address::Address;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::Key;
use namada_state::StateRead;
use namada_tx::BatchedTxRef;
use thiserror::Error;

use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Parameters VP error: Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Parameters functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Parameters VP
pub struct ParametersVp<'a, S, CA>
where
    S: StateRead,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA>,
}

impl<'a, S, CA> NativeVp for ParametersVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
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
                    namada_governance::storage::is_proposal_accepted(
                        &self.ctx.pre(),
                        &data,
                    )
                    .map_err(Error::NativeVpError)?
                    .ok_or_else(|| {
                        native_vp::Error::new_alloc(format!(
                            "Attempted to change a protocol parameter from \
                             outside of a governance proposal, or from a \
                             non-accepted governance proposal: {key}",
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
        if namada_parameters::storage::is_protocol_parameter_key(value) {
            KeyType::PARAMETER
        } else if namada_parameters::storage::is_parameter_key(value) {
            KeyType::UNKNOWN_PARAMETER
        } else {
            KeyType::UNKNOWN
        }
    }
}
