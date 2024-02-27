//! Native VP for protocol parameters

use std::collections::BTreeSet;

use namada_core::address::Address;
use namada_core::storage::Key;
use namada_state::StateRead;
use namada_tx::Tx;
use thiserror::Error;

use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
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
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let result = keys_changed.iter().all(|key| {
            let key_type: KeyType = key.into();
            let data = if let Some(data) = tx_data.data() {
                data
            } else {
                return false;
            };
            match key_type {
                KeyType::PARAMETER => {
                    namada_governance::storage::is_proposal_accepted(
                        &self.ctx.pre(),
                        &data,
                    )
                    .unwrap_or(false)
                }
                KeyType::UNKNOWN_PARAMETER => false,
                KeyType::UNKNOWN => true,
            }
        });
        Ok(result)
    }
}

impl From<native_vp::Error> for Error {
    fn from(err: native_vp::Error) -> Self {
        Self::NativeVpError(err)
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
