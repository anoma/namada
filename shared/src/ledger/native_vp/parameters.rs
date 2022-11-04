//! Native VP for protocol parameters

use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use namada_core::ledger::storage;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::storage::Key;
use thiserror::Error;

use crate::ledger::governance::storage as gov_storage;
use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::ledger::vp_env::VpEnv;
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
pub struct ParametersVp<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for ParametersVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Parameters;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let result = keys_changed.iter().all(|key| {
            let key_type: KeyType = key.into();
            match key_type {
                KeyType::PARAMETER => {
                    let proposal_id = u64::try_from_slice(tx_data).ok();
                    match proposal_id {
                        Some(id) => {
                            let proposal_execution_key =
                                gov_storage::get_proposal_execution_key(id);
                            self.ctx
                                .has_key_pre(&proposal_execution_key)
                                .unwrap_or(false)
                        }
                        _ => false,
                    }
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
        if namada_core::ledger::parameters::storage::is_protocol_parameter_key(
            value,
        ) {
            KeyType::PARAMETER
        } else if namada_core::ledger::parameters::storage::is_parameter_key(
            value,
        ) {
            KeyType::UNKNOWN_PARAMETER
        } else {
            KeyType::UNKNOWN
        }
    }
}
