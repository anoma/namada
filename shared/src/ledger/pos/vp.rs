//! Proof-of-Stake native validity predicate.

use std::collections::BTreeSet;
use std::panic::{RefUnwindSafe, UnwindSafe};

use namada_core::ledger::storage_api::governance::is_proposal_accepted;
// use borsh::BorshDeserialize;
pub use namada_proof_of_stake;
pub use namada_proof_of_stake::parameters::PosParams;
// use namada_proof_of_stake::validation::validate;
use namada_proof_of_stake::read_pos_params;
pub use namada_proof_of_stake::types;
// use rust_decimal::Decimal;
use thiserror::Error;

use super::is_params_key;
use crate::ledger::native_vp::{self, Ctx, NativeVp};
// use crate::ledger::pos::{
//     is_validator_address_raw_hash_key,
//     is_validator_max_commission_rate_change_key,
// };
use crate::ledger::storage::{self as ledger_storage, StorageHasher};
use crate::ledger::storage_api::StorageRead;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{Key, KeySeg};
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
}

/// PoS functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Proof-of-Stake validity predicate
pub struct PosVP<'a, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> PosVP<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Instantiate a `PosVP`.
    pub fn new(ctx: Ctx<'a, DB, H, CA>) -> Self {
        Self { ctx }
    }
}

// TODO this is temporarily to run PoS native VP in a new thread to avoid
// crashing the ledger (in apps/src/lib/node/ledger/protocol/mod.rs). The
// RefCells contained within PosVP are not thread-safe, but each thread has its
// own instances.
impl<DB, H, CA> UnwindSafe for PosVP<'_, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
}

// TODO this is temporarily to run PoS native VP in a new thread to avoid
// crashing the ledger (in apps/src/lib/node/ledger/protocol/mod.rs). The
// RefCells contained within PosVP are not thread-safe, but each thread has its
// own instances.
impl<DB, H, CA> RefUnwindSafe for PosVP<'_, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
}

impl<'a, DB, H, CA> NativeVp for PosVP<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::PoS;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        // use validation::Data;
        // use validation::DataUpdate::{self, *};
        // use validation::ValidatorUpdate::*;

        let addr = Address::Internal(Self::ADDR);
        // let mut changes: Vec<DataUpdate> = vec![];
        let _current_epoch = self.ctx.pre().get_block_epoch()?;

        println!("\nVALIDATING TX\n");

        for key in keys_changed {
            // println!("KEY: {}\n", key);
            if is_params_key(key) {
                if !is_proposal_accepted(&self.ctx.pre(), tx_data)
                    .map_err(Error::NativeVpError)?
                {
                    return Ok(false);
                }
            } else if key.segments.get(0) == Some(&addr.to_db_key()) {
                // Unknown changes to this address space are disallowed
                // tracing::info!("PoS unrecognized key change {} rejected",
                // key);
                tracing::info!(
                    "PoS unrecognized key change {} typically rejected but \
                     letting pass for now while implementing new lazy PoS \
                     storage",
                    key
                );
                // return Ok(false);
            } else {
                // Unknown changes anywhere else are permitted
            }
        }

        let _params = read_pos_params(&self.ctx.pre())?;
        // let errors = validate(&params, changes, current_epoch);
        // Ok(if errors.is_empty() {
        //     true
        // } else {
        //     tracing::info!(
        //         "PoS validation errors:\n - {}",
        //         errors.iter().format("\n - ")
        //     );
        //     false
        // })
        Ok(true)
    }
}

impl From<native_vp::Error> for Error {
    fn from(err: native_vp::Error) -> Self {
        Self::NativeVpError(err)
    }
}
