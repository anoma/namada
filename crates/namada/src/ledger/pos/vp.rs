//! Proof-of-Stake native validity predicate.

use std::collections::BTreeSet;

use namada_core::booleans::BoolResultUnitExt;
pub use namada_proof_of_stake;
pub use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::storage::read_pos_params;
use namada_proof_of_stake::storage_key::is_params_key;
pub use namada_proof_of_stake::types;
use namada_state::StateRead;
use namada_tx::Tx;
use thiserror::Error;

use crate::address::Address;
use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::storage::Key;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("PoS VP error: Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// PoS functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Proof-of-Stake validity predicate
pub struct PosVP<'a, S, CA>
where
    S: StateRead,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA>,
}

impl<'a, S, CA> PosVP<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Instantiate a `PosVP`.
    pub fn new(ctx: Ctx<'a, S, CA>) -> Self {
        Self { ctx }
    }

    /// Return if the parameter change was done via a governance proposal
    fn is_valid_parameter_change(&self, tx: &Tx) -> Result<()> {
        tx.data().map_or_else(
            || {
                Err(native_vp::Error::new_const(
                    "PoS parameter changes require tx data to be present",
                )
                .into())
            },
            |data| {
                namada_governance::is_proposal_accepted(
                    &self.ctx.pre(),
                    data.as_ref(),
                )
                .map_err(Error::NativeVpError)?
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::new_const(
                        "PoS parameter changes can only be performed by a \
                         governance proposal that has been accepted",
                    ))
                })?;
                let validation_errors = itertools::join(
                    read_pos_params(&self.ctx.post())
                        .map_err(Error::NativeVpError)?
                        .owned
                        .validate(),
                    ", ",
                );
                validation_errors.is_empty().ok_or_else(|| {
                    native_vp::Error::new_alloc(format!(
                        "PoS parameter changes were invalid: \
                         {validation_errors}",
                    ))
                    .into()
                })
            },
        )
    }
}

impl<'a, S, CA> NativeVp for PosVP<'a, S, CA>
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
    ) -> Result<()> {
        tracing::debug!("\nValidating PoS Tx\n");

        keys_changed.iter().try_for_each(|key| {
            if is_params_key(key) {
                self.is_valid_parameter_change(tx_data)?;
            }
            Ok(())
        })
    }
}
