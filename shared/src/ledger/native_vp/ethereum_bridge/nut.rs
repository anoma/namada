//! Validity predicate for Non Usable Tokens (NUTs).

use std::collections::BTreeSet;

use eyre::WrapErr;
use namada_core::ledger::storage as ledger_storage;
use namada_core::ledger::storage::traits::StorageHasher;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::storage::Key;
use namada_core::types::token::Amount;

use crate::ledger::native_vp::{Ctx, NativeVp, VpEnv};
use crate::proto::Tx;
use crate::types::token::is_any_token_balance_key;
use crate::vm::WasmCacheAccess;

/// Generic error that may be returned by the validity predicate
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] eyre::Report);

/// Validity predicate for non-usable tokens.
///
/// All this VP does is reject NUT transfers whose destination
/// address is not the Bridge pool escrow address.
pub struct NonUsableTokens<'ctx, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for NonUsableTokens<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        _: &Tx,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(
            keys_changed_len = keys_changed.len(),
            verifiers_len = verifiers.len(),
            "Non usable tokens VP triggered",
        );

        let is_multitoken =
            verifiers.contains(&Address::Internal(InternalAddress::Multitoken));
        if !is_multitoken {
            tracing::debug!("Rejecting non-multitoken transfer tx");
            return Ok(false);
        }

        let nut_owners =
            keys_changed.iter().filter_map(
                |key| match is_any_token_balance_key(key) {
                    Some(
                        [Address::Internal(InternalAddress::Nut(_)), owner],
                    ) => Some((key, owner)),
                    _ => None,
                },
            );

        for (changed_key, token_owner) in nut_owners {
            let pre: Amount = self
                .ctx
                .read_pre(changed_key)
                .context("Reading pre amount failed")
                .map_err(Error)?
                .unwrap_or_default();
            let post: Amount = self
                .ctx
                .read_post(changed_key)
                .context("Reading post amount failed")
                .map_err(Error)?
                .unwrap_or_default();

            match token_owner {
                // the NUT balance of the bridge pool should increase
                Address::Internal(InternalAddress::EthBridgePool) => {
                    if post < pre {
                        tracing::debug!(
                            %changed_key,
                            pre_amount = ?pre,
                            post_amount = ?post,
                            "Bridge pool balance should have increased"
                        );
                        return Ok(false);
                    }
                }
                // arbitrary addresses should have their balance decrease
                _addr => {
                    if post > pre {
                        tracing::debug!(
                            %changed_key,
                            pre_amount = ?pre,
                            post_amount = ?post,
                            "Balance should have decreased"
                        );
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }
}

// TODO: add tests
