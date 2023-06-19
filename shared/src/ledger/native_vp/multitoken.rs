//! Native VP for multitokens

use std::collections::{BTreeSet, HashMap};

use thiserror::Error;

use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::ledger::storage;
use crate::ledger::vp_env::VpEnv;
use crate::proto::Tx;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
use crate::types::token::{
    is_any_minted_balance_key, is_any_token_balance_key, minter_key, Amount,
};
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Multitoken functions result
pub type Result<T> = std::result::Result<T, Error>;

/// Multitoken VP
pub struct MultitokenVp<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for MultitokenVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Multitoken;

    fn validate_tx(
        &self,
        _tx: &Tx,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let mut changes = HashMap::new();
        let mut mints = HashMap::new();
        for key in keys_changed {
            if let Some((token, _)) = is_any_token_balance_key(key) {
                let pre: Amount = self.ctx.read_pre(key)?.unwrap_or_default();
                let post: Amount = self.ctx.read_post(key)?.unwrap_or_default();
                let diff = post.change() - pre.change();
                match changes.get_mut(token) {
                    Some(change) => *change += diff,
                    None => _ = changes.insert(token, diff),
                }
            } else if let Some(token) = is_any_minted_balance_key(key) {
                let pre: Amount = self.ctx.read_pre(key)?.unwrap_or_default();
                let post: Amount = self.ctx.read_post(key)?.unwrap_or_default();
                let diff = post.change() - pre.change();
                match mints.get_mut(token) {
                    Some(mint) => *mint += diff,
                    None => _ = mints.insert(token, diff),
                }

                // Check if the minter VP is called
                let minter_key = minter_key(token);
                let minter = match self.ctx.read_post(&minter_key)? {
                    Some(m) => m,
                    None => return Ok(false),
                };
                if !verifiers.contains(&minter) {
                    return Ok(false);
                }
            }
        }

        Ok(changes.iter().all(|(token, change)| {
            let mint = match mints.get(token) {
                Some(mint) => *mint,
                None => 0,
            };
            *change == mint
        }))
    }
}
