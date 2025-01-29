//! Shielded and transparent tokens related functions

use namada_core::collections::HashSet;
#[cfg(any(test, feature = "testing"))]
pub use namada_token::testing;
pub use namada_token::tx::apply_shielded_transfer;
use namada_token::TransparentTransfersRef;
pub use namada_token::{
    storage_key, utils, Amount, DenominatedAmount, Store, Transfer,
};
use namada_tx::BatchedTx;
use namada_tx_env::Address;

use crate::{Ctx, Result, TxResult};

const EVENT_DESC: &str = "transfer-from-wasm";

/// Transfer transparent token, insert the verifier expected by the VP and an
/// emit an event.
pub fn transfer(
    ctx: &mut Ctx,
    src: &Address,
    dest: &Address,
    token: &Address,
    amount: Amount,
) -> TxResult {
    namada_token::tx::transfer(ctx, src, dest, token, amount, EVENT_DESC.into())
}

/// Transparent and shielded token transfers that can be used in a transaction.
pub fn multi_transfer(
    ctx: &mut Ctx,
    transfers: Transfer,
    tx_data: &BatchedTx,
) -> TxResult {
    namada_token::tx::multi_transfer(ctx, transfers, tx_data, EVENT_DESC.into())
}

/// Transfer tokens from `sources` to `targets` and submit a transfer event.
///
/// Returns an `Err` if any source has insufficient balance or if the transfer
/// to any destination would overflow (This can only happen if the total supply
/// doesn't fit in `token::Amount`). Returns a set of debited accounts.
pub fn apply_transparent_transfers(
    ctx: &mut Ctx,
    transfers: TransparentTransfersRef<'_>,
) -> Result<(HashSet<Address>, HashSet<Address>)> {
    namada_token::tx::apply_transparent_transfers(
        ctx,
        transfers,
        EVENT_DESC.into(),
    )
}
