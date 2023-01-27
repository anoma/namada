//! Cryptographic signature keys

use namada_core::types::address::Address;
pub use namada_core::types::key::*;

use super::*;

/// Get the public key associated with the given address from the state prior to
/// tx execution. Returns `Ok(None)` if not found.
pub fn get(ctx: &Ctx, owner: &Address, index: u64) -> EnvResult<Option<common::PublicKey>> {
    storage_api::key::get(&ctx.pre(), owner, index)
}

/// Get the threshold associated with the given address from the state prior to
/// tx execution. Returns `Ok(None)` if not found.
pub fn threshold(ctx: &Ctx, owner: &Address) -> EnvResult<Option<u64>> {
    storage_api::key::threshold(&ctx.pre(), owner)
}

