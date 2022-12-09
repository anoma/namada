//! Cryptographic signature keys

pub use namada_core::types::key::*;

use super::*;

/// Reveal a PK of an implicit account - the PK is written into the storage
/// of the address derived from the PK.
pub fn reveal_pk(ctx: &mut Ctx, pk: &common::PublicKey) -> EnvResult<()> {
    storage_api::key::reveal_pk(ctx, pk)
}
