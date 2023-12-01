//! MASP utilities

use masp_primitives::transaction::Transaction;

use super::storage_api::StorageWrite;
use crate::ledger::storage_api::Result;
use crate::types::address::MASP;
use crate::types::hash::Hash;
use crate::types::storage::{Key, KeySeg};
use crate::types::token::MASP_NULLIFIERS_KEY_PREFIX;

/// Writes the nullifiers of the provided masp transaction to storage
pub fn reveal_nullifiers(
    ctx: &mut impl StorageWrite,
    transaction: &Transaction,
) -> Result<()> {
    for description in transaction
        .sapling_bundle()
        .map_or(&vec![], |description| &description.shielded_spends)
    {
        let nullifier_key = Key::from(MASP.to_db_key())
            .push(&MASP_NULLIFIERS_KEY_PREFIX.to_owned())
            .expect("Cannot obtain a storage key")
            .push(&Hash(description.nullifier.0))
            .expect("Cannot obtain a storage key");
        ctx.write(&nullifier_key, ())?;
    }

    Ok(())
}
