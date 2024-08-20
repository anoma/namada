//! MASP utilities

use std::collections::BTreeSet;

use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::Transaction;

use crate::storage_key::{
    is_masp_transfer_key, masp_commitment_tree_key, masp_nullifier_key,
};
use crate::{Key, StorageError, StorageRead, StorageResult, StorageWrite};

// Writes the nullifiers of the provided masp transaction to storage
fn reveal_nullifiers(
    ctx: &mut impl StorageWrite,
    transaction: &Transaction,
) -> StorageResult<()> {
    for description in transaction
        .sapling_bundle()
        .map_or(&vec![], |description| &description.shielded_spends)
    {
        ctx.write(&masp_nullifier_key(&description.nullifier), ())?;
    }

    Ok(())
}

/// Appends the note commitments of the provided transaction to the merkle tree
/// and updates the anchor
/// NOTE: this function is public as a temporary workaround because of an issue
/// when running this function in WASM
pub fn update_note_commitment_tree(
    ctx: &mut (impl StorageRead + StorageWrite),
    transaction: &Transaction,
) -> StorageResult<()> {
    if let Some(bundle) = transaction.sapling_bundle() {
        if !bundle.shielded_outputs.is_empty() {
            let tree_key = masp_commitment_tree_key();
            let mut commitment_tree: CommitmentTree<Node> =
                ctx.read(&tree_key)?.ok_or(StorageError::SimpleMessage(
                    "Missing note commitment tree in storage",
                ))?;

            for description in &bundle.shielded_outputs {
                // Add cmu to the merkle tree
                commitment_tree
                    .append(Node::from_scalar(description.cmu))
                    .map_err(|_| {
                        StorageError::SimpleMessage(
                            "Note commitment tree is full",
                        )
                    })?;
            }

            ctx.write(&tree_key, commitment_tree)?;
        }
    }

    Ok(())
}

/// Handle a MASP transaction.
pub fn handle_masp_tx(
    ctx: &mut (impl StorageRead + StorageWrite),
    shielded: &Transaction,
) -> StorageResult<()> {
    // TODO(masp#73): temporarily disabled because of the node aggregation issue
    // in WASM. Using the host env tx_update_masp_note_commitment_tree or
    // directly the update_note_commitment_tree function as a  workaround
    // instead update_note_commitment_tree(ctx, shielded)?;
    reveal_nullifiers(ctx, shielded)?;

    Ok(())
}

/// Check if a transaction was a MASP transaction. This means
/// that at least one key owned by MASP was changed. We cannot
/// simply check that the MASP VP was triggered, as this can
/// be manually requested to be triggered by users.
pub fn is_masp_transfer(changed_keys: &BTreeSet<Key>) -> bool {
    changed_keys.iter().any(is_masp_transfer_key)
}
