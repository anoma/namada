//! MASP utilities

use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::Transaction;
use masp_proofs::bls12_381;

use super::storage_api::{StorageRead, StorageWrite};
use crate::ledger::storage_api::{Error, Result};
use crate::types::address::MASP;
use crate::types::hash::Hash;
use crate::types::storage::{BlockHeight, Epoch, Key, KeySeg, TxIndex};
use crate::types::token::{
    Transfer, HEAD_TX_KEY, MASP_NULLIFIERS_KEY_PREFIX, PIN_KEY_PREFIX,
    TX_KEY_PREFIX,
};
use crate::types::token::{
    MASP_NOTE_COMMITMENT_ANCHOR_PREFIX, MASP_NOTE_COMMITMENT_TREE,
    MASP_NULLIFIERS_KEY_PREFIX,
};

// Writes the nullifiers of the provided masp transaction to storage
fn reveal_nullifiers(
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

// Appends the note commitments of the provided transaction to the merkle tree
// and updates the anchor
fn update_note_commitment_tree(
    ctx: &mut (impl StorageRead + StorageWrite),
    transaction: &Transaction,
) -> Result<()> {
    if let Some(bundle) = transaction.sapling_bundle() {
        if !bundle.shielded_outputs.is_empty() {
            let tree_key = Key::from(MASP.to_db_key())
                .push(&MASP_NOTE_COMMITMENT_TREE.to_owned())
                .expect("Cannot obtain a storage key");
            let mut spend_tree = ctx
                .read::<CommitmentTree<Node>>(&tree_key)?
                .ok_or(Error::SimpleMessage(
                "Missing note commitment tree in storage",
            ))?;

            for description in &bundle.shielded_outputs {
                // Add cmu to the merkle tree
                spend_tree
                    .append(Node::from_scalar(description.cmu))
                    .map_err(|_| {
                        Error::SimpleMessage("Note commitment tree is full")
                    })?;
            }

            // Write the tree back to storage and update the anchor
            let updated_anchor = spend_tree.root();
            ctx.write(&tree_key, spend_tree)?;
            let anchor_key = Key::from(MASP.to_db_key())
                .push(&MASP_NOTE_COMMITMENT_ANCHOR_PREFIX.to_owned())
                .expect("Cannot obtain a storage key")
                .push(&Hash(bls12_381::Scalar::from(updated_anchor).to_bytes()))
                .expect("Cannot obtain a storage key");

            ctx.write(&anchor_key, ())?;
        }
    }

    Ok(())
}

/// Handle a MASP transaction.
pub fn handle_masp_tx(
    ctx: &mut (impl StorageRead + StorageWrite),
    transfer: &Transfer,
    shielded: &Transaction,
) -> Result<()> {
    let masp_addr = MASP;
    let head_tx_key = Key::from(masp_addr.to_db_key())
        .push(&HEAD_TX_KEY.to_owned())
        .expect("Cannot obtain a storage key");
    let current_tx_idx: u64 =
        ctx.read(&head_tx_key).unwrap_or(None).unwrap_or(0);
    let current_tx_key = Key::from(masp_addr.to_db_key())
        .push(&(TX_KEY_PREFIX.to_owned() + &current_tx_idx.to_string()))
        .expect("Cannot obtain a storage key");
    // Save the Transfer object and its location within the blockchain
    // so that clients do not have to separately look these
    // up
    let record: (Epoch, BlockHeight, TxIndex, Transfer, Transaction) = (
        ctx.get_block_epoch()?,
        ctx.get_block_height()?,
        ctx.get_tx_index()?,
        transfer.clone(),
        shielded.clone(),
    );
    ctx.write(&current_tx_key, record)?;
    ctx.write(&head_tx_key, current_tx_idx + 1)?;
    update_note_commitment_tree(ctx, shielded)?;
    reveal_nullifiers(ctx, shielded)?;

    // If storage key has been supplied, then pin this transaction to it
    if let Some(key) = &transfer.key {
        let pin_key = Key::from(masp_addr.to_db_key())
            .push(&(PIN_KEY_PREFIX.to_owned() + key))
            .expect("Cannot obtain a storage key");
        ctx.write(&pin_key, current_tx_idx)?;
    }

    Ok(())
}
