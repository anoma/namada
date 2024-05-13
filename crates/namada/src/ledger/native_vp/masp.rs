//! MASP native VP

use std::cmp::Ordering;
use std::collections::BTreeSet;

use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::transaction::Transaction;
use namada_core::address::Address;
use namada_core::address::InternalAddress::Masp;
use namada_core::arith::checked;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::collections::{HashMap, HashSet};
use namada_core::masp::encode_asset_type;
use namada_core::storage::Key;
use namada_sdk::masp::verify_shielded_tx;
use namada_state::{OptionExt, ResultExt, StateRead};
use namada_token::read_denom;
use namada_tx::Tx;
use namada_vp_env::VpEnv;
use num_traits::ops::checked::{CheckedAdd, CheckedSub};
use ripemd::Digest as RipemdDigest;
use sha2::Digest as Sha2Digest;
use thiserror::Error;
use token::storage_key::{
    balance_key, is_any_shielded_action_balance_key, is_masp_allowed_key,
    is_masp_key, is_masp_nullifier_key, masp_commitment_anchor_key,
    masp_commitment_tree_key, masp_convert_anchor_key, masp_nullifier_key,
};
use token::Amount;

use crate::ledger::native_vp;
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::token;
use crate::token::MaspDigitPos;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("MASP VP error: Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// MASP VP result
pub type Result<T> = std::result::Result<T, Error>;

/// MASP VP
pub struct MaspVp<'a, S, CA>
where
    S: StateRead,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA>,
}

struct TransparentTransferData {
    source: Address,
    target: Address,
    token: Address,
    amount: Amount,
}

impl<'a, S, CA> MaspVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    // Check that the transaction correctly revealed the nullifiers, if needed
    fn valid_nullifiers_reveal(
        &self,
        keys_changed: &BTreeSet<Key>,
        transaction: &Transaction,
    ) -> Result<()> {
        // Support set to check that a nullifier was not revealed more
        // than once in the same tx
        let mut revealed_nullifiers = HashSet::new();

        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_spends)
        {
            let nullifier_key = masp_nullifier_key(&description.nullifier);
            if self.ctx.has_key_pre(&nullifier_key)?
                || revealed_nullifiers.contains(&nullifier_key)
            {
                let error = native_vp::Error::new_alloc(format!(
                    "MASP double spending attempt, the nullifier {:?} has \
                     already been revealed previously",
                    description.nullifier.0,
                ))
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }

            // Check that the nullifier is indeed committed (no temp write
            // and no delete) and carries no associated data (the latter not
            // strictly necessary for validation, but we don't expect any
            // value for this key anyway)
            self.ctx
                .read_bytes_post(&nullifier_key)?
                .is_some_and(|value| value.is_empty())
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::new_const(
                        "The nullifier should have been committed with no \
                         associated data",
                    ))
                })?;

            revealed_nullifiers.insert(nullifier_key);
        }

        // Check that no unneeded nullifier has been revealed
        for nullifier_key in
            keys_changed.iter().filter(|key| is_masp_nullifier_key(key))
        {
            if !revealed_nullifiers.contains(nullifier_key) {
                let error = native_vp::Error::new_alloc(format!(
                    "An unexpected MASP nullifier key {nullifier_key} has \
                     been revealed by the transaction"
                ))
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        Ok(())
    }

    // Check that a transaction carrying output descriptions correctly updates
    // the tree and anchor in storage
    fn valid_note_commitment_update(
        &self,
        transaction: &Transaction,
    ) -> Result<()> {
        // Check that the merkle tree in storage has been correctly updated with
        // the output descriptions cmu
        let tree_key = masp_commitment_tree_key();
        let mut previous_tree: CommitmentTree<Node> =
            self.ctx.read_pre(&tree_key)?.ok_or(Error::NativeVpError(
                native_vp::Error::SimpleMessage("Cannot read storage"),
            ))?;
        let post_tree: CommitmentTree<Node> =
            self.ctx.read_post(&tree_key)?.ok_or(Error::NativeVpError(
                native_vp::Error::SimpleMessage("Cannot read storage"),
            ))?;

        // Based on the output descriptions of the transaction, update the
        // previous tree in storage
        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_outputs)
        {
            previous_tree
                .append(Node::from_scalar(description.cmu))
                .map_err(|()| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Failed to update the commitment tree",
                    ))
                })?;
        }
        // Check that the updated previous tree matches the actual post tree.
        // This verifies that all and only the necessary notes have been
        // appended to the tree
        if previous_tree != post_tree {
            let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
                "The note commitment tree was incorrectly updated",
            ));
            tracing::debug!("{error}");
            return Err(error);
        }

        Ok(())
    }

    // Check that the spend descriptions anchors of a transaction are valid
    fn valid_spend_descriptions_anchor(
        &self,
        transaction: &Transaction,
    ) -> Result<()> {
        let shielded_spends = match transaction.sapling_bundle() {
            Some(bundle) if !bundle.shielded_spends.is_empty() => {
                &bundle.shielded_spends
            }
            _ => {
                let error =
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Missing expected spend descriptions in shielded \
                         transaction",
                    ));
                tracing::debug!("{error}");
                return Err(error);
            }
        };

        for description in shielded_spends {
            let anchor_key = masp_commitment_anchor_key(description.anchor);

            // Check if the provided anchor was published before
            if !self.ctx.has_key_pre(&anchor_key)? {
                let error =
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Spend description refers to an invalid anchor",
                    ));
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        Ok(())
    }

    // Check that the convert descriptions anchors of a transaction are valid
    fn valid_convert_descriptions_anchor(
        &self,
        transaction: &Transaction,
    ) -> Result<()> {
        if let Some(bundle) = transaction.sapling_bundle() {
            if !bundle.shielded_converts.is_empty() {
                let anchor_key = masp_convert_anchor_key();
                let expected_anchor = self
                    .ctx
                    .read_pre::<namada_core::hash::Hash>(&anchor_key)?
                    .ok_or(Error::NativeVpError(
                        native_vp::Error::SimpleMessage("Cannot read storage"),
                    ))?;

                for description in &bundle.shielded_converts {
                    // Check if the provided anchor matches the current
                    // conversion tree's one
                    if namada_core::hash::Hash(description.anchor.to_bytes())
                        != expected_anchor
                    {
                        let error = Error::NativeVpError(
                            native_vp::Error::SimpleMessage(
                                "Convert description refers to an invalid \
                                 anchor",
                            ),
                        );
                        tracing::debug!("{error}");
                        return Err(error);
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_state_and_get_transfer_data(
        &self,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<TransparentTransferData> {
        // Check that the transaction didn't write unallowed masp keys
        let masp_keys_changed: Vec<&Key> =
            keys_changed.iter().filter(|key| is_masp_key(key)).collect();

        if masp_keys_changed
            .iter()
            .any(|key| !is_masp_allowed_key(key))
        {
            return Err(Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Found modifications to non-allowed masp keys",
            )));
        }

        // Verify the changes to balance keys and return the transparent
        // transfer data Get the token from the balance key of the MASP
        let balance_addresses: Vec<[&Address; 2]> = keys_changed
            .iter()
            .filter_map(is_any_shielded_action_balance_key)
            .collect();

        let masp_balances: Vec<&[&Address; 2]> = balance_addresses
            .iter()
            .filter(|addresses| addresses[1] == &Address::Internal(Masp))
            .collect();
        let token = match masp_balances.len() {
            0 => {
                // No masp balance modification found, assume shielded
                // transaction and return dummy transparent data
                return Ok(TransparentTransferData {
                    source: Address::Internal(Masp),
                    target: Address::Internal(Masp),
                    token: self.ctx.get_native_token()?,
                    amount: Amount::zero(),
                });
            }
            1 => masp_balances[0][0].to_owned(),
            _ => {
                // Only one transparent balance of MASP can be updated by the
                // shielding or unshielding transaction
                return Err(Error::NativeVpError(
                    native_vp::Error::SimpleMessage(
                        "More than one MASP transparent balance was modified",
                    ),
                ));
            }
        };

        let counterparts: Vec<&[&Address; 2]> = balance_addresses
            .iter()
            .filter(|addresses| addresses[1] != &Address::Internal(Masp))
            .collect();
        // NOTE: since we don't allow more than one transfer per tx in this vp,
        // there's no need to check the token address in the balance key nor the
        // change to the actual balance, the multitoken VP will verify these
        let counterpart = match counterparts.len() {
            1 => counterparts[0][1].to_owned(),
            _ => {
                return Err(Error::NativeVpError(
                    native_vp::Error::SimpleMessage(
                        "An invalid number of non-MASP transparent balances \
                         was modified",
                    ),
                ));
            }
        };

        let pre_masp_balance: Amount = self
            .ctx
            .read_pre(&balance_key(&token, &Address::Internal(Masp)))?
            .unwrap_or_default();
        let post_masp_balance: Amount = self
            .ctx
            .read_post(&balance_key(&token, &Address::Internal(Masp)))?
            .unwrap_or_default();
        let (amount, source, target) =
            match pre_masp_balance.cmp(&post_masp_balance) {
                Ordering::Equal => {
                    return Err(Error::NativeVpError(
                        native_vp::Error::SimpleMessage(
                            "Found a MASP transaction that moves no \
                             transparent funds",
                        ),
                    ));
                }
                Ordering::Less => (
                    checked!(post_masp_balance - pre_masp_balance)
                        .map_err(|e| Error::NativeVpError(e.into()))?,
                    counterpart,
                    Address::Internal(Masp),
                ),
                Ordering::Greater => (
                    checked!(pre_masp_balance - post_masp_balance)
                        .map_err(|e| Error::NativeVpError(e.into()))?,
                    Address::Internal(Masp),
                    counterpart,
                ),
            };

        Ok(TransparentTransferData {
            source,
            target,
            token,
            amount,
        })
    }
}

// Make a map to help recognize asset types lacking an epoch
fn unepoched_tokens(
    token: &Address,
    denom: token::Denomination,
) -> Result<HashMap<AssetType, (Address, token::Denomination, MaspDigitPos)>> {
    let mut unepoched_tokens = HashMap::new();
    for digit in MaspDigitPos::iter() {
        let asset_type = encode_asset_type(token.clone(), denom, digit, None)
            .wrap_err("unable to create asset type")?;
        unepoched_tokens.insert(asset_type, (token.clone(), denom, digit));
    }
    Ok(unepoched_tokens)
}

impl<'a, S, CA> NativeVp for MaspVp<'a, S, CA>
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
        let epoch = self.ctx.get_block_epoch()?;
        let conversion_state = self.ctx.state.in_mem().get_conversion_state();
        let shielded_tx = self.ctx.get_shielded_action(tx_data)?;

        if u64::from(self.ctx.get_block_height()?)
            > u64::from(shielded_tx.expiry_height())
        {
            let error =
                native_vp::Error::new_const("MASP transaction is expired")
                    .into();
            tracing::debug!("{error}");
            return Err(error);
        }

        // The Sapling value balance adds to the transparent tx pool
        let mut transparent_tx_pool = shielded_tx.sapling_value_balance();

        // Check the validity of the keys and get the transfer data
        let transfer =
            self.validate_state_and_get_transfer_data(keys_changed)?;

        let denom = read_denom(&self.ctx.pre(), &transfer.token)?
            .ok_or_err_msg(
                "No denomination found in storage for the given token",
            )?;

        if transfer.source != Address::Internal(Masp) {
            // No shielded spends nor shielded conversions are allowed
            if shielded_tx.sapling_bundle().is_some_and(|bundle| {
                !(bundle.shielded_spends.is_empty()
                    && bundle.shielded_converts.is_empty())
            }) {
                let error = native_vp::Error::new_const(
                    "No shielded spends nor shielded conversions are allowed",
                )
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }

            let transp_bundle =
                shielded_tx.transparent_bundle().ok_or_err_msg(
                    "Expected transparent outputs in shielding transaction",
                )?;
            let mut total_in_values = token::Amount::zero();
            let source_enc = transfer.source.serialize_to_vec();
            let hash =
                ripemd::Ripemd160::digest(sha2::Sha256::digest(&source_enc));

            // To help recognize asset types not in the conversion tree
            let unepoched_tokens = unepoched_tokens(&transfer.token, denom)?;
            // Handle transparent input
            //
            // The following boundary conditions must be satisfied:
            //
            // 1. Total of transparent input values equals containing transfer
            // amount
            //
            // 2. Asset type must be properly derived
            //
            // 3. Public key must be the hash of the source
            for vin in &transp_bundle.vin {
                // Non-masp sources add to the transparent tx pool
                transparent_tx_pool = transparent_tx_pool
                    .checked_add(
                        &I128Sum::from_nonnegative(
                            vin.asset_type,
                            i128::from(vin.value),
                        )
                        .ok()
                        .ok_or_err_msg(
                            "invalid value or asset type for amount",
                        )?,
                    )
                    .ok_or_err_msg("Overflow in input sum")?;

                // Satisfies 3.
                if <[u8; 20]>::from(hash) != vin.address.0 {
                    let error = native_vp::Error::new_const(
                        "The public key of the output account does not match \
                         the transfer target",
                    )
                    .into();
                    tracing::debug!("{error}");
                    return Err(error);
                }
                match conversion_state.assets.get(&vin.asset_type) {
                    // Satisfies 2. Note how the asset's epoch must be equal to
                    // the present: users must never be allowed to backdate
                    // transparent inputs to a transaction for they would then
                    // be able to claim rewards while locking their assets for
                    // negligible time periods.
                    Some((
                        (address, asset_denom, digit),
                        asset_epoch,
                        _,
                        _,
                    )) if *address == transfer.token
                        && *asset_denom == denom
                        && *asset_epoch == epoch =>
                    {
                        total_in_values = total_in_values
                            .checked_add(token::Amount::from_masp_denominated(
                                vin.value, *digit,
                            ))
                            .ok_or_else(|| {
                                Error::NativeVpError(
                                    native_vp::Error::SimpleMessage(
                                        "Overflow in total in value sum",
                                    ),
                                )
                            })?;
                    }
                    // Maybe the asset type has no attached epoch
                    None if unepoched_tokens.contains_key(&vin.asset_type) => {
                        let (token, denom, digit) =
                            &unepoched_tokens[&vin.asset_type];
                        // Determine what the asset type would be if it were
                        // epoched
                        let epoched_asset_type = encode_asset_type(
                            token.clone(),
                            *denom,
                            *digit,
                            Some(epoch),
                        )
                        .wrap_err("unable to create asset type")?;
                        if conversion_state
                            .assets
                            .contains_key(&epoched_asset_type)
                        {
                            // If such an epoched asset type is available in the
                            // conversion tree, then we must reject the
                            // unepoched variant
                            let error = native_vp::Error::new_const(
                                "Epoch is missing from asset type",
                            )
                            .into();
                            tracing::debug!("{error}");
                            return Err(error);
                        } else {
                            // Otherwise note the contribution to this
                            // trransparent input
                            total_in_values = total_in_values
                                .checked_add(
                                    token::Amount::from_masp_denominated(
                                        vin.value, *digit,
                                    ),
                                )
                                .ok_or_else(|| {
                                    Error::NativeVpError(
                                        native_vp::Error::SimpleMessage(
                                            "Overflow in total in values sum",
                                        ),
                                    )
                                })?;
                        }
                    }
                    // unrecognized asset
                    _ => {
                        return Err(native_vp::Error::new_alloc(format!(
                            "Unrecognized asset {}",
                            vin.asset_type
                        ))
                        .into());
                    }
                };
            }
            // Satisfies 1.
            if total_in_values != transfer.amount {
                return Err(native_vp::Error::new_const(
                    "Total amount of transparent input values was not the \
                     same as the transferred amount",
                )
                .into());
            }
        } else {
            // Handle shielded input
            // The following boundary conditions must be satisfied
            // 1. Zero transparent input
            // 2. At least one shielded input
            // 3. The spend descriptions' anchors are valid
            // 4. The convert descriptions's anchors are valid
            if shielded_tx
                .transparent_bundle()
                .is_some_and(|bundle| !bundle.vin.is_empty())
            {
                let error = native_vp::Error::new_const(
                    "Transparent input to a transaction from the masp must be \
                     0",
                )
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }

            if !shielded_tx
                .sapling_bundle()
                .is_some_and(|bundle| !bundle.shielded_spends.is_empty())
            {
                return Err(Error::NativeVpError(
                    native_vp::Error::SimpleMessage(
                        "Missing expected shielded spends",
                    ),
                ));
            }

            self.valid_spend_descriptions_anchor(&shielded_tx)?;
            self.valid_convert_descriptions_anchor(&shielded_tx)?;
        }

        // The transaction must correctly update the note commitment tree
        // in storage with the new output descriptions and also reveal the
        // nullifiers correctly (only if needed) NOTE: these two checks
        // validate the keys that the transaction write in storage and therefore
        // must be done regardless of the type of transaction (shielding,
        // shielded, unshielding) since a malicious tx could try to write keys
        // in an invalid way
        self.valid_note_commitment_update(&shielded_tx)?;
        self.valid_nullifiers_reveal(keys_changed, &shielded_tx)?;

        if transfer.target != Address::Internal(Masp) {
            // Handle transparent output
            //
            // The following boundary conditions must be satisfied:
            //
            // 1. Total of transparent output values equals containing transfer
            // amount
            //
            // 2. Asset type must be properly derived
            //
            // 3. Public key must be the hash of the target

            let transp_bundle =
                shielded_tx.transparent_bundle().ok_or_err_msg(
                    "Expected transparent outputs in unshielding transaction",
                )?;

            let mut total_out_values = token::Amount::zero();
            let target_enc = transfer.target.serialize_to_vec();
            let hash =
                ripemd::Ripemd160::digest(sha2::Sha256::digest(&target_enc));
            // To help recognize asset types not in the conversion tree
            let unepoched_tokens = unepoched_tokens(&transfer.token, denom)?;

            for out in &transp_bundle.vout {
                // Non-masp destinations subtract from transparent tx
                // pool
                transparent_tx_pool = transparent_tx_pool
                    .checked_sub(
                        &I128Sum::from_nonnegative(
                            out.asset_type,
                            i128::from(out.value),
                        )
                        .ok()
                        .ok_or_err_msg(
                            "invalid value or asset type for amount",
                        )?,
                    )
                    .ok_or_err_msg("Underflow in output subtraction")?;

                // Satisfies 3.
                if <[u8; 20]>::from(hash) != out.address.0 {
                    let error = native_vp::Error::new_const(
                        "The public key of the output account does not match \
                         the transfer target",
                    )
                    .into();
                    tracing::debug!("{error}");
                    return Err(error);
                }
                match conversion_state.assets.get(&out.asset_type) {
                    // Satisfies 2.
                    Some((
                        (address, asset_denom, digit),
                        asset_epoch,
                        _,
                        _,
                    )) if *address == transfer.token
                        && *asset_denom == denom
                        && *asset_epoch <= epoch =>
                    {
                        total_out_values = total_out_values
                            .checked_add(token::Amount::from_masp_denominated(
                                out.value, *digit,
                            ))
                            .ok_or_else(|| {
                                Error::NativeVpError(
                                    native_vp::Error::SimpleMessage(
                                        "Overflow in total out values sum",
                                    ),
                                )
                            })?;
                    }
                    // Maybe the asset type has no attached epoch
                    None if unepoched_tokens.contains_key(&out.asset_type) => {
                        let (_token, _denom, digit) =
                            &unepoched_tokens[&out.asset_type];
                        // Otherwise note the contribution to this
                        // trransparent input
                        total_out_values = total_out_values
                            .checked_add(token::Amount::from_masp_denominated(
                                out.value, *digit,
                            ))
                            .ok_or_else(|| {
                                Error::NativeVpError(
                                    native_vp::Error::SimpleMessage(
                                        "Overflow in total out values sum",
                                    ),
                                )
                            })?;
                    }
                    // unrecognized asset
                    _ => {
                        return Err(native_vp::Error::new_alloc(format!(
                            "Unrecognized asset {}",
                            out.asset_type
                        ))
                        .into());
                    }
                };
            }
            // Satisfies 1.
            if total_out_values != transfer.amount {
                return Err(native_vp::Error::new_const(
                    "Total amount of transparent output values was not the \
                     same as the transferred amount",
                )
                .into());
            }
        } else {
            // Handle shielded output
            // The following boundary conditions must be satisfied
            // 1. Zero transparent output
            // 2. At least one shielded output

            // Satisfies 1.
            if shielded_tx
                .transparent_bundle()
                .is_some_and(|bundle| !bundle.vout.is_empty())
            {
                let error = native_vp::Error::new_const(
                    "Transparent output to a transaction from the masp must \
                     be 0",
                )
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }

            // Staisfies 2.
            if !shielded_tx
                .sapling_bundle()
                .is_some_and(|bundle| !bundle.shielded_outputs.is_empty())
            {
                let error = native_vp::Error::new_const(
                    "There were no shielded outputs in the sapling bundle",
                )
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        match transparent_tx_pool.partial_cmp(&I128Sum::zero()) {
            None | Some(Ordering::Less) => {
                let error = native_vp::Error::new_const(
                    "Transparent transaction value pool must be nonnegative. \
                     Violation may be caused by transaction being constructed \
                     in previous epoch. Maybe try again.",
                )
                .into();
                tracing::debug!("{error}");
                // Section 3.4: The remaining value in the transparent
                // transaction value pool MUST be nonnegative.
                return Err(error);
            }
            Some(Ordering::Greater) => {
                let error = native_vp::Error::new_const(
                    "Transaction fees cannot be paid inside MASP transaction.",
                )
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }
            _ => {}
        }

        // Verify the proofs
        verify_shielded_tx(&shielded_tx, |gas| self.ctx.charge_gas(gas))
            .map_err(Error::NativeVpError)
    }
}
