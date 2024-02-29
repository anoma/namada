//! MASP native VP

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::transparent::Authorization;
use masp_primitives::transaction::components::{
    I128Sum, TxIn, TxOut, ValueSum,
};
use masp_primitives::transaction::Transaction;
use namada_core::types::address::Address;
use namada_core::types::address::InternalAddress::Masp;
use namada_core::types::masp::encode_asset_type;
use namada_core::types::storage::{IndexedTx, Key};
use namada_gas::MASP_VERIFY_SHIELDED_TX_GAS;
use namada_proof_of_stake::Epoch;
use namada_sdk::masp::verify_shielded_tx;
use namada_state::{ConversionState, OptionExt, ResultExt};
use namada_token::read_denom;
use namada_tx::Tx;
use namada_vp_env::VpEnv;
use num_traits::ops::checked::{CheckedAdd, CheckedSub};
use ripemd::Digest as RipemdDigest;
use sha2::Digest as Sha2Digest;
use thiserror::Error;
use token::storage_key::{
    balance_key, is_any_token_balance_key, is_masp_allowed_key, is_masp_key,
    is_masp_nullifier_key, is_masp_tx_pin_key, masp_commitment_anchor_key,
    masp_commitment_tree_key, masp_convert_anchor_key, masp_nullifier_key,
};
use token::Amount;

use crate::ledger::native_vp;
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::token;
use crate::types::token::MaspDigitPos;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
}

/// MASP VP result
pub type Result<T> = std::result::Result<T, Error>;

/// MASP VP
pub struct MaspVp<'a, DB, H, CA>
where
    DB: namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
    H: namada_state::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

// The balances changed by the transaction, split between masp and non-masp
// balances. The masp collection carries the token addresses. The collection of
// the other balances maps the token address to the addresses of the
// senders/receivers, their balance diff and whether this is positive or
// negative diff
#[derive(Default)]
struct ChangedBalances {
    tokens: BTreeMap<AssetType, (Address, token::Denomination, MaspDigitPos)>,
    pre: BTreeMap<[u8; 20], ValueSum<Address, Amount>>,
    post: BTreeMap<[u8; 20], ValueSum<Address, Amount>>,
}

impl<'a, DB, H, CA> MaspVp<'a, DB, H, CA>
where
    DB: 'static + namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
    H: 'static + namada_state::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    // Check that the transaction correctly revealed the nullifiers, if needed
    fn valid_nullifiers_reveal(
        &self,
        keys_changed: &BTreeSet<Key>,
        transaction: &Transaction,
    ) -> Result<bool> {
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
                tracing::debug!(
                    "MASP double spending attempt, the nullifier {:#?} has \
                     already been revealed previously",
                    description.nullifier.0
                );
                return Ok(false);
            }

            // Check that the nullifier is indeed committed (no temp write
            // and no delete) and carries no associated data (the latter not
            // strictly necessary for validation, but we don't expect any
            // value for this key anyway)
            match self.ctx.read_bytes_post(&nullifier_key)? {
                Some(value) if value.is_empty() => (),
                _ => return Ok(false),
            }

            revealed_nullifiers.insert(nullifier_key);
        }

        // Check that no unneeded nullifier has been revealed
        for nullifier_key in
            keys_changed.iter().filter(|key| is_masp_nullifier_key(key))
        {
            if !revealed_nullifiers.contains(nullifier_key) {
                tracing::debug!(
                    "An unexpected MASP nullifier key {nullifier_key} has \
                     been revealed by the transaction"
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    // Check that a transaction carrying output descriptions correctly updates
    // the tree and anchor in storage
    fn valid_note_commitment_update(
        &self,
        transaction: &Transaction,
    ) -> Result<bool> {
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
            tracing::debug!("The note commitment tree was incorrectly updated");
            return Ok(false);
        }

        Ok(true)
    }

    // Check that the spend descriptions anchors of a transaction are valid
    fn valid_spend_descriptions_anchor(
        &self,
        transaction: &Transaction,
    ) -> Result<bool> {
        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_spends)
        {
            let anchor_key = masp_commitment_anchor_key(description.anchor);

            // Check if the provided anchor was published before
            if !self.ctx.has_key_pre(&anchor_key)? {
                tracing::debug!(
                    "Spend description refers to an invalid anchor"
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    // Check that the convert descriptions anchors of a transaction are valid
    fn valid_convert_descriptions_anchor(
        &self,
        transaction: &Transaction,
    ) -> Result<bool> {
        if let Some(bundle) = transaction.sapling_bundle() {
            if !bundle.shielded_converts.is_empty() {
                let anchor_key = masp_convert_anchor_key();
                let expected_anchor = self
                    .ctx
                    .read_pre::<namada_core::types::hash::Hash>(&anchor_key)?
                    .ok_or(Error::NativeVpError(
                        native_vp::Error::SimpleMessage("Cannot read storage"),
                    ))?;

                for description in &bundle.shielded_converts {
                    // Check if the provided anchor matches the current
                    // conversion tree's one
                    if namada_core::types::hash::Hash(
                        description.anchor.to_bytes(),
                    ) != expected_anchor
                    {
                        tracing::debug!(
                            "Convert description refers to an invalid anchor"
                        );
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    fn validate_state_and_get_transfer_data<'vp>(
        &'vp self,
        keys_changed: &'vp BTreeSet<Key>,
    ) -> Result<ChangedBalances> {
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

        // Validate pin key if found
        let pin_keys: Vec<_> = masp_keys_changed
            .iter()
            .filter(|key| is_masp_tx_pin_key(key))
            .collect();
        match &pin_keys[..] {
            [] => (),
            [pin_key] => match self.ctx.read_post::<IndexedTx>(pin_key)? {
                Some(IndexedTx { height, index })
                    if height == self.ctx.get_block_height()?
                        && index == self.ctx.get_tx_index()? => {}
                Some(_) => {
                    return Err(Error::NativeVpError(
                        native_vp::Error::SimpleMessage("Invalid MASP pin key"),
                    ));
                }
                None => (),
            },
            _ => {
                return Err(Error::NativeVpError(
                    native_vp::Error::SimpleMessage(
                        "Found more than one pin key",
                    ),
                ));
            }
        }

        let mut result = ChangedBalances::default();
        // Get the changed balance keys
        let counterparts_balances: Vec<_> = keys_changed
            .iter()
            .filter_map(is_any_token_balance_key)
            .collect();

        for [token, counterpart] in counterparts_balances {
            let denom = read_denom(&self.ctx.pre(), token)?.ok_or_err_msg(
                "No denomination found in storage for the given token",
            )?;
            unepoched_tokens(token, denom, &mut result.tokens)?;
            let counterpart_balance_key = balance_key(token, counterpart);
            let pre_balance: Amount = self
                .ctx
                .read_pre(&counterpart_balance_key)?
                .unwrap_or_default();
            let post_balance: Amount = self
                .ctx
                .read_post(&counterpart_balance_key)?
                .unwrap_or_default();
            // Public keys must be the hash of the sources/targets
            let address_hash = <[u8; 20]>::from(ripemd::Ripemd160::digest(
                sha2::Sha256::digest(&counterpart.serialize_to_vec()),
            ));

            *result.pre.entry(address_hash).or_insert(ValueSum::zero()) +=
                ValueSum::from_pair(token.clone(), pre_balance).unwrap();
            *result.post.entry(address_hash).or_insert(ValueSum::zero()) +=
                ValueSum::from_pair(token.clone(), post_balance).unwrap();
        }

        Ok(result)
    }
}

// Make a map to help recognize asset types lacking an epoch
fn unepoched_tokens(
    token: &Address,
    denom: token::Denomination,
    tokens: &mut BTreeMap<
        AssetType,
        (Address, token::Denomination, MaspDigitPos),
    >,
) -> Result<()> {
    for digit in MaspDigitPos::iter() {
        let asset_type = encode_asset_type(token.clone(), denom, digit, None)
            .wrap_err("unable to create asset type")?;
        tokens.insert(asset_type, (token.clone(), denom, digit));
    }
    Ok(())
}

// Handle transparent input
fn validate_transparent_input<A: Authorization>(
    vin: &TxIn<A>,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: Epoch,
    conversion_state: &ConversionState,
) -> Result<bool> {
    // Non-masp sources add to the transparent tx pool
    *transparent_tx_pool = transparent_tx_pool
        .checked_add(
            &I128Sum::from_nonnegative(vin.asset_type, vin.value as i128)
                .ok()
                .ok_or_err_msg("invalid value or asset type for amount")?,
        )
        .ok_or_err_msg("Overflow in input sum")?;

    let bal_ref = changed_balances
        .pre
        .entry(vin.address.0)
        .or_insert(ValueSum::zero());

    match conversion_state.assets.get(&vin.asset_type) {
        // Note how the asset's epoch must be equal to the present: users
        // must never be allowed to backdate transparent inputs to a
        // transaction for they would then be able to claim rewards while
        // locking their assets for negligible time periods.
        Some(((address, _asset_denom, digit), asset_epoch, _, _))
            if *asset_epoch == epoch =>
        {
            let amount =
                token::Amount::from_masp_denominated(vin.value, *digit);
            *bal_ref = bal_ref
                .checked_sub(
                    &ValueSum::from_pair(address.clone(), amount).unwrap(),
                )
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in bundle balance",
                    ))
                })?;
        }
        // Maybe the asset type has no attached epoch
        None if changed_balances.tokens.contains_key(&vin.asset_type) => {
            let (token, denom, digit) =
                &changed_balances.tokens[&vin.asset_type];
            // Determine what the asset type would be if it were epoched
            let epoched_asset_type =
                encode_asset_type(token.clone(), *denom, *digit, Some(epoch))
                    .wrap_err("unable to create asset type")?;
            if conversion_state.assets.contains_key(&epoched_asset_type) {
                // If such an epoched asset type is available in the
                // conversion tree, then we must reject the unepoched
                // variant
                tracing::debug!("epoch is missing from asset type");
                return Ok(false);
            } else {
                // Otherwise note the contribution to this transparent input
                let amount =
                    token::Amount::from_masp_denominated(vin.value, *digit);
                *bal_ref = bal_ref
                    .checked_sub(
                        &ValueSum::from_pair(token.clone(), amount).unwrap(),
                    )
                    .ok_or_else(|| {
                        Error::NativeVpError(native_vp::Error::SimpleMessage(
                            "Overflow in bundle balance",
                        ))
                    })?;
            }
        }
        // unrecognized asset
        _ => return Ok(false),
    };
    Ok(true)
}

// Handle transparent output
fn validate_transparent_output(
    out: &TxOut,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: Epoch,
    conversion_state: &ConversionState,
) -> Result<bool> {
    // Non-masp destinations subtract from transparent tx pool
    *transparent_tx_pool = transparent_tx_pool
        .checked_sub(
            &I128Sum::from_nonnegative(out.asset_type, out.value as i128)
                .ok()
                .ok_or_err_msg("invalid value or asset type for amount")?,
        )
        .ok_or_err_msg("Underflow in output subtraction")?;

    let bal_ref = changed_balances
        .post
        .entry(out.address.0)
        .or_insert(ValueSum::zero());

    match conversion_state.assets.get(&out.asset_type) {
        Some(((address, _asset_denom, digit), asset_epoch, _, _))
            if *asset_epoch <= epoch =>
        {
            let amount =
                token::Amount::from_masp_denominated(out.value, *digit);
            *bal_ref = bal_ref
                .checked_sub(
                    &ValueSum::from_pair(address.clone(), amount).unwrap(),
                )
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in bundle balance",
                    ))
                })?;
        }
        // Maybe the asset type has no attached epoch
        None if changed_balances.tokens.contains_key(&out.asset_type) => {
            // Otherwise note the contribution to this transparent output
            let (token, _denom, digit) =
                &changed_balances.tokens[&out.asset_type];
            let amount =
                token::Amount::from_masp_denominated(out.value, *digit);
            *bal_ref = bal_ref
                .checked_sub(
                    &ValueSum::from_pair(token.clone(), amount).unwrap(),
                )
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in bundle balance",
                    ))
                })?;
        }
        // unrecognized asset
        _ => return Ok(false),
    };
    Ok(true)
}

// Update the transaction value pool and also ensure that the Transaction is
// consistent with the balance changes. I.e. the transparent inputs are not more
// than the initial balances and that the transparent outputs are not more than
// the final balances.
fn validate_transparent_bundle(
    shielded_tx: &Transaction,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: Epoch,
    conversion_state: &ConversionState,
) -> Result<bool> {
    if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
        for vin in transp_bundle.vin.iter() {
            if !validate_transparent_input(
                vin,
                changed_balances,
                transparent_tx_pool,
                epoch,
                conversion_state,
            )? {
                return Ok(false);
            }
        }

        for out in transp_bundle.vout.iter() {
            if !validate_transparent_output(
                out,
                changed_balances,
                transparent_tx_pool,
                epoch,
                conversion_state,
            )? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

// Verify that the pre balance + the Sapling value balance = the post balance
// using the decodings in tokens and conversion_state for assistance.
fn verify_sapling_balancing_value(
    pre: &ValueSum<Address, Amount>,
    post: &ValueSum<Address, Amount>,
    sapling_value_balance: &I128Sum,
    target_epoch: Epoch,
    tokens: &BTreeMap<AssetType, (Address, token::Denomination, MaspDigitPos)>,
    conversion_state: &ConversionState,
) -> Result<bool> {
    let mut acc = pre.clone();
    for (asset_type, val) in sapling_value_balance.components() {
        // Only assets with at most the target timestamp count
        match conversion_state.assets.get(asset_type) {
            Some(((address, _, digit), asset_epoch, _, _))
                if *asset_epoch <= target_epoch =>
            {
                let decoded_change = token::Amount::from_masp_denominated(
                    val.unsigned_abs() as u64,
                    *digit,
                );
                let decoded_change =
                    ValueSum::from_pair(address.clone(), decoded_change)
                        .expect("expected this to fit");
                if *val < 0 {
                    acc += decoded_change;
                } else {
                    acc -= decoded_change;
                }
            }
            None if tokens.contains_key(asset_type) => {
                let (token, _denom, digit) = &tokens[asset_type];
                let decoded_change = token::Amount::from_masp_denominated(
                    val.unsigned_abs() as u64,
                    *digit,
                );
                let decoded_change =
                    ValueSum::from_pair(token.clone(), decoded_change)
                        .expect("expected this to fit");
                if *val < 0 {
                    acc += decoded_change;
                } else {
                    acc -= decoded_change;
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(acc == *post)
}

impl<'a, DB, H, CA> NativeVp for MaspVp<'a, DB, H, CA>
where
    DB: 'static + namada_state::DB + for<'iter> namada_state::DBIter<'iter>,
    H: 'static + namada_state::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let epoch = self.ctx.get_block_epoch()?;
        let conversion_state = self.ctx.storage.get_conversion_state();
        let shielded_tx = self.ctx.get_shielded_action(tx_data)?;

        if u64::from(self.ctx.get_block_height()?)
            > u64::from(shielded_tx.expiry_height())
        {
            tracing::debug!("MASP transaction is expired");
            return Ok(false);
        }

        // The Sapling value balance adds to the transparent tx pool
        let mut transparent_tx_pool = shielded_tx.sapling_value_balance();

        // Check the validity of the keys and get the transfer data
        let mut changed_balances =
            self.validate_state_and_get_transfer_data(keys_changed)?;

        let masp_address_hash = <[u8; 20]>::from(ripemd::Ripemd160::digest(
            sha2::Sha256::digest(&Address::Internal(Masp).serialize_to_vec()),
        ));
        if !verify_sapling_balancing_value(
            changed_balances
                .pre
                .get(&masp_address_hash)
                .unwrap_or(&ValueSum::zero()),
            changed_balances
                .post
                .get(&masp_address_hash)
                .unwrap_or(&ValueSum::zero()),
            &shielded_tx.sapling_value_balance(),
            epoch,
            &changed_balances.tokens,
            conversion_state,
        )? {
            return Ok(false);
        }

        // Checks on the sapling bundle
        // 1. The spend descriptions' anchors are valid
        // 2. The convert descriptions's anchors are valid
        // 3. The nullifiers provided by the transaction have not been
        // revealed previously (even in the same tx) and no unneeded
        // nullifier is being revealed by the tx
        // 4. The transaction must correctly update the note commitment tree
        // in storage with the new output descriptions
        // Checks on the transparent bundle, if present
        if !(self.valid_spend_descriptions_anchor(&shielded_tx)?
            && self.valid_convert_descriptions_anchor(&shielded_tx)?
            && self.valid_nullifiers_reveal(keys_changed, &shielded_tx)?
            && self.valid_note_commitment_update(&shielded_tx)?
            && validate_transparent_bundle(
                &shielded_tx,
                &mut changed_balances,
                &mut transparent_tx_pool,
                epoch,
                conversion_state,
            )?)
        {
            return Ok(false);
        }

        match transparent_tx_pool.partial_cmp(&I128Sum::zero()) {
            None | Some(Ordering::Less) => {
                tracing::debug!(
                    "Transparent transaction value pool must be nonnegative. \
                     Violation may be caused by transaction being constructed \
                     in previous epoch. Maybe try again."
                );
                // Section 3.4: The remaining value in the transparent
                // transaction value pool MUST be nonnegative.
                return Ok(false);
            }
            Some(Ordering::Greater) => {
                tracing::debug!(
                    "Transaction fees cannot be paid inside MASP transaction."
                );
                return Ok(false);
            }
            _ => {}
        }

        // Verify the proofs and charge the gas for the expensive execution
        self.ctx
            .charge_gas(MASP_VERIFY_SHIELDED_TX_GAS)
            .map_err(Error::NativeVpError)?;
        Ok(verify_shielded_tx(&shielded_tx))
    }
}

impl From<native_vp::Error> for Error {
    fn from(err: native_vp::Error) -> Self {
        Self::NativeVpError(err)
    }
}
