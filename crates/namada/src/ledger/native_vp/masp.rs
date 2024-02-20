//! MASP native VP

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::transaction::Transaction;
use namada_core::address::Address;
use namada_core::address::InternalAddress::Masp;
use namada_core::masp::encode_asset_type;
use namada_core::storage::{IndexedTx, Key};
use namada_gas::MASP_VERIFY_SHIELDED_TX_GAS;
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
    is_masp_key, is_masp_nullifier_key, is_masp_tx_pin_key,
    masp_commitment_anchor_key, masp_commitment_tree_key,
    masp_convert_anchor_key, masp_nullifier_key,
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
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
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

#[derive(PartialEq)]
enum DeltaBalance {
    Positive(Amount),
    Negative(Amount),
}

impl DeltaBalance {
    fn checked_add(&self, rhs: Self) -> Option<Self> {
        match (self, rhs) {
            (Self::Positive(lhs), Self::Positive(rhs)) => {
                let tmp = lhs.checked_add(rhs)?;
                Some(Self::Positive(tmp))
            }
            (Self::Positive(lhs), Self::Negative(rhs)) => {
                match lhs.checked_sub(rhs) {
                    Some(diff) => Some(Self::Positive(diff)),
                    None => Some(Self::Negative(rhs - *lhs)),
                }
            }
            (Self::Negative(lhs), Self::Positive(rhs)) => {
                match rhs.checked_sub(*lhs) {
                    Some(diff) => Some(Self::Positive(diff)),
                    None => Some(Self::Negative(*lhs - rhs)),
                }
            }
            (Self::Negative(lhs), Self::Negative(rhs)) => {
                let tmp = lhs.checked_add(rhs)?;
                Some(Self::Negative(tmp))
            }
        }
    }
}

// The balances changed by the transaction, split between masp and non-masp
// balances. The masp collection carries the token addresses. The collection of
// the other balances maps the token address to the addresses of the
// senders/receivers, their balance diff and whether this is positive or
// negative diff
#[derive(Default)]
struct ChangedBalances<'vp> {
    masp: BTreeSet<&'vp Address>,
    other: BTreeMap<&'vp Address, BTreeMap<[u8; 20], DeltaBalance>>,
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
        let shielded_spends = match transaction.sapling_bundle() {
            Some(bundle) if !bundle.shielded_spends.is_empty() => {
                &bundle.shielded_spends
            }
            _ => {
                tracing::debug!(
                    "Missing expected spend descriptions in shielded \
                     transaction"
                );
                return Ok(false);
            }
        };

        for description in shielded_spends {
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
        match pin_keys.len() {
            0 => (),
            1 => {
                match self
                    .ctx
                    .read_post::<IndexedTx>(pin_keys.first().unwrap())?
                {
                    Some(IndexedTx { height, index })
                        if height == self.ctx.get_block_height()?
                            && index == self.ctx.get_tx_index()? => {}
                    Some(_) => {
                        return Err(Error::NativeVpError(
                            native_vp::Error::SimpleMessage(
                                "Invalid MASP pin key",
                            ),
                        ));
                    }
                    _ => (),
                }
            }
            _ => {
                return Err(Error::NativeVpError(
                    native_vp::Error::SimpleMessage(
                        "Found more than one pin key",
                    ),
                ));
            }
        }

        // FIXME: I also need to update note fetching in the client? Yes more
        // than one transfer

        let mut result = ChangedBalances::default();
        // Get the changed balance keys
        // FIXME: can partiotion here?
        // FIXME: does this also contain temp modification? Yes, is this
        // correct? I don't think so, I might end up validating keys that are
        // not committed, so wrong validation FIXME: probably I need to
        // read post from storage to circumvent this
        let balance_addresses: Vec<[&Address; 2]> = keys_changed
            .iter()
            .filter_map(is_any_shielded_action_balance_key)
            .collect();

        let masp_balances: Vec<&[&Address; 2]> = balance_addresses
            .iter()
            .filter(|addresses| addresses[1] == &Address::Internal(Masp))
            .collect();
        for &[token, _] in masp_balances {
            // NOTE: no need to extract the changes of the masp balances too,
            // we'll examine those of the other transparent addresses and the
            // multitoken vp ensures a correct match between the two sets
            result.masp.insert(token);
        }

        let counterparts: Vec<&[&Address; 2]> = balance_addresses
            .iter()
            .filter(|addresses| addresses[1] != &Address::Internal(Masp))
            .collect();

        for &[token, counterpart] in counterparts {
            // FIXME: incorrect use read_bytes like in the other places
            // otherwise I read temp modifications FIXME: also
            // mention this in red teaming. Also the fact that temporary keys
            // changed are passed to the vps
            let pre_balance: Amount = self
                .ctx
                .read_pre(&balance_key(token, counterpart))?
                .unwrap_or_default();
            // FIXME: incorrect use read_bytes like in the other places
            // otherwise I read temp modifications FIXME: actually,
            // not sure, maybe this method is correct, depend on the
            // implementation on Ctx
            let post_balance: Amount = self
                .ctx
                .read_post(&balance_key(token, counterpart))?
                .unwrap_or_default();
            // Public keys must be the hash of the sources/targets
            let address_hash = <[u8; 20]>::from(ripemd::Ripemd160::digest(
                sha2::Sha256::digest(&counterpart.serialize_to_vec()),
            ));
            let diff = match post_balance.checked_sub(pre_balance) {
                Some(diff) => DeltaBalance::Positive(diff),
                None => DeltaBalance::Negative(pre_balance - post_balance),
            };

            result
                .other
                .entry(token)
                .or_insert(BTreeMap::default())
                .insert(address_hash, diff);
        }

        Ok(result)
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
    ) -> Result<bool> {
        let epoch = self.ctx.get_block_epoch()?;
        let conversion_state = self.ctx.state.in_mem().get_conversion_state();
        let shielded_tx = self.ctx.get_shielded_action(tx_data)?;

        if u64::from(self.ctx.get_block_height()?)
            > u64::from(shielded_tx.expiry_height())
        {
            tracing::debug!("MASP transaction is expired");
            return Ok(false);
        }

        // FIXME: why do we need to look at the balance keys in the client?
        // Isn't Transaction enough?

        let mut transparent_tx_pool = I128Sum::zero();
        // The Sapling value balance adds to the transparent tx pool
        transparent_tx_pool += shielded_tx.sapling_value_balance();

        // Check the validity of the keys and get the transfer data
        let changed_balances =
            self.validate_state_and_get_transfer_data(keys_changed)?;

        // Checks on the sapling bundle
        // 1. The spend descriptions' anchors are valid
        // 2. The convert descriptions's anchors are valid
        // 3. The nullifiers provided by the transaction have not been
        // revealed previously (even in the same tx) and no unneeded
        // nullifier is being revealed by the tx
        // 4. The transaction must correctly update the note commitment tree
        // in storage with the new output descriptions
        // FIXME: actually I need to review all of these functions, I should
        // never assume that the sapling bundle is there
        if !(self.valid_spend_descriptions_anchor(&shielded_tx)?
            && self.valid_convert_descriptions_anchor(&shielded_tx)?
            && self.valid_nullifiers_reveal(keys_changed, &shielded_tx)?
            && self.valid_note_commitment_update(&shielded_tx)?)
        {
            return Ok(false);
        }

        // FIXME: extract to function
        // Checks on the transparent bundle, if present
        let bundle_balances = if let Some(transp_bundle) =
            shielded_tx.transparent_bundle()
        {
            let mut total_bundle_balances: BTreeMap<
                &Address,
                BTreeMap<[u8; 20], DeltaBalance>,
            > = BTreeMap::default();

            let mut unprocessed_vins =
                BTreeSet::from_iter(0..transp_bundle.vin.len());
            let mut unprocessed_vouts =
                BTreeSet::from_iter(0..transp_bundle.vout.len());

            // Run the checks fore every token involved in the transaction
            for token in changed_balances.masp {
                let denom = read_denom(&self.ctx.pre(), token)?.ok_or_err_msg(
                    "No denomination found in storage for the given token",
                )?;

                let mut token_bundle_balances = BTreeMap::default();

                // To help recognize asset types not in the conversion tree
                let unepoched_tokens = unepoched_tokens(token, denom)?;

                // FIXME: can we support a fully transparent transfer
                // triggering the masp vp? Probably not if it carries the
                // Transaction object. Actually maybe yes, in protcol
                // instead of just checking that the masp vp was triggered
                // and was succesful I should ALSO check that at least one
                // masp key was changed

                // Handle transparent input
                // The following boundary condition must be satisfied: asset
                // type must be properly derived
                for (ref idx, vin) in transp_bundle.vin.iter().enumerate() {
                    if !unprocessed_vins.contains(idx) {
                        continue;
                    }
                    // Non-masp sources add to the transparent tx pool
                    transparent_tx_pool = transparent_tx_pool
                        .checked_add(
                            &I128Sum::from_nonnegative(
                                vin.asset_type,
                                vin.value as i128,
                            )
                            .ok()
                            .ok_or_err_msg(
                                "invalid value or asset type for amount",
                            )?,
                        )
                        .ok_or_err_msg("Overflow in input sum")?;

                    match conversion_state.assets.get(&vin.asset_type) {
                        // Note how the asset's epoch must be equal to
                        // the present: users must never be allowed to
                        // backdate transparent
                        // inputs to a transaction for they would then
                        // be able to claim rewards while locking their
                        // assets for negligible
                        // time periods.
                        Some((
                            (address, asset_denom, digit),
                            asset_epoch,
                            _,
                            _,
                        )) if address == token
                            && *asset_denom == denom
                            && *asset_epoch == epoch =>
                        {
                            let amount = token::Amount::from_masp_denominated(
                                vin.value, *digit,
                            );
                            let bref = token_bundle_balances
                                .entry(vin.address.0)
                                .or_insert(DeltaBalance::Negative(
                                    Amount::default(),
                                ));
                            *bref = bref
                                .checked_add(DeltaBalance::Negative(amount))
                                .ok_or_else(|| {
                                    Error::NativeVpError(
                                        native_vp::Error::SimpleMessage(
                                            "Overflow in bundle balance",
                                        ),
                                    )
                                })?;
                        }
                        // Maybe the asset type has no attached epoch
                        None if unepoched_tokens
                            .contains_key(&vin.asset_type) =>
                        {
                            let (token, denom, digit) =
                                &unepoched_tokens[&vin.asset_type];
                            // Determine what the asset type would be if it
                            // were epoched
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
                                // If such an epoched asset type is
                                // available in the
                                // conversion tree, then we must reject the
                                // unepoched variant
                                tracing::debug!(
                                    "epoch is missing from asset type"
                                );
                                return Ok(false);
                            } else {
                                // Otherwise note the contribution to this
                                // transparent input
                                let amount =
                                    token::Amount::from_masp_denominated(
                                        vin.value, *digit,
                                    );
                                let bref = token_bundle_balances
                                    .entry(vin.address.0)
                                    .or_insert(DeltaBalance::Negative(
                                        Amount::default(),
                                    ));
                                *bref = bref
                                    .checked_add(DeltaBalance::Negative(amount))
                                    .ok_or_else(|| {
                                        Error::NativeVpError(
                                            native_vp::Error::SimpleMessage(
                                                "Overflow in bundle balance",
                                            ),
                                        )
                                    })?;
                            }
                        }
                        // unrecognized asset, will try with another token
                        _ => continue,
                    };

                    unprocessed_vins.remove(idx);
                }

                // Handle transparent output
                // The following boundary condition must be satisfied: asset
                // type must be properly derived
                for (ref idx, out) in transp_bundle.vout.iter().enumerate() {
                    if !unprocessed_vouts.contains(idx) {
                        continue;
                    }
                    // Non-masp destinations subtract from transparent tx
                    // pool
                    transparent_tx_pool = transparent_tx_pool
                        .checked_sub(
                            &I128Sum::from_nonnegative(
                                out.asset_type,
                                out.value as i128,
                            )
                            .ok()
                            .ok_or_err_msg(
                                "invalid value or asset type for amount",
                            )?,
                        )
                        .ok_or_err_msg("Underflow in output subtraction")?;

                    match conversion_state.assets.get(&out.asset_type) {
                        Some((
                            (address, asset_denom, digit),
                            asset_epoch,
                            _,
                            _,
                        )) if address == token
                            && *asset_denom == denom
                            && *asset_epoch <= epoch =>
                        {
                            let amount = token::Amount::from_masp_denominated(
                                out.value, *digit,
                            );
                            let bref = token_bundle_balances
                                .entry(out.address.0)
                                .or_insert(DeltaBalance::Positive(
                                    Amount::default(),
                                ));
                            *bref = bref
                                .checked_add(DeltaBalance::Positive(amount))
                                .ok_or_else(|| {
                                    Error::NativeVpError(
                                        native_vp::Error::SimpleMessage(
                                            "Overflow in bundle balance",
                                        ),
                                    )
                                })?;
                        }
                        // Maybe the asset type has no attached epoch
                        None if unepoched_tokens
                            .contains_key(&out.asset_type) =>
                        {
                            // Otherwise note the contribution to this
                            // transparent output
                            let (_token, _denom, digit) =
                                &unepoched_tokens[&out.asset_type];
                            let amount = token::Amount::from_masp_denominated(
                                out.value, *digit,
                            );
                            let bref = token_bundle_balances
                                .entry(out.address.0)
                                .or_insert(DeltaBalance::Positive(
                                    Amount::default(),
                                ));
                            *bref = bref
                                .checked_add(DeltaBalance::Positive(amount))
                                .ok_or_else(|| {
                                    Error::NativeVpError(
                                        native_vp::Error::SimpleMessage(
                                            "Overflow in bundle balance",
                                        ),
                                    )
                                })?;
                        }
                        // unrecognized asset, will try with another token
                        _ => continue,
                    };

                    unprocessed_vouts.remove(idx);
                }

                total_bundle_balances.insert(token, token_bundle_balances);
            }
            if !(unprocessed_vins.is_empty() && unprocessed_vouts.is_empty()) {
                tracing::debug!(
                    "Some transparent assets could not be recognized"
                );
                return Ok(false);
            }

            total_bundle_balances
        } else {
            BTreeMap::default()
        };

        // Check that the changed balance keys in storage match the
        // modifications carried by the transparent bundle
        if bundle_balances != changed_balances.other {
            // NOTE: this effectively prevent addresses from being
            // involved in other transparent transfers in the same tx since
            // that would lead to a different change in their balances
            tracing::debug!(
                "The transparent bundle modifications don't match the actual \
                 changes in storage."
            );
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
