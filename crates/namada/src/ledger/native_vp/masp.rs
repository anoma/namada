//! MASP native VP

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::transparent::Authorization;
use masp_primitives::transaction::components::{
    I128Sum, TxIn, TxOut, ValueSum,
};
use masp_primitives::transaction::{Transaction, TransparentAddress};
use namada_core::address::Address;
use namada_core::address::InternalAddress::Masp;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::collections::HashSet;
use namada_core::masp::encode_asset_type;
use namada_core::storage::{IndexedTx, Key};
use namada_gas::GasMetering;
use namada_governance::storage::is_proposal_accepted;
use namada_proof_of_stake::Epoch;
use namada_sdk::masp::verify_shielded_tx;
use namada_state::{ConversionState, OptionExt, ResultExt, StateRead};
use namada_token::read_denom;
use namada_tx::action::{Action, MaspAction, Read};
use namada_tx::Tx;
use namada_vp_env::VpEnv;
use num_traits::ops::checked::{CheckedAdd, CheckedSub};
use ripemd::Digest as RipemdDigest;
use sha2::Digest as Sha2Digest;
use thiserror::Error;
use token::storage_key::{
    is_any_shielded_action_balance_key, is_masp_key, is_masp_nullifier_key,
    is_masp_token_map_key, is_masp_transfer_key, is_masp_tx_pin_key,
    masp_commitment_anchor_key, masp_commitment_tree_key,
    masp_convert_anchor_key, masp_nullifier_key, ShieldedActionOwner,
};
use token::Amount;

use crate::ledger::native_vp;
use crate::ledger::native_vp::{Ctx, NativeVp, SignedAmount};
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

// The balances changed by the transaction, split between masp and non-masp
// balances. The masp collection carries the token addresses. The collection of
// the other balances maps the token address to the addresses of the
// senders/receivers, their balance diff and whether this is positive or
// negative diff
#[derive(Default)]
struct ChangedBalances {
    tokens: BTreeMap<AssetType, (Address, token::Denomination, MaspDigitPos)>,
    decoder: BTreeMap<TransparentAddress, Address>,
    pre: BTreeMap<TransparentAddress, ValueSum<Address, Amount>>,
    post: BTreeMap<TransparentAddress, ValueSum<Address, Amount>>,
}

impl<'a, S, CA> MaspVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Return if the parameter change was done via a governance proposal
    pub fn is_valid_parameter_change(&self, tx: &Tx) -> Result<()> {
        tx.data().map_or_else(
            || {
                Err(native_vp::Error::new_const(
                    "MASP parameter changes require tx data to be present",
                )
                .into())
            },
            |data| {
                is_proposal_accepted(&self.ctx.pre(), data.as_ref())
                    .map_err(Error::NativeVpError)?
                    .ok_or_else(|| {
                        native_vp::Error::new_const(
                            "MASP parameter changes can only be performed by \
                             a governance proposal that has been accepted",
                        )
                        .into()
                    })
            },
        )
    }

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
        for description in transaction
            .sapling_bundle()
            .map_or(&vec![], |bundle| &bundle.shielded_spends)
        {
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

    // Check that transfer is pinned correctly and record the balance changes
    fn validate_state_and_get_transfer_data(
        &self,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<ChangedBalances> {
        // Check that the transaction didn't write unallowed masp keys
        let masp_keys_changed: Vec<&Key> =
            keys_changed.iter().filter(|key| is_masp_key(key)).collect();

        // Validate pin key if found
        let pin_keys: Vec<_> = masp_keys_changed
            .iter()
            .filter(|key| is_masp_tx_pin_key(key))
            .collect();
        match &pin_keys[..] {
            [] => (),
            [pin_key] => match self.ctx.read_post::<IndexedTx>(pin_key)? {
                Some(IndexedTx { height, index, .. })
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
            .filter_map(is_any_shielded_action_balance_key)
            .collect();

        for (token, counterpart) in counterparts_balances {
            let denom = read_denom(&self.ctx.pre(), token)?.ok_or_err_msg(
                "No denomination found in storage for the given token",
            )?;
            unepoched_tokens(token, denom, &mut result.tokens)?;
            let counterpart_balance_key = counterpart.to_balance_key(token);
            let mut pre_balance: Amount = self
                .ctx
                .read_pre(&counterpart_balance_key)?
                .unwrap_or_default();
            let mut post_balance: Amount = self
                .ctx
                .read_post(&counterpart_balance_key)?
                .unwrap_or_default();
            if let ShieldedActionOwner::Minted = counterpart {
                // When receiving ibc transfers we mint and also shield so we
                // have two credits/debits, we need to mock the mint balance as
                // the opposite change
                std::mem::swap(&mut pre_balance, &mut post_balance);
            }
            // Public keys must be the hash of the sources/targets
            let address_hash = TransparentAddress(<[u8; 20]>::from(
                ripemd::Ripemd160::digest(sha2::Sha256::digest(
                    &counterpart.to_address_ref().serialize_to_vec(),
                )),
            ));

            result
                .decoder
                .insert(address_hash, counterpart.to_address_ref().clone());
            *result.pre.entry(address_hash).or_insert(ValueSum::zero()) +=
                ValueSum::from_pair(token.clone(), pre_balance);
            *result.post.entry(address_hash).or_insert(ValueSum::zero()) +=
                ValueSum::from_pair(token.clone(), post_balance);
        }

        Ok(result)
    }

    // Check that MASP Transaction and state changes are valid
    fn is_valid_masp_transfer(
        &self,
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
    ) -> Result<()> {
        let epoch = self.ctx.get_block_epoch()?;
        let conversion_state = self.ctx.state.in_mem().get_conversion_state();

        // Get the Transaction object from the actions
        let shielded_tx = self
            .ctx
            .read_actions()?
            .iter()
            .find_map(|action| {
                // In case of multiple masp actions we only get the first one
                if let Action::Masp(MaspAction {
                    ref masp_section_ref,
                }) = action
                {
                    tx_data.get_section(masp_section_ref)?.masp_tx()
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                native_vp::Error::new_const(
                    "Missing MASP section in transaction",
                )
            })?;

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
        let mut changed_balances =
            self.validate_state_and_get_transfer_data(keys_changed)?;

        let masp_address_hash = TransparentAddress(<[u8; 20]>::from(
            ripemd::Ripemd160::digest(sha2::Sha256::digest(
                &Address::Internal(Masp).serialize_to_vec(),
            )),
        ));
        verify_sapling_balancing_value(
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
        )?;

        // The set of addresses that are required to authorize this transaction
        let mut signers = BTreeSet::new();

        // Checks on the sapling bundle
        // 1. The spend descriptions' anchors are valid
        // 2. The convert descriptions's anchors are valid
        // 3. The nullifiers provided by the transaction have not been
        // revealed previously (even in the same tx) and no unneeded
        // nullifier is being revealed by the tx
        // 4. The transaction must correctly update the note commitment tree
        // in storage with the new output descriptions
        self.valid_spend_descriptions_anchor(&shielded_tx)?;
        self.valid_convert_descriptions_anchor(&shielded_tx)?;
        self.valid_nullifiers_reveal(keys_changed, &shielded_tx)?;
        self.valid_note_commitment_update(&shielded_tx)?;

        // Checks on the transparent bundle, if present
        validate_transparent_bundle(
            &shielded_tx,
            &mut changed_balances,
            &mut transparent_tx_pool,
            epoch,
            conversion_state,
            &mut signers,
        )?;

        // Ensure that every account for which balance has gone down has
        // authorized this transaction
        for (addr, pre) in changed_balances.pre {
            if changed_balances.post[&addr] < pre && addr != masp_address_hash {
                signers.insert(addr);
            }
        }

        let ibc_address_hash = TransparentAddress(<[u8; 20]>::from(
            ripemd::Ripemd160::digest(sha2::Sha256::digest(
                &Address::Internal(namada_core::address::InternalAddress::Ibc)
                    .serialize_to_vec(),
            )),
        ));

        // Ensure that this transaction is authorized by all involved parties
        for signer in signers {
            if signer == ibc_address_hash {
                // If the IBC address is a signatory, then it means that either
                // Tx - Transaction(s) causes a decrease in the IBC balance or
                // one of the Transactions' transparent inputs is the IBC. We
                // can't check whether such an action has been authorized by the
                // original sender since their address is not in this Namada
                // instance. However, we do know that the overall changes in the
                // IBC state are okay since the IBC VP does check this
                // transaction. So the best we can do is just to ensure that
                // funds intended for the IBC are not being siphoned from the
                // Transactions inside this Tx. We achieve this by not allowing
                // the IBC to be in the transparent output of any of the
                // Transaction(s).
                if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
                    for vout in transp_bundle.vout.iter() {
                        if vout.address == ibc_address_hash {
                            let error = native_vp::Error::new_const(
                                "Simultaneous credit and debit of IBC account \
                                 in a MASP transaction not allowed",
                            )
                            .into();
                            tracing::debug!("{error}");
                            return Err(error);
                        }
                    }
                }
            } else if let Some(signer) = changed_balances.decoder.get(&signer) {
                // Otherwise the signer must be decodable so that we can
                // manually check the signatures
                let public_keys_index_map =
                    crate::account::public_keys_index_map(
                        &self.ctx.pre(),
                        signer,
                    )?;
                let threshold =
                    crate::account::threshold(&self.ctx.pre(), signer)?
                        .unwrap_or(1);
                let max_signatures_per_transaction =
                    crate::parameters::max_signatures_per_transaction(
                        &self.ctx.pre(),
                    )?;
                let mut gas_meter = self.ctx.gas_meter.borrow_mut();
                tx_data
                    .verify_signatures(
                        &[tx_data.raw_header_hash()],
                        public_keys_index_map,
                        &Some(signer.clone()),
                        threshold,
                        max_signatures_per_transaction,
                        || gas_meter.consume(crate::gas::VERIFY_TX_SIG_GAS),
                    )
                    .map_err(native_vp::Error::new)?;
            } else {
                // We are not able to decode the signer, so just fail
                let error = native_vp::Error::new_const(
                    "Unable to decode a transaction signer",
                )
                .into();
                tracing::debug!("{error}");
                return Err(error);
            }
        }

        // Ensure that the shielded transaction exactly balances
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
    signers: &mut BTreeSet<TransparentAddress>,
) -> Result<()> {
    // A decrease in the balance of an account needs to be
    // authorized by the account of this transparent input
    signers.insert(vin.address);
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
        .entry(vin.address)
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
                .checked_sub(&ValueSum::from_pair(address.clone(), amount))
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
                let error =
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "epoch is missing from asset type",
                    ));
                tracing::debug!("{error}");
                return Err(error);
            } else {
                // Otherwise note the contribution to this transparent input
                let amount =
                    token::Amount::from_masp_denominated(vin.value, *digit);
                *bal_ref = bal_ref
                    .checked_sub(&ValueSum::from_pair(token.clone(), amount))
                    .ok_or_else(|| {
                        Error::NativeVpError(native_vp::Error::SimpleMessage(
                            "Overflow in bundle balance",
                        ))
                    })?;
            }
        }
        // unrecognized asset
        _ => {
            let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Unable to decode asset type",
            ));
            tracing::debug!("{error}");
            return Err(error);
        }
    };
    Ok(())
}

// Handle transparent output
fn validate_transparent_output(
    out: &TxOut,
    changed_balances: &mut ChangedBalances,
    transparent_tx_pool: &mut I128Sum,
    epoch: Epoch,
    conversion_state: &ConversionState,
) -> Result<()> {
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
        .entry(out.address)
        .or_insert(ValueSum::zero());

    match conversion_state.assets.get(&out.asset_type) {
        Some(((address, _asset_denom, digit), asset_epoch, _, _))
            if *asset_epoch <= epoch =>
        {
            let amount =
                token::Amount::from_masp_denominated(out.value, *digit);
            *bal_ref = bal_ref
                .checked_sub(&ValueSum::from_pair(address.clone(), amount))
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
                .checked_sub(&ValueSum::from_pair(token.clone(), amount))
                .ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in bundle balance",
                    ))
                })?;
        }
        // unrecognized asset
        _ => {
            let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Unable to decode asset type",
            ));
            tracing::debug!("{error}");
            return Err(error);
        }
    };
    Ok(())
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
    signers: &mut BTreeSet<TransparentAddress>,
) -> Result<()> {
    if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
        for vin in transp_bundle.vin.iter() {
            validate_transparent_input(
                vin,
                changed_balances,
                transparent_tx_pool,
                epoch,
                conversion_state,
                signers,
            )?;
        }

        for out in transp_bundle.vout.iter() {
            validate_transparent_output(
                out,
                changed_balances,
                transparent_tx_pool,
                epoch,
                conversion_state,
            )?;
        }
    }
    Ok(())
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
) -> Result<()> {
    let mut acc = ValueSum::<Address, SignedAmount>::from_sum(pre.clone());
    for (asset_type, val) in sapling_value_balance.components() {
        // Only assets with at most the target timestamp count
        match conversion_state.assets.get(asset_type) {
            Some(((address, _, digit), asset_epoch, _, _))
                if *asset_epoch <= target_epoch =>
            {
                let decoded_change = SignedAmount::from_masp_denominated(
                    *val, *digit,
                )
                .map_err(|_| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in MASP value balance",
                    ))
                })?;
                let decoded_change =
                    ValueSum::from_pair(address.clone(), decoded_change);
                acc = acc.checked_sub(&decoded_change).ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in MASP value balance",
                    ))
                })?;
            }
            None if tokens.contains_key(asset_type) => {
                let (token, _denom, digit) = &tokens[asset_type];
                let decoded_change = SignedAmount::from_masp_denominated(
                    *val, *digit,
                )
                .map_err(|_| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in MASP value balance",
                    ))
                })?;
                let decoded_change =
                    ValueSum::from_pair(token.clone(), decoded_change);
                acc = acc.checked_sub(&decoded_change).ok_or_else(|| {
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Overflow in MASP value balance",
                    ))
                })?;
            }
            _ => {
                let error =
                    Error::NativeVpError(native_vp::Error::SimpleMessage(
                        "Unable to decode asset type",
                    ));
                tracing::debug!("{error}");
                return Err(error);
            }
        }
    }
    if acc == ValueSum::from_sum(post.clone()) {
        Ok(())
    } else {
        let error = Error::NativeVpError(native_vp::Error::SimpleMessage(
            "MASP balance change not equal to Sapling value balance",
        ));
        tracing::debug!("{error}");
        Err(error)
    }
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
        let masp_keys_changed: Vec<&Key> =
            keys_changed.iter().filter(|key| is_masp_key(key)).collect();

        // Check that the transaction didn't write unallowed masp keys
        if masp_keys_changed.iter().any(|key| {
            !is_masp_transfer_key(key) && !is_masp_token_map_key(key)
        }) {
            return Err(Error::NativeVpError(native_vp::Error::SimpleMessage(
                "Found modifications to non-allowed masp keys",
            )));
        }
        // The token map can only be changed by a successful governance proposal
        if masp_keys_changed
            .iter()
            .any(|key| is_masp_token_map_key(key))
        {
            self.is_valid_parameter_change(tx_data)?;
        }
        // The MASP transfer keys can only be changed by a valid Transaction
        if masp_keys_changed
            .iter()
            .any(|key| is_masp_transfer_key(key))
        {
            self.is_valid_masp_transfer(tx_data, keys_changed)?;
        }
        Ok(())
    }
}
