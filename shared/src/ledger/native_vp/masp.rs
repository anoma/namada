//! MASP native VP

use std::cmp::Ordering;
use std::collections::BTreeSet;

use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::I128Sum;
use namada_core::ledger::gas::MASP_VERIFY_SHIELDED_TX_GAS;
use namada_core::ledger::storage;
use namada_core::ledger::storage_api::OptionExt;
use namada_core::ledger::vp_env::VpEnv;
use namada_core::proto::Tx;
use namada_core::types::address::Address;
use namada_core::types::address::InternalAddress::Masp;
use namada_core::types::storage::{Epoch, Key};
use namada_core::types::token;
use namada_sdk::masp::verify_shielded_tx;
use ripemd::Digest as RipemdDigest;
use sha2::Digest as Sha2Digest;
use thiserror::Error;

use crate::ledger::native_vp;
use crate::ledger::native_vp::{Ctx, NativeVp};
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
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

/// Generates the current asset type given the current epoch and an
/// unique token address
fn asset_type_from_epoched_address(
    epoch: Epoch,
    token: &Address,
    denom: token::MaspDenom,
) -> AssetType {
    // Timestamp the chosen token with the current epoch
    let token_bytes = (token, denom, epoch.0).serialize_to_vec();
    // Generate the unique asset identifier from the unique token address
    AssetType::new(token_bytes.as_ref()).expect("unable to create asset type")
}

/// Checks if the asset type matches the expected asset type, Adds a
/// debug log if the values do not match.
fn valid_asset_type(
    asset_type: &AssetType,
    asset_type_to_test: &AssetType,
) -> bool {
    let res =
        asset_type.get_identifier() == asset_type_to_test.get_identifier();
    if !res {
        tracing::debug!(
            "The asset type must be derived from the token address and \
             current epoch"
        );
    }
    res
}

/// Checks if the reported transparent amount and the unshielded
/// values agree, if not adds to the debug log
fn valid_transfer_amount(
    reporeted_transparent_value: u64,
    unshielded_transfer_value: u64,
) -> bool {
    let res = reporeted_transparent_value == unshielded_transfer_value;
    if !res {
        tracing::debug!(
            "The unshielded amount {} disagrees with the calculated masp \
             transparented value {}",
            unshielded_transfer_value,
            reporeted_transparent_value
        );
    }
    res
}

/// Convert Namada amount and token type to MASP equivalents
fn convert_amount(
    epoch: Epoch,
    token: &Address,
    val: token::Amount,
    denom: token::MaspDenom,
) -> (AssetType, I128Sum) {
    let asset_type = asset_type_from_epoched_address(epoch, token, denom);
    // Combine the value and unit into one amount
    let amount =
        I128Sum::from_nonnegative(asset_type, denom.denominate(&val) as i128)
            .expect("invalid value or asset type for amount");
    (asset_type, amount)
}

impl<'a, DB, H, CA> NativeVp for MaspVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        tx_data: &Tx,
        _keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let epoch = self.ctx.get_block_epoch()?;
        let (transfer, shielded_tx) = self.ctx.get_shielded_action(tx_data)?;
        let mut transparent_tx_pool = I128Sum::zero();
        // The Sapling value balance adds to the transparent tx pool
        transparent_tx_pool += shielded_tx.sapling_value_balance();

        if transfer.source != Address::Internal(Masp) {
            // Handle transparent input
            // Note that the asset type is timestamped so shields
            // where the shielded value has an incorrect timestamp
            // are automatically rejected
            for denom in token::MaspDenom::iter() {
                let (_transp_asset, transp_amt) = convert_amount(
                    epoch,
                    &transfer.token,
                    transfer.amount.into(),
                    denom,
                );

                // Non-masp sources add to transparent tx pool
                transparent_tx_pool += transp_amt;
            }
        } else {
            // Handle shielded input
            // The following boundary conditions must be satisfied
            // 1. Zero transparent input
            // 2. the transparent transaction value pool's amount must equal
            // the containing wrapper transaction's fee
            // amount Satisfies 1.
            if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
                if !transp_bundle.vin.is_empty() {
                    tracing::debug!(
                        "Transparent input to a transaction from the masp \
                         must be 0 but is {}",
                        transp_bundle.vin.len()
                    );
                    return Ok(false);
                }
            }
        }

        if transfer.target != Address::Internal(Masp) {
            // Handle transparent output
            // The following boundary conditions must be satisfied
            // 1. One to 4 transparent outputs
            // 2. Asset type must be properly derived
            // 3. Value from the output must be the same as the containing
            // transfer
            // 4. Public key must be the hash of the target

            // Satisfies 1.
            let transp_bundle =
                shielded_tx.transparent_bundle().ok_or_err_msg(
                    "Expected transparent outputs in unshielding transaction",
                )?;

            let out_length = transp_bundle.vout.len();
            if !(1..=4).contains(&out_length) {
                tracing::debug!(
                    "Transparent output to a transaction to the masp must be \
                     between 1 and 4 but is {}",
                    transp_bundle.vout.len()
                );

                return Ok(false);
            }
            let mut outs = transp_bundle.vout.iter();
            let mut valid_count = 0;
            for denom in token::MaspDenom::iter() {
                let out = match outs.next() {
                    Some(out) => out,
                    None => continue,
                };

                let expected_asset_type: AssetType =
                    asset_type_from_epoched_address(
                        epoch,
                        &transfer.token,
                        denom,
                    );

                // Satisfies 2. and 3.
                if !valid_asset_type(&expected_asset_type, &out.asset_type) {
                    // we don't know which masp denoms are necessary
                    // apriori. This is encoded via
                    // the asset types.
                    continue;
                }
                if !valid_transfer_amount(
                    out.value,
                    denom.denominate(&transfer.amount.amount),
                ) {
                    return Ok(false);
                }

                let (_transp_asset, transp_amt) = convert_amount(
                    epoch,
                    &transfer.token,
                    transfer.amount.amount,
                    denom,
                );

                // Non-masp destinations subtract from transparent tx pool
                transparent_tx_pool -= transp_amt;

                // Satisfies 4.
                let target_enc = transfer.target.serialize_to_vec();

                let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                    &target_enc,
                ));

                if <[u8; 20]>::from(hash) != out.address.0 {
                    tracing::debug!(
                        "the public key of the output account does not match \
                         the transfer target"
                    );
                    return Ok(false);
                }
                valid_count += 1;
            }
            // one or more of the denoms in the batch failed to verify
            // the asset derivation.
            if valid_count != out_length {
                return Ok(false);
            }
        } else {
            // Handle shielded output
            // The following boundary conditions must be satisfied
            // 1. Zero transparent output

            // Satisfies 1.
            if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
                if !transp_bundle.vout.is_empty() {
                    tracing::debug!(
                        "Transparent output to a transaction from the masp \
                         must be 0 but is {}",
                        transp_bundle.vout.len()
                    );
                    return Ok(false);
                }
            }
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
