use std::cmp::Ordering;

use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::I128Sum;
/// Multi-asset shielded pool VP.
use namada_vp_prelude::address::masp;
use namada_vp_prelude::borsh_ext::BorshSerializeExt;
use namada_vp_prelude::storage::Epoch;
use namada_vp_prelude::*;
use ripemd::{Digest, Ripemd160};

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
        debug_log!(
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
        debug_log!(
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

#[validity_predicate(gas = 8030000)]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Tx,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "vp_masp called with {} bytes data, address {}, keys_changed {:?}, \
         verifiers {:?}",
        tx_data.data().as_ref().map(|x| x.len()).unwrap_or(0),
        addr,
        keys_changed,
        verifiers,
    );

    let signed = tx_data;
    let transfer =
        token::Transfer::try_from_slice(&signed.data().unwrap()[..]).unwrap();

    let shielded = transfer
        .shielded
        .as_ref()
        .map(|hash| {
            signed
                .get_section(hash)
                .and_then(|x| x.as_ref().masp_tx())
                .ok_or_err_msg("unable to find shielded section")
        })
        .transpose()?;
    if let Some(shielded_tx) = shielded {
        let mut transparent_tx_pool = I128Sum::zero();
        // The Sapling value balance adds to the transparent tx pool
        transparent_tx_pool += shielded_tx.sapling_value_balance();

        if transfer.source != masp() {
            // Handle transparent input
            // Note that the asset type is timestamped so shields
            // where the shielded value has an incorrect timestamp
            // are automatically rejected
            for denom in token::MaspDenom::iter() {
                let (_transp_asset, transp_amt) = convert_amount(
                    ctx.get_block_epoch().unwrap(),
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
            // 2. the transparent transaction value pool's amount must equal the
            // containing wrapper transaction's fee amount
            // Satisfies 1.
            if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
                if !transp_bundle.vin.is_empty() {
                    debug_log!(
                        "Transparent input to a transaction from the masp \
                         must be 0 but is {}",
                        transp_bundle.vin.len()
                    );
                    return reject();
                }
            }
        }

        if transfer.target != masp() {
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
                debug_log!(
                    "Transparent output to a transaction to the masp must be \
                     beteween 1 and 4 but is {}",
                    transp_bundle.vout.len()
                );

                return reject();
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
                        ctx.get_block_epoch().unwrap(),
                        &transfer.token,
                        denom,
                    );

                // Satisfies 2. and 3.
                if !valid_asset_type(&expected_asset_type, &out.asset_type) {
                    // we don't know which masp denoms are necessary apriori.
                    // This is encoded via the asset types.
                    continue;
                }
                if !valid_transfer_amount(
                    out.value,
                    denom.denominate(&transfer.amount.amount),
                ) {
                    return reject();
                }

                let (_transp_asset, transp_amt) = convert_amount(
                    ctx.get_block_epoch().unwrap(),
                    &transfer.token,
                    transfer.amount.amount,
                    denom,
                );

                // Non-masp destinations subtract from transparent tx pool
                transparent_tx_pool -= transp_amt;

                // Satisfies 4.
                let target_enc = transfer.target.serialize_to_vec();

                let hash = Ripemd160::digest(sha256(&target_enc).0.as_slice());

                if <[u8; 20]>::from(hash) != out.address.0 {
                    debug_log!(
                        "the public key of the output account does not match \
                         the transfer target"
                    );
                    return reject();
                }
                valid_count += 1;
            }
            // one or more of the denoms in the batch failed to verify
            // the asset derivation.
            if valid_count != out_length {
                return reject();
            }
        } else {
            // Handle shielded output
            // The following boundary conditions must be satisfied
            // 1. Zero transparent output

            // Satisfies 1.
            if let Some(transp_bundle) = shielded_tx.transparent_bundle() {
                if !transp_bundle.vout.is_empty() {
                    debug_log!(
                        "Transparent output to a transaction from the masp \
                         must be 0 but is {}",
                        transp_bundle.vout.len()
                    );
                    return reject();
                }
            }
        }

        match transparent_tx_pool.partial_cmp(&I128Sum::zero()) {
            None | Some(Ordering::Less) => {
                debug_log!(
                    "Transparent transaction value pool must be nonnegative. \
                     Violation may be caused by transaction being constructed \
                     in previous epoch. Maybe try again."
                );
                // Section 3.4: The remaining value in the transparent
                // transaction value pool MUST be nonnegative.
                return reject();
            }
            Some(Ordering::Greater) => {
                debug_log!(
                    "Transaction fees cannot be paid inside MASP transaction."
                );
                return reject();
            }
            _ => {}
        }
        // Do the expensive proof verification in the VM at the end.
        ctx.verify_masp(shielded_tx.serialize_to_vec())
    } else {
        reject()
    }
}
