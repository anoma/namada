use std::cmp::Ordering;

use masp_primitives::asset_type::AssetType;
use masp_primitives::legacy::TransparentAddress::{PublicKey, Script};
use masp_primitives::transaction::components::{Amount, TxOut};
/// Multi-asset shielded pool VP.
use namada_vp_prelude::address::masp;
use namada_vp_prelude::storage::Epoch;
use namada_vp_prelude::*;
use ripemd160::{Digest, Ripemd160};

/// Generates the current asset type given the current epoch and an
/// unique token address
fn asset_type_from_epoched_address(epoch: Epoch, token: &Address) -> AssetType {
    // Timestamp the chosen token with the current epoch
    let token_bytes = (token, epoch.0)
        .try_to_vec()
        .expect("token should serialize");
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
        )
    }
    res
}

/// Convert Namada amount and token type to MASP equivalents
fn convert_amount(
    epoch: Epoch,
    token: &Address,
    val: token::Amount,
) -> (AssetType, Amount) {
    let asset_type = asset_type_from_epoched_address(epoch, token);
    // Combine the value and unit into one amount
    let amount = Amount::from_nonnegative(asset_type, u64::from(val))
        .expect("invalid value or asset type for amount");
    (asset_type, amount)
}

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Vec<u8>,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "vp_masp called with {} bytes data, address {}, keys_changed {:?}, \
         verifiers {:?}",
        tx_data.len(),
        addr,
        keys_changed,
        verifiers,
    );

    let signed = SignedTxData::try_from_slice(&tx_data[..]).unwrap();
    // Also get the data as bytes for the VM.
    let data = signed.data.as_ref().unwrap().clone();
    let transfer =
        token::Transfer::try_from_slice(&signed.data.unwrap()[..]).unwrap();

    if let Some(shielded_tx) = transfer.shielded {
        let mut transparent_tx_pool = Amount::zero();
        // The Sapling value balance adds to the transparent tx pool
        transparent_tx_pool += shielded_tx.value_balance.clone();

        if transfer.source != masp() {
            // Handle transparent input
            // Note that the asset type is timestamped so shields
            // where the shielded value has an incorrect timestamp
            // are automatically rejected
            let (_transp_asset, transp_amt) = convert_amount(
                ctx.get_block_epoch().unwrap(),
                &transfer.token,
                transfer.amount,
            );

            // Non-masp sources add to transparent tx pool
            transparent_tx_pool += transp_amt;
        } else {
            // Handle shielded input
            // The following boundary conditions must be satisfied
            // 1. Zero transparent inupt
            // 2. the transparent transaction value pool's amount must equal the
            // containing wrapper transaction's fee amount
            // Satisfies 1.
            if shielded_tx.vin.len() != 0 {
                debug_log!(
                    "Transparent input to a transaction from the masp must be \
                     0 but is {}",
                    shielded_tx.vin.len()
                );
                return reject();
            }
        }

        if transfer.target != masp() {
            // Handle transparent output
            // The following boundary conditions must be satisfied
            // 1. One transparent output
            // 2. Asset type must be properly derived
            // 3. Value from the output must be the same as the containing transfer
            // 4. Public key must be the hash of the target
            // Satisfies 1.
            if shielded_tx.vout.len() != 1 {
                debug_log!(
                    "Transparent output to a transaction to the masp must be \
                     1 but is {}",
                    shielded_tx.vin.len()
                );
                return reject();
            }

            let out: &TxOut = &shielded_tx.vout[0];

            let expected_asset_type: AssetType =
                asset_type_from_epoched_address(
                    ctx.get_block_epoch().unwrap(),
                    &transfer.token,
                );

            // Satisfies 2. and 3.
            if !(valid_asset_type(&expected_asset_type, &out.asset_type)
                && valid_transfer_amount(out.value, u64::from(transfer.amount)))
            {
                return reject();
            }

            let (_transp_asset, transp_amt) = convert_amount(
                ctx.get_block_epoch().unwrap(),
                &transfer.token,
                transfer.amount,
            );

            // Non-masp destinations subtract from transparent tx pool
            transparent_tx_pool -= transp_amt;

            // Satisfies 4.
            match out.script_pubkey.address() {
                None | Some(Script(_)) => {}
                Some(PublicKey(pub_bytes)) => {
                    let target_enc = transfer
                        .target
                        .try_to_vec()
                        .expect("target address encoding");

                    let hash =
                        Ripemd160::digest(sha256(&target_enc).as_slice());

                    if <[u8; 20]>::from(hash) != pub_bytes {
                        debug_log!(
                            "the public key of the output account does not \
                             match the transfer target"
                        );
                        return reject();
                    }
                }
            }
        } else {
            // Handle shielded output
            // The following boundary conditions must be satisfied
            // 1. Zero transparent output
            // Satisfies 1.
            if !shielded_tx.vout.is_empty() {
                debug_log!(
                    "Transparent output to a transaction from the masp must \
                     be 0 but is {}",
                    shielded_tx.vin.len()
                );
                return reject();
            }
        }

        match transparent_tx_pool.partial_cmp(&Amount::zero()) {
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
            _ => {}
        }
    }

    // Do the expensive proof verification in the VM at the end.
    ctx.verify_masp(data)
}
