//! MASP verification wrappers.

use std::env;
use std::fs::File;
use std::ops::Deref;
use std::path::PathBuf;

use masp_proofs::bellman::groth16::{prepare_verifying_key, PreparedVerifyingKey};
use masp_proofs::bls12_381::Bls12;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::{
    ConvertDescription, OutputDescription, SpendDescription,
};
use masp_primitives::transaction::{
    Transaction, TransactionData,
};
use masp_proofs::sapling::SaplingVerificationContext;
use masp_primitives::transaction::Authorization;
use masp_primitives::transaction::Authorized;
use masp_primitives::transaction::components::Amount;
use masp_primitives::group::GroupEncoding;
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::transaction::sighash::{SignableInput, signature_hash};
use masp_primitives::transaction::components::transparent::Bundle;
use masp_primitives::transaction::Unauthorized;
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::components::TxOut;
use masp_primitives::transaction::TransparentAddress;
use masp_primitives::sapling::redjubjub::PublicKey;
use sha2::Digest as Sha2Digest;
use ripemd::Digest as RipemdDigest;

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

// TODO these could be exported from masp_proof crate
/// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
/// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
/// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

/// Load Sapling spend params.
pub fn load_spend_params() -> (
    masp_proofs::bellman::groth16::Parameters<Bls12>,
    masp_proofs::bellman::groth16::PreparedVerifyingKey<Bls12>,
) {
    let params_dir = get_params_dir();
    let spend_path = params_dir.join(SPEND_NAME);
    if !spend_path.exists() {
        #[cfg(feature = "masp_proofs/download-params")]
        masp_proofs::download_parameters()
            .expect("MASP parameters not present or downloadable");
        #[cfg(not(feature = "masp_proofs/download-params"))]
        panic!("MASP parameters not present or downloadable");
    }
    let param_f = File::open(spend_path).unwrap();
    let params = masp_proofs::bellman::groth16::Parameters::read(&param_f, false).unwrap();
    let vk = prepare_verifying_key(&params.vk);
    (params, vk)
}

/// Load Sapling convert params.
pub fn load_convert_params() -> (
    masp_proofs::bellman::groth16::Parameters<Bls12>,
    masp_proofs::bellman::groth16::PreparedVerifyingKey<Bls12>,
) {
    let params_dir = get_params_dir();
    let spend_path = params_dir.join(CONVERT_NAME);
    if !spend_path.exists() {
        #[cfg(feature = "masp_proofs/download-params")]
        masp_proofs::download_parameters()
            .expect("MASP parameters not present or downloadable");
        #[cfg(not(feature = "masp_proofs/download-params"))]
        panic!("MASP parameters not present or downloadable");
    }
    let param_f = File::open(spend_path).unwrap();
    let params = masp_proofs::bellman::groth16::Parameters::read(&param_f, false).unwrap();
    let vk = prepare_verifying_key(&params.vk);
    (params, vk)
}

/// Load Sapling output params.
pub fn load_output_params() -> (
    masp_proofs::bellman::groth16::Parameters<Bls12>,
    masp_proofs::bellman::groth16::PreparedVerifyingKey<Bls12>,
) {
    let params_dir = get_params_dir();
    let output_path = params_dir.join(OUTPUT_NAME);
    if !output_path.exists() {
        #[cfg(feature = "masp_proofs/download-params")]
        masp_proofs::download_parameters()
            .expect("MASP parameters not present or downloadable");
        #[cfg(not(feature = "masp_proofs/download-params"))]
        panic!("MASP parameters not present or downloadable");
    }
    let param_f = File::open(output_path).unwrap();
    let params = masp_proofs::bellman::groth16::Parameters::read(&param_f, false).unwrap();
    let vk = prepare_verifying_key(&params.vk);
    (params, vk)
}

/// check_spend wrapper
pub fn check_spend(
    spend: &SpendDescription<<Authorized as Authorization>::SaplingAuth>,
    sighash: &[u8; 32],
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(spend.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    ctx.check_spend(
        spend.cv,
        spend.anchor,
        &spend.nullifier.0,
        PublicKey(spend.rk.0),
        sighash,
        spend.spend_auth_sig,
        zkproof,
        parameters,
    )
}

/// check_output wrapper
pub fn check_output(
    output: &OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(output.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    let epk = masp_proofs::jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key.0);
    let epk = match epk.into() {
        Some(p) => p,
        None => return false,
    };
    ctx.check_output(
        output.cv,
        output.cmu,
        epk,
        zkproof,
        parameters,
    )
}

/// check convert wrapper
pub fn check_convert(
    convert: &ConvertDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(convert.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    ctx.check_convert(convert.cv, convert.anchor, zkproof, parameters)
}

/// Represents an authorization where the Sapling bundle is authorized and the
/// transparent bundle is unauthorized.
pub struct PartialAuthorized;

impl Authorization for PartialAuthorized {
    type TransparentAuth = <Unauthorized as Authorization>::TransparentAuth;
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
}

/// Partially deauthorize the transparent bundle
fn partial_deauthorize(
    tx_data: &TransactionData<Authorized>
) -> Option<TransactionData<PartialAuthorized>> {
    let transp = tx_data.transparent_bundle().and_then(|x| {
        let mut tb = TransparentBuilder::empty();
        for vin in &x.vin {
            tb.add_input(TxOut {
                asset_type: vin.asset_type,
                value: vin.value,
                address: vin.address,
            }).ok()?;
        }
        for vout in &x.vout {
            tb.add_output(&vout.address, vout.asset_type, vout.value).ok()?;
        }
        tb.build()
    });
    if tx_data.transparent_bundle().is_some() != transp.is_some() {
        return None;
    }
    Some(TransactionData::from_parts(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        transp,
        tx_data.sapling_bundle().cloned(),
    ))
}

/// Verify a shielded transaction.
pub fn verify_shielded_tx(transaction: &Transaction) -> bool {
    tracing::info!("entered verify_shielded_tx()");

    let sapling_bundle = if let Some(bundle) = transaction.sapling_bundle() {
        bundle
    } else {
        return false;
    };
    let tx_data = transaction.deref();

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = match partial_deauthorize(tx_data) {
        Some(tx_data) => tx_data,
        None => return false,
    };

    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    // the commitment being signed is shared across all Sapling inputs; once
    // V4 transactions are deprecated this should just be the txid, but
    // for now we need to continue to compute it here.
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);

    tracing::info!("sighash computed");

    let (_, spend_pvk) = load_spend_params();
    let (_, convert_pvk) = load_convert_params();
    let (_, output_pvk) = load_output_params();

    let mut ctx = SaplingVerificationContext::new(true);
    let spends_valid = sapling_bundle
        .shielded_spends
        .iter()
        .all(|spend| check_spend(spend, &sighash.as_ref(), &mut ctx, &spend_pvk));
    let converts_valid = sapling_bundle
        .shielded_converts
        .iter()
        .all(|convert| check_convert(convert, &mut ctx, &convert_pvk));
    let outputs_valid = sapling_bundle
        .shielded_outputs
        .iter()
        .all(|output| check_output(output, &mut ctx, &output_pvk));

    if !(spends_valid && outputs_valid && converts_valid) {
        return false;
    }

    tracing::info!("passed spend/output verification");

    let assets_and_values: Amount = sapling_bundle.value_balance.clone();

    tracing::info!("accumulated {} assets/values", assets_and_values.components().len());

    let result = ctx.final_check(
        assets_and_values,
        &sighash.as_ref(),
        sapling_bundle.authorization.binding_sig,
    );
    tracing::info!("final check result {result}");
    result
}

/// Get the path to MASP parameters from [`ENV_VAR_MASP_PARAMS_DIR`] env var or
/// use the default.
pub fn get_params_dir() -> PathBuf {
    if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
        println!("Using {} as masp parameter folder.", params_dir);
        PathBuf::from(params_dir)
    } else {
        masp_proofs::default_params_folder().unwrap()
    }
}
