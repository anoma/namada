//! MASP verification wrappers.

use std::env;
use std::fs::File;
use std::ops::Deref;
use std::path::PathBuf;

use bellman::groth16::{prepare_verifying_key, PreparedVerifyingKey};
use bls12_381::Bls12;
use masp_primitives::asset_type::AssetType;
use masp_primitives::consensus::BranchId::Sapling;
use masp_primitives::redjubjub::PublicKey;
use masp_primitives::transaction::components::{
    ConvertDescription, OutputDescription, SpendDescription,
};
use masp_primitives::transaction::{
    signature_hash_data, Transaction, SIGHASH_ALL,
};
use masp_proofs::sapling::SaplingVerificationContext;

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "ANOMA_MASP_PARAMS_DIR";

// TODO these could be exported from masp_proof crate
// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

/// Load Sapling spend params.
pub fn load_spend_params() -> (
    bellman::groth16::Parameters<Bls12>,
    bellman::groth16::PreparedVerifyingKey<Bls12>,
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
    let params = bellman::groth16::Parameters::read(&param_f, false).unwrap();
    let vk = prepare_verifying_key(&params.vk);
    (params, vk)
}

/// Load Sapling convert params.
pub fn load_convert_params() -> (
    bellman::groth16::Parameters<Bls12>,
    bellman::groth16::PreparedVerifyingKey<Bls12>,
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
    let params = bellman::groth16::Parameters::read(&param_f, false).unwrap();
    let vk = prepare_verifying_key(&params.vk);
    (params, vk)
}

/// Load Sapling output params.
pub fn load_output_params() -> (
    bellman::groth16::Parameters<Bls12>,
    bellman::groth16::PreparedVerifyingKey<Bls12>,
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
    let params = bellman::groth16::Parameters::read(&param_f, false).unwrap();
    let vk = prepare_verifying_key(&params.vk);
    (params, vk)
}

/// check_spend wrapper
pub fn check_spend(
    spend: &SpendDescription,
    sighash: &[u8; 32],
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        bellman::groth16::Proof::read(spend.zkproof.as_slice()).unwrap();
    ctx.check_spend(
        spend.cv,
        spend.anchor,
        &spend.nullifier,
        // TODO: should make this clone, or just use an ExtendedPoint?
        PublicKey(spend.rk.0.clone()),
        sighash,
        spend.spend_auth_sig.unwrap(),
        zkproof,
        parameters,
    )
}

/// check_output wrapper
pub fn check_output(
    output: &OutputDescription,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        bellman::groth16::Proof::read(output.zkproof.as_slice()).unwrap();
    ctx.check_output(
        output.cv,
        output.cmu,
        output.ephemeral_key,
        zkproof,
        parameters,
    )
}

/// check convert wrapper
pub fn check_convert(
    convert: &ConvertDescription,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        bellman::groth16::Proof::read(convert.zkproof.as_slice()).unwrap();
    ctx.check_convert(convert.cv, convert.anchor, zkproof, parameters)
}

/// Verify a shielded transaction.
pub fn verify_shielded_tx(transaction: &Transaction) -> bool {
    tracing::info!("entered verify_shielded_tx()");

    let mut ctx = SaplingVerificationContext::new();
    let tx_data = transaction.deref();

    let (_, spend_pvk) = load_spend_params();
    let (_, convert_pvk) = load_convert_params();
    let (_, output_pvk) = load_output_params();

    let sighash: [u8; 32] =
        signature_hash_data(&tx_data, Sapling, SIGHASH_ALL, None)
            .try_into()
            .unwrap();

    tracing::info!("sighash computed");

    let spends_valid = tx_data
        .shielded_spends
        .iter()
        .all(|spend| check_spend(spend, &sighash, &mut ctx, &spend_pvk));
    let converts_valid = tx_data
        .shielded_converts
        .iter()
        .all(|convert| check_convert(convert, &mut ctx, &convert_pvk));
    let outputs_valid = tx_data
        .shielded_outputs
        .iter()
        .all(|output| check_output(output, &mut ctx, &output_pvk));

    if !(spends_valid && outputs_valid && converts_valid) {
        return false;
    }

    tracing::info!("passed spend/output verification");

    let assets_and_values: Vec<(AssetType, i64)> =
        tx_data.value_balance.clone().into_components().collect();

    tracing::info!("accumulated {} assets/values", assets_and_values.len());

    ctx.final_check(
        assets_and_values.as_slice(),
        &sighash,
        tx_data.binding_sig.unwrap(),
    )
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
