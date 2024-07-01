//! Helpers for use in multitoken tests.
use std::path::PathBuf;
use std::str::FromStr;

use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use eyre::Context;
use namada_core::address::Address;
use namada_core::{storage, token};
use namada_test_utils::tx_data::TxWriteData;
use namada_test_utils::TestWasms;
use namada_tx_prelude::storage::KeySeg;
use rand::Rng;
use regex::Regex;

use super::setup::constants::NAM;
use super::setup::{Bin, NamadaCmd, Test};
use crate::e2e::setup::constants::ALBERT;
use crate::run;
use crate::strings::{TX_ACCEPTED, TX_APPLIED_SUCCESS};

const MULTITOKEN_KEY_SEGMENT: &str = "tokens";
const BALANCE_KEY_SEGMENT: &str = "balance";
const RED_TOKEN_KEY_SEGMENT: &str = "red";
const MULTITOKEN_RED_TOKEN_SUB_PREFIX: &str = "tokens/red";

const ARBITRARY_SIGNER: &str = ALBERT;

/// Initializes a VP to represent a multitoken account.
pub fn init_multitoken_vp(test: &Test, rpc_addr: &str) -> Result<String> {
    // we use a VP that always returns true for the multitoken VP here, as we
    // are testing out the VPs of the sender and receiver of multitoken
    // transactions here - not any multitoken VP itself
    let multitoken_vp_wasm_path =
        TestWasms::VpAlwaysTrue.path().to_string_lossy().to_string();
    let multitoken_alias = "multitoken";

    let init_account_args = vec![
        "init-account",
        "--source",
        ARBITRARY_SIGNER,
        "--public-key",
        // Value obtained from
        // `namada_sdk::key::ed25519::tests::gen_keypair`
        "001be519a321e29020fa3cbfbfd01bd5e92db134305609270b71dace25b5a21168",
        "--code-path",
        &multitoken_vp_wasm_path,
        "--alias",
        multitoken_alias,
        "--gas-limit",
        "100",
        "--fee-token",
        NAM,
        "--ledger-address",
        rpc_addr,
    ];
    let mut cmd = run!(test, Bin::Client, init_account_args, Some(40))?;
    cmd.exp_string(TX_ACCEPTED)?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();
    Ok(multitoken_alias.to_string())
}

/// Generates a random path within the `test` directory.
fn generate_random_test_dir_path(test: &Test) -> PathBuf {
    let rng = rand::thread_rng();
    let random_string: String = rng
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    test.test_dir.path().join(random_string)
}

/// Writes `contents` to a random path within the `test` directory, and return
/// the path.
pub fn write_test_file(
    test: &Test,
    contents: impl AsRef<[u8]>,
) -> Result<PathBuf> {
    let path = generate_random_test_dir_path(test);
    std::fs::write(&path, contents)?;
    Ok(path)
}

/// Mint red tokens to the given address.
pub fn mint_red_tokens(
    test: &Test,
    rpc_addr: &str,
    multitoken: &Address,
    owner: &Address,
    amount: &token::Amount,
) -> Result<()> {
    let red_balance_key = storage::Key::from(multitoken.to_db_key())
        .push(&MULTITOKEN_KEY_SEGMENT.to_owned())?
        .push(&RED_TOKEN_KEY_SEGMENT.to_owned())?
        .push(&BALANCE_KEY_SEGMENT.to_owned())?
        .push(owner)?;

    let tx_code_path = TestWasms::TxWriteStorageKey.path();
    let tx_data_path = write_test_file(
        test,
        TxWriteData {
            key: red_balance_key,
            value: amount.serialize_to_vec()?,
        }
        .serialize_to_vec()?,
    )?;

    let tx_data_path = tx_data_path.to_string_lossy().to_string();
    let tx_code_path = tx_code_path.to_string_lossy().to_string();
    let tx_args = vec![
        "tx",
        "--signer",
        ARBITRARY_SIGNER,
        "--code-path",
        &tx_code_path,
        "--data-path",
        &tx_data_path,
        "--ledger-address",
        rpc_addr,
    ];
    let mut cmd = run!(test, Bin::Client, tx_args, Some(40))?;
    cmd.exp_string(TX_ACCEPTED)?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();
    Ok(())
}

pub fn attempt_red_tokens_transfer(
    test: &Test,
    rpc_addr: &str,
    multitoken: &str,
    from: &str,
    to: &str,
    signer: &str,
    amount: &token::Amount,
) -> Result<NamadaCmd> {
    let amount = amount.to_string();
    let transfer_args = vec![
        "transfer",
        "--token",
        multitoken,
        "--sub-prefix",
        MULTITOKEN_RED_TOKEN_SUB_PREFIX,
        "--source",
        from,
        "--target",
        to,
        "--signer",
        signer,
        "--amount",
        &amount,
        "--gas-limit",
        "100",
        "--ledger-address",
        rpc_addr,
    ];
    run!(test, Bin::Client, transfer_args, Some(40))
}

pub fn fetch_red_token_balance(
    test: &Test,
    rpc_addr: &str,
    multitoken_alias: &str,
    owner_alias: &str,
) -> Result<token::Amount> {
    let balance_args = vec![
        "balance",
        "--owner",
        owner_alias,
        "--token",
        multitoken_alias,
        "--sub-prefix",
        MULTITOKEN_RED_TOKEN_SUB_PREFIX,
        "--ledger-address",
        rpc_addr,
    ];
    let mut client_balance = run!(test, Bin::Client, balance_args, Some(40))?;
    let (_, matched) = client_balance.exp_regex(&format!(
        r"{MULTITOKEN_RED_TOKEN_SUB_PREFIX}: (\d*\.?\d+)"
    ))?;
    let decimal_regex = Regex::new(r"(\d*\.?\d+)").unwrap();
    println!("Got balance for {}: {}", owner_alias, matched);
    let decimal = decimal_regex.find(&matched).unwrap().as_str();
    client_balance.assert_success();
    token::Amount::from_str(decimal)
        .wrap_err(format!("Failed to parse {}", matched))
}
