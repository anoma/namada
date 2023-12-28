//! By default, these tests will run in release mode. This can be disabled
//! by setting environment variable `NAMADA_E2E_DEBUG=true`. For debugging,
//! you'll typically also want to set `RUST_BACKTRACE=1`, e.g.:
//!
//! ```ignore,shell
//! NAMADA_E2E_DEBUG=true RUST_BACKTRACE=1 cargo test e2e::ledger_tests -- --test-threads=1 --nocapture
//! ```
//!
//! To keep the temporary files created by a test, use env var
//! `NAMADA_E2E_KEEP_TEMP=true`.
#![allow(clippy::type_complexity)]

use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use borsh_ext::BorshSerializeExt;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use data_encoding::HEXLOWER;
use namada::types::address::Address;
use namada::types::storage::Epoch;
use namada::types::token;
use namada_apps::config::ethereum_bridge;
use namada_apps::config::utils::convert_tm_addr_to_socket_addr;
use namada_apps::facade::tendermint_config::net::Address as TendermintAddress;
use namada_core::ledger::governance::cli::onchain::{
    PgfFunding, PgfFundingTarget, StewardsUpdate,
};
use namada_core::types::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_test_utils::TestWasms;
use namada_vp_prelude::BTreeSet;
use serde_json::json;
use setup::constants::*;
use setup::Test;

use super::helpers::{
    epochs_per_year_from_min_duration, get_established_addr_from_pregenesis,
    get_height, get_pregenesis_wallet, wait_for_block_height,
    wait_for_wasm_pre_compile,
};
use super::setup::{get_all_wasms_hashes, set_ethereum_bridge_mode, NamadaCmd};
use crate::e2e::helpers::{
    epoch_sleep, find_address, find_bonded_stake, get_actor_rpc, get_epoch,
    is_debug_mode, parse_reached_epoch,
};
use crate::e2e::setup::{
    self, allow_duplicate_ips, default_port_offset, set_validators, sleep, Bin,
    Who,
};
use crate::strings::{
    LEDGER_SHUTDOWN, LEDGER_STARTED, NON_VALIDATOR_NODE, TX_ACCEPTED,
    TX_APPLIED_SUCCESS, TX_FAILED, TX_REJECTED, VALIDATOR_NODE,
};
use crate::{run, run_as};

fn start_namada_ledger_node(
    test: &Test,
    idx: Option<u64>,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd> {
    let who = match idx {
        Some(idx) => Who::Validator(idx),
        _ => Who::NonValidator,
    };
    let mut node = run_as!(test, who, Bin::Node, &["ledger"], timeout_sec)?;
    node.exp_string(LEDGER_STARTED)?;
    if let Who::Validator(_) = who {
        node.exp_string(VALIDATOR_NODE)?;
    } else {
        node.exp_string(NON_VALIDATOR_NODE)?;
    }
    Ok(node)
}

fn start_namada_ledger_node_wait_wasm(
    test: &Test,
    idx: Option<u64>,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd> {
    let mut node = start_namada_ledger_node(test, idx, timeout_sec)?;
    wait_for_wasm_pre_compile(&mut node)?;
    Ok(node)
}

/// Test that when we "run-ledger" with all the possible command
/// combinations from fresh state, the node starts-up successfully for both a
/// validator and non-validator user.
#[test]
fn run_ledger() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let cmd_combinations = vec![vec!["ledger"], vec!["ledger", "run"]];

    // Start the ledger as a validator
    for args in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::Validator(0), Bin::Node, args, Some(40))?;
        ledger.exp_string(LEDGER_STARTED)?;
        ledger.exp_string(VALIDATOR_NODE)?;
    }

    // Start the ledger as a non-validator
    for args in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::NonValidator, Bin::Node, args, Some(40))?;
        ledger.exp_string(LEDGER_STARTED)?;
        ledger.exp_string(NON_VALIDATOR_NODE)?;
    }

    Ok(())
}

/// In this test we:
/// 1. Run 2 genesis validator ledger nodes and 1 non-validator node
/// 2. Cross over epoch to check for consensus with multiple nodes
/// 3. Submit a valid token transfer tx
/// 4. Check that all the nodes processed the tx with the same result
#[test]
fn test_node_connectivity_and_consensus() -> Result<()> {
    // Setup 2 genesis validator nodes
    let test = setup::network(
        |genesis, base_dir| {
            setup::set_validators(2, genesis, base_dir, default_port_offset)
        },
        None,
    )?;

    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(1),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run 2 genesis validator ledger nodes and 1 non-validator node
    let bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();
    let bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();
    let _bg_non_validator =
        start_namada_ledger_node_wait_wasm(&test, None, Some(40))?.background();

    // 2. Cross over epoch to check for consensus with multiple nodes
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    let _ = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // 3. Submit a valid token transfer tx
    let tx_args = [
        "transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "10.1",
        "--gas-price",
        "0.00090",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4. Check that all the nodes processed the tx with the same result
    let mut validator_0 = bg_validator_0.foreground();
    let mut validator_1 = bg_validator_1.foreground();
    let expected_result = "successful inner txs: 1";
    // We cannot check this on non-validator node as it might sync without
    // applying the tx itself, but its state should be the same, checked below.
    validator_0.exp_string(expected_result)?;
    validator_1.exp_string(expected_result)?;
    let _bg_validator_0 = validator_0.background();
    let _bg_validator_1 = validator_1.background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));
    let validator_1_rpc = get_actor_rpc(&test, Who::Validator(1));
    let non_validator_rpc = get_actor_rpc(&test, Who::NonValidator);

    // Find the block height on the validator
    let after_tx_height = get_height(&test, &validator_0_rpc)?;

    // Wait for the non-validator to be synced to at least the same height
    wait_for_block_height(&test, &non_validator_rpc, after_tx_height, 10)?;

    let query_balance_args = |ledger_rpc| {
        vec![
            "balance", "--owner", ALBERT, "--token", NAM, "--node", ledger_rpc,
        ]
    };
    for ledger_rpc in &[validator_0_rpc, validator_1_rpc, non_validator_rpc] {
        let mut client =
            run!(test, Bin::Client, query_balance_args(ledger_rpc), Some(40))?;
        client.exp_string("nam: 2000010.1")?;
        client.assert_success();
    }

    Ok(())
}

/// In this test we:
/// 1. Start up the ledger
/// 2. Kill the tendermint process
/// 3. Check that the node detects this
/// 4. Check that the node shuts down
#[test]
fn test_namada_shuts_down_if_tendermint_dies() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let mut ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?;

    // 2. Kill the tendermint node
    sleep(1);
    Command::new("pkill")
        .args(["cometbft"])
        .spawn()
        .expect("Test failed")
        .wait()
        .expect("Test failed");

    // 3. Check that namada detects that the tendermint node is dead
    ledger.exp_string("Tendermint node is no longer running.")?;

    // 4. Check that the ledger node shuts down
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Shut it down
/// 3. Run the ledger again, it should load its previous state
/// 4. Shut it down
/// 5. Reset the ledger's state
/// 6. Run the ledger again, it should start from fresh state
#[test]
fn run_ledger_load_state_and_reset() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    let bg_ledger = ledger.background();
    // Wait for a new epoch
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    epoch_sleep(&test, &validator_one_rpc, 30)?;

    // 2. Shut it down
    let mut ledger = bg_ledger.foreground();
    ledger.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;
    drop(ledger);

    // 3. Run the ledger again, it should load its previous state
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be previous state now
    ledger.exp_string("Last state root hash:")?;

    // 4. Shut it down
    ledger.interrupt()?;
    // Wait for it to stop
    ledger.exp_eof()?;
    drop(ledger);

    // 5. Reset the ledger's state
    let mut session = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "reset"],
        Some(10),
    )?;
    session.exp_eof()?;

    // 6. Run the ledger again, it should start from fresh state
    let mut session = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be no previous state
    session.exp_string("No state could be found")?;

    Ok(())
}

/// In this test we
///   1. Run the ledger node until a pre-configured height,
///      at which point it should suspend.
///   2. Check that we can still query the ledger.
///   3. Check that we can shutdown the ledger normally afterwards.
#[test]
fn suspend_ledger() -> Result<()> {
    let test = setup::single_node_net()?;
    // 1. Run the ledger node
    let mut ledger = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "run-until", "--block-height", "2", "--suspend",],
        Some(40)
    )?;

    ledger.exp_string(LEDGER_STARTED)?;
    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    ledger.exp_string("Reached block height 2, suspending.")?;
    let bg_ledger = ledger.background();

    // 2. Query the ledger
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    let mut client = run!(
        test,
        Bin::Client,
        &["epoch", "--ledger-address", &validator_one_rpc],
        Some(40)
    )?;
    client.exp_string("Last committed epoch: 0")?;

    // 3. Shut it down
    let mut ledger = bg_ledger.foreground();
    ledger.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;
    Ok(())
}

/// Test that if we configure the ledger to
/// halt at a given height, it does indeed halt.
#[test]
fn stop_ledger_at_height() -> Result<()> {
    let test = setup::single_node_net()?;
    // 1. Run the ledger node
    let mut ledger = run_as!(
        test,
        Who::Validator(0),
        Bin::Node,
        &["ledger", "run-until", "--block-height", "2", "--halt",],
        Some(40)
    )?;

    ledger.exp_string(LEDGER_STARTED)?;
    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    ledger.exp_string("Reached block height 2, halting the chain.")?;
    ledger.exp_eof()?;
    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Submit a token transfer tx
/// 3. Submit a transaction to update an account's validity predicate
/// 4. Submit a custom tx
/// 5. Submit a tx to initialize a new account
/// 6. Submit a tx to withdraw from faucet account (requires PoW challenge
///    solution)
/// 7. Query token balance
/// 8. Query the raw bytes of a storage key
#[test]
fn ledger_txs_and_queries() -> Result<()> {
    let test = setup::single_node_net()?;
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    // for a custom tx
    let transfer = token::Transfer {
        source: find_address(&test, BERTHA).unwrap(),
        target: find_address(&test, ALBERT).unwrap(),
        token: find_address(&test, NAM).unwrap(),
        amount: token::DenominatedAmount::new(
            token::Amount::native_whole(10),
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        ),
        key: None,
        shielded: None,
    }
    .serialize_to_vec();
    let tx_data_path = test.test_dir.path().join("tx.data");
    std::fs::write(&tx_data_path, transfer).unwrap();
    let tx_data_path = tx_data_path.to_string_lossy();

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let multisig_account =
        format!("{},{},{}", BERTHA_KEY, ALBERT_KEY, CHRISTEL_KEY);

    let txs_args = vec![
        // 2. Submit a token transfer tx (from an established account)
        vec![
            "transfer",
            "--source",
            BERTHA,
            "--target",
            ALBERT,
            "--token",
            NAM,
            "--amount",
            "10.1",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ],
        // Submit a token transfer tx (from an ed25519 implicit account)
        vec![
            "transfer",
            "--source",
            DAEWON,
            "--target",
            ALBERT,
            "--token",
            NAM,
            "--amount",
            "10.1",
            "--signing-keys",
            DAEWON,
            "--node",
            &validator_one_rpc,
        ],
        // Submit a token transfer tx (from a secp256k1 implicit account)
        vec![
            "transfer",
            "--source",
            ESTER,
            "--target",
            ALBERT,
            "--token",
            NAM,
            "--amount",
            "10.1",
            "--node",
            &validator_one_rpc,
        ],
        // 3. Submit a transaction to update an account's validity
        // predicate
        vec![
            "update-account",
            "--address",
            BERTHA,
            "--code-path",
            VP_USER_WASM,
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ],
        // 4. Submit a custom tx
        vec![
            "tx",
            "--code-path",
            TX_TRANSFER_WASM,
            "--data-path",
            &tx_data_path,
            "--owner",
            BERTHA,
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ],
        // 5. Submit a tx to initialize a new account
        vec![
            "init-account",
            "--public-keys",
            // Value obtained from `namada::types::key::ed25519::tests::gen_keypair`
            "tpknam1qpqfzxu3gt05jx2mvg82f4anf90psqerkwqhjey4zlqv0qfgwuvkzt5jhkp",
            "--threshold",
            "1",
            "--code-path",
            VP_USER_WASM,
            "--alias",
            "Test-Account",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ],
        // 5. Submit a tx to initialize a new multisig account
        vec![
            "init-account",
            "--public-keys",
            &multisig_account,
            "--threshold",
            "2",
            "--code-path",
            VP_USER_WASM,
            "--alias",
            "Test-Account-2",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_one_rpc,
        ],
    ];

    for tx_args in &txs_args {
        for &dry_run in &[true, false] {
            let tx_args = if dry_run && tx_args[0] == "tx" {
                continue;
            } else if dry_run {
                vec![tx_args.clone(), vec!["--dry-run"]].concat()
            } else {
                tx_args.clone()
            };
            let mut client = run!(test, Bin::Client, tx_args, Some(40))?;

            if !dry_run {
                client.exp_string(TX_ACCEPTED)?;
            }
            client.exp_string(TX_APPLIED_SUCCESS)?;
            client.assert_success();
        }
    }

    let query_args_and_expected_response = vec![
        // 7. Query token balance
        (
            vec![
                "balance",
                "--owner",
                BERTHA,
                "--token",
                NAM,
                "--node",
                &validator_one_rpc,
            ],
            // expect a decimal
            vec![r"nam: \d+(\.\d+)?"],
            // check also as validator node
            true,
        ),
        // Unspecified token expect all tokens from wallet derived from genesis
        (
            vec!["balance", "--owner", ALBERT, "--node", &validator_one_rpc],
            // expect all genesis tokens, sorted by alias
            vec![
                r"apfel: \d+(\.\d+)?",
                r"btc: \d+(\.\d+)?",
                r"dot: \d+(\.\d+)?",
                r"eth: \d+(\.\d+)?",
                r"kartoffel: \d+(\.\d+)?",
                r"schnitzel: \d+(\.\d+)?",
            ],
            // check also as validator node
            true,
        ),
        (
            vec![
                "query-account",
                "--owner",
                "Test-Account-2",
                "--node",
                &validator_one_rpc,
            ],
            vec!["Threshold: 2"],
            // check also as validator node
            false,
        ),
    ];
    for (query_args, expected, check_as_validator) in
        &query_args_and_expected_response
    {
        // Run as a non-validator
        let mut client = run!(test, Bin::Client, query_args, Some(40))?;
        for pattern in expected {
            client.exp_regex(pattern)?;
        }
        client.assert_success();

        if !check_as_validator {
            continue;
        }

        // Run as a validator
        let mut client = run_as!(
            test,
            Who::Validator(0),
            Bin::Client,
            query_args,
            Some(40)
        )?;
        for pattern in expected {
            client.exp_regex(pattern)?;
        }
        client.assert_success();
    }
    let christel = find_address(&test, CHRISTEL)?;
    // as setup in `genesis/e2e-tests-single-node.toml`
    let christel_balance = token::Amount::native_whole(2000000);
    let nam = find_address(&test, NAM)?;
    let storage_key = token::balance_key(&nam, &christel).to_string();
    let query_args_and_expected_response = vec![
        // 8. Query storage key and get hex-encoded raw bytes
        (
            vec![
                "query-bytes",
                "--storage-key",
                &storage_key,
                "--node",
                &validator_one_rpc,
            ],
            // expect hex encoded of borsh encoded bytes
            HEXLOWER.encode(&christel_balance.serialize_to_vec()),
        ),
    ];
    for (query_args, expected) in &query_args_and_expected_response {
        let mut client = run!(test, Bin::Client, query_args, Some(40))?;
        client.exp_string(expected)?;

        client.assert_success();
    }

    Ok(())
}

/// Test the optional disposable keypair for wrapper signing
///
/// 1. Test that a tx requesting a disposable signer with a correct unshielding
/// operation is successful
/// 2. Test that a tx requesting a disposable signer
/// providing an insufficient unshielding fails
#[test]
fn wrapper_disposable_signer() -> Result<()> {
    // Download the shielded pool parameters before starting node
    let _ = FsShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(120);
            genesis.parameters.parameters.min_num_of_blocks = 1;
            set_validators(1, genesis, base_dir, default_port_offset)
        },
        None,
    )?;

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let _ep1 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    let tx_args = vec![
        "transfer",
        "--source",
        ALBERT,
        "--target",
        AA_PAYMENT_ADDRESS,
        "--token",
        NAM,
        "--amount",
        "50",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(720))?;

    client.exp_string(TX_ACCEPTED)?;
    client.exp_string(TX_APPLIED_SUCCESS)?;

    let _ep1 = epoch_sleep(&test, &validator_one_rpc, 720)?;
    let tx_args = vec![
        "transfer",
        "--source",
        ALBERT,
        "--target",
        BERTHA,
        "--token",
        NAM,
        "--amount",
        "1",
        "--gas-spending-key",
        A_SPENDING_KEY,
        "--disposable-gas-payer",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(720))?;

    client.exp_string(TX_ACCEPTED)?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    let _ep1 = epoch_sleep(&test, &validator_one_rpc, 720)?;
    let tx_args = vec![
        "transfer",
        "--source",
        ALBERT,
        "--target",
        BERTHA,
        "--token",
        NAM,
        "--amount",
        "1",
        "--gas-price",
        "90000000",
        "--gas-spending-key",
        A_SPENDING_KEY,
        "--disposable-gas-payer",
        "--ledger-address",
        &validator_one_rpc,
        // NOTE: Forcing the transaction will make the client produce a
        // transfer without a masp object attached to it, so don't expect a
        // failure from the masp vp here but from the check_fees function
        "--force",
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(720))?;
    client.exp_string("Error while processing transaction's fees")?;

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Submit an invalid transaction (disallowed by state machine)
/// 3. Shut down the ledger
/// 4. Restart the ledger
/// 5. Submit and invalid transactions (malformed)
#[test]
fn invalid_transactions() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    // 2. Submit a an invalid transaction (trying to transfer tokens should fail
    // in the user's VP due to the wrong signer)
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let tx_args = vec![
        "transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "1",
        "--signing-keys",
        ALBERT_KEY,
        "--node",
        &validator_one_rpc,
        "--force",
    ];

    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_ACCEPTED)?;
    client.exp_string(TX_REJECTED)?;

    client.assert_success();
    let mut ledger = bg_ledger.foreground();
    ledger.exp_string("rejected inner txs: 1")?;

    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    // 3. Shut it down
    ledger.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    ledger.exp_string(LEDGER_SHUTDOWN)?;
    ledger.exp_eof()?;
    drop(ledger);

    // 4. Restart the ledger
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be previous state now
    ledger.exp_string("Last state root hash:")?;
    // Wait for a block by which time the RPC should be ready
    ledger.exp_string("Committed block hash")?;
    let _bg_ledger = ledger.background();

    // we need to wait for the rpc endpoint to start
    sleep(10);

    // 5. Submit an invalid transactions (invalid token address)
    let daewon_lower = DAEWON.to_lowercase();
    let tx_args = vec![
        "transfer",
        "--source",
        DAEWON,
        "--signing-keys",
        &daewon_lower,
        "--target",
        ALBERT,
        "--token",
        BERTHA,
        "--amount",
        "1000000.1",
        // Force to ignore client check that fails on the balance check of the
        // source address
        "--force",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_ACCEPTED)?;
    client.exp_string(TX_FAILED)?;
    client.assert_success();
    Ok(())
}

/// PoS bonding, unbonding and withdrawal tests. In this test we:
///
/// 1. Run the ledger node with shorter epochs for faster progression
/// 2. Submit a self-bond for the first genesis validator
/// 3. Submit a delegation to the first genesis validator
/// 4. Submit a re-delegation from the first to the second genesis validator
/// 5. Submit an unbond of the self-bond
/// 6. Submit an unbond of the delegation from the first validator
/// 7. Submit an unbond of the re-delegation from the second validator
/// 8. Wait for the unbonding epoch
/// 9. Submit a withdrawal of the self-bond
/// 10. Submit a withdrawal of the delegation
/// 11. Submit an withdrawal of the re-delegation
#[test]
fn pos_bonds() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = unbonding_len;
            genesis.parameters.parameters.min_num_of_blocks = 6;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            let mut genesis = setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
            );
            genesis.transactions.bond = Some({
                let wallet = get_pregenesis_wallet(base_dir);
                let validator_1_address = wallet
                    .find_address("validator-1")
                    .expect("Failed to find validator-1 address");
                let mut bonds = genesis.transactions.bond.unwrap();
                bonds
                    .retain(|bond| bond.data.validator != *validator_1_address);
                bonds
            });
            genesis
        },
        None,
    )?;
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 2. Submit a self-bond for the first genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--amount",
        "10000.0",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 3. Submit a delegation to the first genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "5000.0",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4. Submit a re-delegation from the first to the second genesis validator
    let tx_args = vec![
        "redelegate",
        "--source-validator",
        "validator-0",
        "--destination-validator",
        "validator-1",
        "--owner",
        BERTHA,
        "--amount",
        "2500.0",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 5. Submit an unbond of the self-bond
    let tx_args = vec![
        "unbond",
        "--validator",
        "validator-0",
        "--amount",
        "5100.0",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client
        .exp_string("Amount 5100.000000 withdrawable starting from epoch ")?;
    client.assert_success();

    // 6. Submit an unbond of the delegation from the first validator
    let tx_args = vec![
        "unbond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "1600.",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    let expected = "Amount 1600.000000 withdrawable starting from epoch ";
    let _ = client.exp_regex(&format!("{expected}.*\n"))?;
    client.assert_success();

    // 7. Submit an unbond of the re-delegation from the second validator
    let tx_args = vec![
        "unbond",
        "--validator",
        "validator-1",
        "--source",
        BERTHA,
        "--amount",
        "1600.",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    let expected = "Amount 1600.000000 withdrawable starting from epoch ";
    let (_unread, matched) = client.exp_regex(&format!("{expected}.*\n"))?;
    let epoch_raw = matched.trim().split_once(expected).unwrap().1;
    let delegation_withdrawable_epoch = Epoch::from_str(epoch_raw).unwrap();
    client.assert_success();

    // 8. Wait for the delegation withdrawable epoch (the self-bond was unbonded
    // before it)
    let epoch = get_epoch(&test, &validator_0_rpc)?;

    println!(
        "Current epoch: {}, earliest epoch for withdrawal: {}",
        epoch, delegation_withdrawable_epoch
    );
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!(
                "Timed out waiting for epoch: {}",
                delegation_withdrawable_epoch
            );
        }
        let epoch = epoch_sleep(&test, &validator_0_rpc, 40)?;
        if epoch >= delegation_withdrawable_epoch {
            break;
        }
    }

    // 9. Submit a withdrawal of the self-bond
    let tx_args = vec![
        "withdraw",
        "--validator",
        "validator-0",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 10. Submit a withdrawal of the delegation
    let tx_args = vec![
        "withdraw",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 11. Submit an withdrawal of the re-delegation
    let tx_args = vec![
        "withdraw",
        "--validator",
        "validator-1",
        "--source",
        BERTHA,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    Ok(())
}

/// Test for claiming PoS inflationary rewards
///
/// 1. Run the ledger node
/// 2. Wait some epochs while inflationary rewards accumulate in the PoS system
/// 3. Submit a claim-rewards tx
/// 4. Query the validator's balance before and after the claim tx to ensure
/// that reward tokens were actually transferred
#[test]
fn pos_rewards() -> Result<()> {
    let test = setup::network(
        |mut genesis, base_dir| {
            genesis.parameters.parameters.max_expected_time_per_block = 4;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            genesis.parameters.pos_params.pipeline_len = 2;
            genesis.parameters.pos_params.unbonding_len = 4;
            setup::set_validators(1, genesis, base_dir, default_port_offset)
        },
        None,
    )?;

    for i in 0..1 {
        set_ethereum_bridge_mode(
            &test,
            &test.net.chain_id,
            Who::Validator(i),
            ethereum_bridge::ledger::Mode::Off,
            None,
        );
    }

    // 1. Run 3 genesis validator ledger nodes
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // Query the current rewards for the validator self-bond
    let tx_args = vec![
        "rewards",
        "--validator",
        "validator-0",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    let (_, res) = client
        .exp_regex(r"Current rewards available for claim: [0-9\.]+ NAM")
        .unwrap();
    let words = res.split(' ').collect::<Vec<_>>();
    let res = words[words.len() - 2];
    let mut last_amount = token::Amount::from_str(
        res.split(' ').last().unwrap(),
        NATIVE_MAX_DECIMAL_PLACES,
    )
    .unwrap();
    client.assert_success();

    // Wait some epochs
    let mut last_epoch = get_epoch(&test, &validator_0_rpc)?;
    let wait_epoch = last_epoch + 4_u64;

    let start = Instant::now();
    let loop_timeout = Duration::new(40, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!("Timed out waiting for epoch: {}", wait_epoch);
        }

        let epoch = epoch_sleep(&test, &validator_0_rpc, 40)?;
        if dbg!(epoch) >= wait_epoch {
            break;
        }

        // Query the current rewards for the validator self-bond and see that it
        // grows
        let tx_args = vec![
            "rewards",
            "--validator",
            "validator-0",
            "--node",
            &validator_0_rpc,
        ];
        let mut client =
            run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
        let (_, res) = client
            .exp_regex(r"Current rewards available for claim: [0-9\.]+ NAM")
            .unwrap();
        let words = res.split(' ').collect::<Vec<_>>();
        let res = words[words.len() - 2];
        let amount = token::Amount::from_str(
            res.split(' ').last().unwrap(),
            NATIVE_MAX_DECIMAL_PLACES,
        )
        .unwrap();
        client.assert_success();

        if epoch > last_epoch {
            assert!(amount > last_amount);
        } else {
            assert_eq!(amount, last_amount);
        }

        last_amount = amount;
        last_epoch = epoch;
    }

    // Query the balance of the validator account
    let query_balance_args = vec![
        "balance",
        "--owner",
        "validator-0",
        "--token",
        NAM,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, query_balance_args, Some(40))?;
    let (_, res) = client.exp_regex(r"nam: [0-9\.]+").unwrap();
    let amount_pre = token::Amount::from_str(
        res.split(' ').last().unwrap(),
        NATIVE_MAX_DECIMAL_PLACES,
    )
    .unwrap();
    client.assert_success();

    // Claim rewards
    let tx_args = vec![
        "claim-rewards",
        "--validator",
        "validator-0",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Query the validator balance again and check that the balance has grown
    // after claiming
    let query_balance_args = vec![
        "balance",
        "--owner",
        "validator-0",
        "--token",
        NAM,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, query_balance_args, Some(40))?;
    let (_, res) = client.exp_regex(r"nam: [0-9\.]+").unwrap();
    let amount_post = token::Amount::from_str(
        res.split(' ').last().unwrap(),
        NATIVE_MAX_DECIMAL_PLACES,
    )
    .unwrap();
    client.assert_success();

    assert!(amount_post > amount_pre);

    Ok(())
}

/// Test for PoS bonds and unbonds queries.
///
/// 1. Run the ledger node
/// 2. Submit a delegation to the genesis validator
/// 3. Wait for epoch 4
/// 4. Submit another delegation to the genesis validator
/// 5. Submit an unbond of the delegation
/// 6. Wait for epoch 7
/// 7. Check the output of the bonds query
#[test]
fn test_bond_queries() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.min_num_of_blocks = 2;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = unbonding_len;
            setup::set_validators(1, genesis, base_dir, default_port_offset)
        },
        None,
    )?;

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    let validator_alias = "validator-0";

    // 2. Submit a delegation to the genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        validator_alias,
        "--amount",
        "100",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 3. Submit a delegation to the genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "200",
        "--signing-keys",
        BERTHA_KEY,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 3. Wait for epoch 4
    let start = Instant::now();
    let loop_timeout = Duration::new(20, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!("Timed out waiting for epoch: {}", 1);
        }
        let epoch = epoch_sleep(&test, &validator_one_rpc, 40)?;
        if epoch >= Epoch(4) {
            break;
        }
    }

    // 4. Submit another delegation to the genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        validator_alias,
        "--source",
        BERTHA,
        "--amount",
        "300",
        "--signing-keys",
        BERTHA_KEY,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 5. Submit an unbond of the delegation
    let tx_args = vec![
        "unbond",
        "--validator",
        validator_alias,
        "--source",
        BERTHA,
        "--amount",
        "412",
        "--signing-keys",
        BERTHA_KEY,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    let (_, res) = client
        .exp_regex(r"withdrawable starting from epoch [0-9]+")
        .unwrap();
    let withdraw_epoch =
        Epoch::from_str(res.split(' ').last().unwrap()).unwrap();
    client.assert_success();

    // 6. Wait for withdraw_epoch
    loop {
        let epoch = epoch_sleep(&test, &validator_one_rpc, 120)?;
        // NOTE: test passes from epoch ~13 onwards
        if epoch >= withdraw_epoch {
            break;
        }
    }

    // 7. Check the output of the bonds query
    let tx_args = vec!["bonds", "--ledger-address", &validator_one_rpc];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(
        "All bonds total active: 100188.000000\r
All bonds total: 100188.000000\r
All unbonds total active: 412.000000\r
All unbonds total: 412.000000\r
All unbonds total withdrawable: 412.000000\r",
    )?;
    client.assert_success();

    Ok(())
}

/// PoS validator creation test. In this test we:
///
/// 1. Run the ledger node with shorter epochs for faster progression
/// 2. Initialize a new validator account
/// 3. Submit a delegation to the new validator
/// 4. Transfer some NAM to the new validator
/// 5. Submit a self-bond for the new validator
/// 6. Wait for the pipeline epoch
/// 7. Check the new validator's bonded stake
#[test]
fn pos_init_validator() -> Result<()> {
    let pipeline_len = 1;
    let validator_stake = token::Amount::native_whole(100000_u64);
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.min_num_of_blocks = 4;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = 2;
            let genesis = setup::set_validators(
                1,
                genesis,
                base_dir,
                default_port_offset,
            );
            println!("{:?}", genesis.transactions.bond);
            let stake = genesis
                .transactions
                .bond
                .as_ref()
                .unwrap()
                .iter()
                .map(|bond| {
                    bond.data
                        .amount
                        .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                        .unwrap()
                        .amount()
                })
                .sum::<token::Amount>();
            assert_eq!(
                stake, validator_stake,
                "Assuming this stake, we give the same amount to the new \
                 validator to have half of voting power",
            );
            genesis
        },
        None,
    )?;

    // 1. Run a validator and non-validator ledger node
    let mut validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(60))?;
    let mut non_validator =
        start_namada_ledger_node_wait_wasm(&test, None, Some(60))?;

    // Wait for a first block
    validator_0.exp_string("Committed block hash")?;
    let _bg_validator_0 = validator_0.background();
    non_validator.exp_string("Committed block hash")?;
    let bg_non_validator = non_validator.background();

    let non_validator_rpc = get_actor_rpc(&test, Who::NonValidator);

    // 2. Initialize a new validator account with the non-validator node
    let new_validator = "new-validator";
    let _new_validator_key = format!("{}-key", new_validator);
    let tx_args = vec![
        "init-validator",
        "--alias",
        new_validator,
        "--account-keys",
        "bertha-key",
        "--commission-rate",
        "0.05",
        "--max-commission-rate-change",
        "0.01",
        "--email",
        "null@null.net",
        "--signing-keys",
        "bertha-key",
        "--node",
        &non_validator_rpc,
        "--unsafe-dont-encrypt",
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 3. Submit a delegation to the new validator
    //    First, transfer some tokens to the validator's key for fees:
    let tx_args = vec![
        "transfer",
        "--source",
        BERTHA,
        "--target",
        new_validator,
        "--token",
        NAM,
        "--amount",
        "10000.5",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();
    //     Then self-bond the tokens:
    let delegation = 5_u64;
    let delegation_str = &delegation.to_string();
    let tx_args = vec![
        "bond",
        "--validator",
        new_validator,
        "--source",
        BERTHA,
        "--amount",
        delegation_str,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4. Transfer some NAM to the new validator
    let validator_stake_str = &validator_stake.to_string_native();
    let tx_args = vec![
        "transfer",
        "--source",
        BERTHA,
        "--target",
        new_validator,
        "--token",
        NAM,
        "--amount",
        validator_stake_str,
        "--signing-keys",
        BERTHA_KEY,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 5. Submit a self-bond for the new validator
    let tx_args = vec![
        "bond",
        "--validator",
        new_validator,
        "--amount",
        validator_stake_str,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Stop the non-validator node and run it as the new validator
    let mut non_validator = bg_non_validator.foreground();
    non_validator.interrupt()?;
    non_validator.exp_eof()?;

    // it takes a bit before the node is shutdown. We dont want flasky test.
    if is_debug_mode() {
        sleep(10);
    } else {
        sleep(5);
    }

    let loc = format!("{}:{}", std::file!(), std::line!());
    let validator_1_base_dir = test.get_base_dir(Who::NonValidator);
    let mut validator_1 = setup::run_cmd(
        Bin::Node,
        ["ledger"],
        Some(60),
        &test.working_dir,
        validator_1_base_dir,
        loc,
    )?;

    validator_1.exp_string(LEDGER_STARTED)?;
    validator_1.exp_string(VALIDATOR_NODE)?;
    validator_1.exp_string("Committed block hash")?;
    let _bg_validator_1 = validator_1.background();

    // 6. Wait for the pipeline epoch when the validator's bonded stake should
    // be non-zero
    let epoch = get_epoch(&test, &non_validator_rpc)?;
    let earliest_update_epoch = epoch + pipeline_len;
    println!(
        "Current epoch: {}, earliest epoch with updated bonded stake: {}",
        epoch, earliest_update_epoch
    );
    let start = Instant::now();
    let loop_timeout = Duration::new(20, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!("Timed out waiting for epoch: {}", earliest_update_epoch);
        }
        let epoch = epoch_sleep(&test, &non_validator_rpc, 40)?;
        if epoch >= earliest_update_epoch {
            break;
        }
    }

    // 7. Check the new validator's bonded stake
    let bonded_stake =
        find_bonded_stake(&test, new_validator, &non_validator_rpc)?;
    assert_eq!(
        bonded_stake,
        token::Amount::native_whole(delegation) + validator_stake
    );

    Ok(())
}

/// Test that multiple txs submitted in the same block all get the tx result.
///
/// In this test we:
/// 1. Run the ledger node with 10s consensus timeout
/// 2. Spawn threads each submitting token transfer tx
#[test]
fn ledger_many_txs_in_a_block() -> Result<()> {
    let test = Arc::new(setup::network(
        |genesis, base_dir: &_| {
            setup::set_validators(1, genesis, base_dir, |_| 0)
        },
        // Set 10s consensus timeout to have more time to submit txs
        Some("10s"),
    )?);

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = Arc::new(get_actor_rpc(&test, Who::Validator(0)));

    // A token transfer tx args
    let tx_args = Arc::new(vec![
        "transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "1.01",
        "--signing-keys",
        BERTHA_KEY,
        "--node",
    ]);

    // 2. Spawn threads each submitting token transfer tx
    // We collect to run the threads in parallel.
    #[allow(clippy::needless_collect)]
    let tasks: Vec<std::thread::JoinHandle<_>> = (0..4)
        .map(|_| {
            let test = Arc::clone(&test);
            let validator_one_rpc = Arc::clone(&validator_one_rpc);
            let tx_args = Arc::clone(&tx_args);
            std::thread::spawn(move || {
                let mut args = (*tx_args).clone();
                args.push(&*validator_one_rpc);
                let mut client = run!(*test, Bin::Client, args, Some(80))?;
                client.exp_string(TX_ACCEPTED)?;
                client.exp_string(TX_APPLIED_SUCCESS)?;
                client.assert_success();
                let res: Result<()> = Ok(());
                res
            })
        })
        .collect();
    for task in tasks.into_iter() {
        task.join().unwrap()?;
    }
    // Wait to commit a block
    let mut ledger = bg_ledger.foreground();
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Submit a valid proposal
/// 3. Query the proposal
/// 4. Query token balance (submitted funds)
/// 5. Query governance address balance
/// 6. Submit an invalid proposal
/// 7. Check invalid proposal was not accepted
/// 8. Query token balance (funds shall not be submitted)
/// 9. Send a yay vote from a validator
/// 10. Send a yay vote from a normal user
/// 11. Query the proposal and check the result
/// 12. Wait proposal grace and check proposal author funds
/// 13. Check governance address funds are 0
#[test]
fn proposal_submission() -> Result<()> {
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.gov_params.max_proposal_code_size = 600000;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            setup::set_validators(1, genesis, base_dir, |_| 0u16)
        },
        None,
    )?;
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let namadac_help = vec!["--help"];

    let mut client = run!(test, Bin::Client, namadac_help, Some(40))?;
    client.exp_string("Namada client command line interface.")?;
    client.assert_success();

    // 1. Run the ledger node
    let bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 1.1 Delegate some token
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 2. Submit valid proposal
    let albert = find_address(&test, ALBERT)?;
    let valid_proposal_json_path = prepare_proposal_data(
        &test,
        albert,
        TestWasms::TxProposalCode.read_bytes(),
        12,
    );
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--gas-limit",
        "2000000",
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Wait for the proposal to be committed
    let mut ledger = bg_ledger.foreground();
    ledger.exp_string("Committed block hash")?;
    let _bg_ledger = ledger.background();

    // 3. Query the proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "0",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("Proposal Id: 0")?;
    client.assert_success();

    // 4. Query token balance proposal author (submitted funds)
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_balance_args, Some(40))?;
    client.exp_string("nam: 1999500")?;
    client.assert_success();

    // 5. Query token balance governance
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_balance_args, Some(40))?;
    client.exp_string("nam: 500")?;
    client.assert_success();

    // 6. Submit an invalid proposal
    // proposal is invalid due to voting_end_epoch - voting_start_epoch < 3
    let albert = find_address(&test, ALBERT)?;
    let invalid_proposal_json = prepare_proposal_data(
        &test,
        albert,
        TestWasms::TxProposalCode.read_bytes(),
        1,
    );

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        invalid_proposal_json.to_str().unwrap(),
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_regex(
        "Proposal data are invalid: Invalid proposal start epoch: 1 must be \
         greater than current epoch .* and a multiple of 3",
    )?;
    client.assert_failure();

    // 7. Check invalid proposal was not submitted
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "1",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("No proposal found with id: 1")?;
    client.assert_success();

    // 8. Query token balance (funds shall not be submitted)
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_balance_args, Some(40))?;
    client.exp_string("nam: 1999500")?;
    client.assert_success();

    // 9. Send a yay vote from a validator
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 13 {
        sleep(10);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        submit_proposal_vote,
        Some(15)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let submit_proposal_vote_delagator = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "nay",
        "--address",
        BERTHA,
        "--node",
        &validator_one_rpc,
    ];

    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 10. Send a yay vote from a non-validator/non-delegator user
    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        ALBERT,
        "--node",
        &validator_one_rpc,
    ];

    // this is valid because the client filter ALBERT delegation and there are
    // none
    let mut client = run!(test, Bin::Client, submit_proposal_vote, Some(15))?;
    client.exp_string("Voter address must have delegations")?;
    client.assert_failure();

    // 11. Query the proposal and check the result
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 25 {
        sleep(10);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let query_proposal = vec![
        "query-proposal-result",
        "--proposal-id",
        "0",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_proposal, Some(15))?;
    client.exp_string("Proposal Id: 0")?;
    client.exp_string(
        "passed with 100000.000000 yay votes, 900.000000 nay votes and \
         0.000000 abstain votes, total voting power: 100900.000000 threshold \
         was: 67266.666666",
    )?;
    client.assert_success();

    // 12. Wait proposal grace and check proposal author funds
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 < 31 {
        sleep(10);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_balance_args, Some(30))?;
    client.exp_string("nam: 200000")?;
    client.assert_success();

    // 13. Check if governance funds are 0
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, query_balance_args, Some(30))?;
    client.exp_string("nam: 0")?;
    client.assert_success();

    // // 14. Query parameters
    let query_protocol_parameters =
        vec!["query-protocol-parameters", "--node", &validator_one_rpc];

    let mut client =
        run!(test, Bin::Client, query_protocol_parameters, Some(30))?;
    client.exp_regex(".*Min. proposal grace epochs: 9.*")?;
    client.assert_success();

    Ok(())
}

/// Test submission and vote of a PGF proposal
///
/// 1 - Submit two proposals
/// 2 - Check balance
/// 3 - Vote for the accepted proposals
/// 4 - Check one proposal passed and the other one didn't
/// 5 - Check funds
#[test]
fn pgf_governance_proposal() -> Result<()> {
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1);
            genesis.parameters.parameters.max_proposal_bytes =
                Default::default();
            genesis.parameters.parameters.min_num_of_blocks = 4;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            genesis.parameters.pgf_params.stewards =
                BTreeSet::from_iter([get_established_addr_from_pregenesis(
                    "albert-key",
                    base_dir,
                    &genesis,
                )
                .unwrap()]);
            setup::set_validators(1, genesis, base_dir, |_| 0)
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let namadac_help = vec!["--help"];

    let mut client = run!(test, Bin::Client, namadac_help, Some(40))?;
    client.exp_string("Namada client command line interface.")?;
    client.assert_success();

    // Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    // Delegate some token
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 1 - Submit proposal
    let albert = find_address(&test, ALBERT)?;
    let pgf_stewards = StewardsUpdate {
        add: Some(albert.clone()),
        remove: vec![],
    };

    let valid_proposal_json_path =
        prepare_proposal_data(&test, albert, pgf_stewards, 12);
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let submit_proposal_args = vec![
        "init-proposal",
        "--pgf-stewards",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 2 - Query the proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "0",
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("Proposal Id: 0")?;
    client.assert_success();

    // Query token balance proposal author (submitted funds)
    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, query_balance_args, Some(40))?;
    client.exp_string("nam: 1999500")?;
    client.assert_success();

    // Query token balance governance
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, query_balance_args, Some(40))?;
    client.exp_string("nam: 500")?;
    client.assert_success();

    // 3 - Send a yay vote from a validator
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 13 {
        sleep(1);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let albert_address = find_address(&test, ALBERT)?;
    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        "validator-0",
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        submit_proposal_vote,
        Some(15)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Send different yay vote from delegator to check majority on 1/3
    let submit_proposal_vote_delagator = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--address",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ];

    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4 - Query the proposal and check the result is the one voted by the
    // validator (majority)
    epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 25 {
        sleep(1);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let query_proposal = vec![
        "query-proposal-result",
        "--proposal-id",
        "0",
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, query_proposal, Some(15))?;
    client.exp_string("passed")?;
    client.assert_success();

    // 12. Wait proposals grace and check proposal author funds
    while epoch.0 < 31 {
        sleep(2);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let query_balance_args = vec![
        "balance",
        "--owner",
        ALBERT,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, query_balance_args, Some(30))?;
    client.exp_string("nam: 2000000")?;
    client.assert_success();

    // Check if governance funds are 0
    let query_balance_args = vec![
        "balance",
        "--owner",
        GOVERNANCE_ADDRESS,
        "--token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, query_balance_args, Some(30))?;
    client.exp_string("nam: 0")?;
    client.assert_success();

    // 14. Query pgf stewards
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];

    let mut client = run!(test, Bin::Client, query_pgf, Some(30))?;
    client.exp_string("Pgf stewards:")?;
    client.exp_string(&format!("- {}", albert_address))?;
    client.exp_string("Reward distribution:")?;
    client.exp_string(&format!("- 1 to {}", albert_address))?;
    client.exp_string("Pgf fundings: no fundings are currently set.")?;
    client.assert_success();

    // 15 - Submit proposal funding
    let albert = find_address(&test, ALBERT)?;
    let bertha = find_address(&test, BERTHA)?;
    let christel = find_address(&test, CHRISTEL)?;

    let pgf_funding = PgfFunding {
        continuous: vec![PgfFundingTarget {
            amount: token::Amount::from_u64(10),
            address: bertha.clone(),
        }],
        retro: vec![PgfFundingTarget {
            amount: token::Amount::from_u64(5),
            address: christel,
        }],
    };

    let valid_proposal_json_path =
        prepare_proposal_data(&test, albert, pgf_funding, 36);
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let submit_proposal_args = vec![
        "init-proposal",
        "--pgf-funding",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 2 - Query the funding proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "1",
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("Proposal Id: 1")?;
    client.assert_success();

    // 13. Wait proposals grace and check proposal author funds
    while epoch.0 < 55 {
        sleep(2);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    // 14. Query pgf fundings
    let query_pgf = vec!["query-pgf", "--node", &validator_one_rpc];
    let mut client = run!(test, Bin::Client, query_pgf, Some(30))?;
    client.exp_string("Pgf fundings")?;
    client.exp_string(&format!(
        "{} for {}",
        bertha,
        token::Amount::from_u64(10).to_string_native()
    ))?;
    client.assert_success();

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Create an offline proposal
/// 3. Create an offline vote
/// 4. Tally offline
#[test]
fn proposal_offline() -> Result<()> {
    let working_dir = setup::working_dir();
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(1);
            genesis.parameters.parameters.max_proposal_bytes =
                Default::default();
            genesis.parameters.parameters.min_num_of_blocks = 4;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            genesis.parameters.parameters.vp_whitelist =
                Some(get_all_wasms_hashes(&working_dir, Some("vp_")));
            // Enable tx whitelist to test the execution of a
            // non-whitelisted tx by governance
            genesis.parameters.parameters.tx_whitelist =
                Some(get_all_wasms_hashes(&working_dir, Some("tx_")));
            setup::set_validators(1, genesis, base_dir, |_| 0)
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 1.1 Delegate some token
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        ALBERT,
        "--amount",
        "900",
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 2. Create an offline proposal
    let albert = find_address(&test, ALBERT)?;
    let valid_proposal_json = json!(
        {
            "content": {
                "title": "TheTitle",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
                "motivation": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
                "details": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
                "requires": "2"
            },
            "author": albert,
            "tally_epoch": 3_u64,
        }
    );
    let valid_proposal_json_path =
        test.test_dir.path().join("valid_proposal.json");
    generate_proposal_json_file(
        valid_proposal_json_path.as_path(),
        &valid_proposal_json,
    );

    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 3 {
        sleep(1);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    let offline_proposal_args = vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--offline",
        "--signing-keys",
        ALBERT_KEY,
        "--output-folder-path",
        test.test_dir.path().to_str().unwrap(),
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, offline_proposal_args, Some(15))?;
    let (_, matched) = client.exp_regex("Proposal serialized to: .*")?;
    client.assert_success();

    let proposal_path = matched
        .split(':')
        .collect::<Vec<&str>>()
        .get(1)
        .unwrap()
        .trim()
        .to_string();

    // 3. Generate an offline yay vote
    let submit_proposal_vote = vec![
        "vote-proposal",
        "--data-path",
        &proposal_path,
        "--vote",
        "yay",
        "--address",
        ALBERT,
        "--offline",
        "--signing-keys",
        ALBERT_KEY,
        "--output-folder-path",
        test.test_dir.path().to_str().unwrap(),
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, submit_proposal_vote, Some(15))?;
    client.exp_string("Proposal vote serialized to: ")?;
    client.assert_success();

    // 4. Compute offline tally
    let tally_offline = vec![
        "query-proposal-result",
        "--data-path",
        test.test_dir.path().to_str().unwrap(),
        "--offline",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, tally_offline, Some(15))?;
    client.exp_string("Parsed 1 votes")?;
    client.exp_string("rejected with 900.000000 yay votes")?;
    client.assert_success();

    Ok(())
}

fn generate_proposal_json_file(
    proposal_path: &std::path::Path,
    proposal_content: &serde_json::Value,
) {
    let intent_writer = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(proposal_path)
        .unwrap();

    serde_json::to_writer(intent_writer, proposal_content).unwrap();
}

/// In this test we intentionally make a validator node double sign blocks
/// to test that slashing evidence is received and processed by the ledger
/// correctly:
/// 1. Run 2 genesis validator ledger nodes
/// 2. Copy the first genesis validator base-dir
/// 3. Increment its ports and generate new node ID to avoid conflict
/// 4. Run it to get it to double vote and sign blocks
/// 5. Submit a valid token transfer tx to validator 0
/// 6. Wait for double signing evidence
/// 7. Make sure the the first validator can proceed to the next epoch
#[test]
fn double_signing_gets_slashed() -> Result<()> {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use namada::types::key::{self, ed25519, SigScheme};
    use namada_apps::client;
    use namada_apps::config::Config;

    let mut pipeline_len = 0;
    let mut unbonding_len = 0;
    let mut cubic_offset = 0;

    // Setup 2 genesis validator nodes
    let test = setup::network(
        |mut genesis, base_dir| {
            (pipeline_len, unbonding_len, cubic_offset) = (
                genesis.parameters.pos_params.pipeline_len,
                genesis.parameters.pos_params.unbonding_len,
                genesis.parameters.pos_params.cubic_slashing_window_length,
            );
            // Make faster epochs to be more likely to discover boundary issues
            genesis.parameters.parameters.min_num_of_blocks = 2;
            setup::set_validators(4, genesis, base_dir, default_port_offset)
        },
        None,
    )?;

    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(1),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    println!("pipeline_len: {}", pipeline_len);

    // 1. Run 2 genesis validator ledger nodes
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();
    let bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();

    let mut validator_2 =
        run_as!(test, Who::Validator(2), Bin::Node, &["ledger"], Some(40))?;
    validator_2.exp_string(LEDGER_STARTED)?;
    validator_2.exp_string(VALIDATOR_NODE)?;
    let _bg_validator_2 = validator_2.background();

    let mut validator_3 =
        run_as!(test, Who::Validator(3), Bin::Node, &["ledger"], Some(40))?;
    validator_3.exp_string(LEDGER_STARTED)?;
    validator_3.exp_string(VALIDATOR_NODE)?;
    let _bg_validator_3 = validator_3.background();

    // 2. Copy the first genesis validator base-dir
    let validator_0_base_dir = test.get_base_dir(Who::Validator(0));
    let validator_0_base_dir_copy = test
        .test_dir
        .path()
        .join(test.net.chain_id.as_str())
        .join(client::utils::NET_ACCOUNTS_DIR)
        .join("validator-0-copy")
        .join(namada_apps::config::DEFAULT_BASE_DIR);
    fs_extra::dir::copy(
        validator_0_base_dir,
        &validator_0_base_dir_copy,
        &fs_extra::dir::CopyOptions {
            copy_inside: true,
            ..Default::default()
        },
    )
    .unwrap();

    // 3. Increment its ports and generate new node ID to avoid conflict

    // Same as in `genesis/e2e-tests-single-node.toml` for `validator-0`
    let net_address_0 = SocketAddr::from_str("127.0.0.1:27656").unwrap();
    let net_address_port_0 = net_address_0.port();

    let update_config = |ix: u8, mut config: Config| {
        let first_port = net_address_port_0 + 26 * (ix as u16 + 1);
        let p2p_addr =
            convert_tm_addr_to_socket_addr(&config.ledger.cometbft.p2p.laddr)
                .ip()
                .to_string();

        config.ledger.cometbft.p2p.laddr = TendermintAddress::from_str(
            &format!("{}:{}", p2p_addr, first_port),
        )
        .unwrap();
        let rpc_addr =
            convert_tm_addr_to_socket_addr(&config.ledger.cometbft.rpc.laddr)
                .ip()
                .to_string();
        config.ledger.cometbft.rpc.laddr = TendermintAddress::from_str(
            &format!("{}:{}", rpc_addr, first_port + 1),
        )
        .unwrap();
        let proxy_app_addr =
            convert_tm_addr_to_socket_addr(&config.ledger.cometbft.proxy_app)
                .ip()
                .to_string();
        config.ledger.cometbft.proxy_app = TendermintAddress::from_str(
            &format!("{}:{}", proxy_app_addr, first_port + 2),
        )
        .unwrap();
        config
    };

    let validator_0_copy_config = update_config(
        2,
        Config::load(&validator_0_base_dir_copy, &test.net.chain_id, None),
    );
    validator_0_copy_config
        .write(&validator_0_base_dir_copy, &test.net.chain_id, true)
        .unwrap();

    // Generate a new node key
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    let mut rng: ThreadRng = thread_rng();
    let node_sk = ed25519::SigScheme::generate(&mut rng);
    let node_sk = key::common::SecretKey::Ed25519(node_sk);
    let tm_home_dir = validator_0_base_dir_copy
        .join(test.net.chain_id.as_str())
        .join("cometbft");
    let _node_pk =
        client::utils::write_tendermint_node_key(&tm_home_dir, node_sk);

    // 4. Run it to get it to double vote and sign block
    let loc = format!("{}:{}", std::file!(), std::line!());
    // This node will only connect to `validator_1`, so that nodes
    // `validator_0` and `validator_0_copy` should start double signing
    let mut validator_0_copy = setup::run_cmd(
        Bin::Node,
        ["ledger"],
        Some(40),
        &test.working_dir,
        validator_0_base_dir_copy,
        loc,
    )?;
    validator_0_copy.exp_string(LEDGER_STARTED)?;
    validator_0_copy.exp_string(VALIDATOR_NODE)?;
    let _bg_validator_0_copy = validator_0_copy.background();

    // 5. Submit a valid token transfer tx to validator 0
    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));
    let tx_args = [
        "transfer",
        "--source",
        BERTHA,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "10.1",
        "--node",
        &validator_one_rpc,
    ];
    let _client = run!(test, Bin::Client, tx_args, Some(100))?;
    // We don't wait for tx result - sometimes the node may crash before while
    // it's being applied, because the slashed validator will stop voting and
    // rewards calculation then fails with `InsufficientVotes`.

    // 6. Wait for double signing evidence
    let mut validator_1 = bg_validator_1.foreground();
    validator_1.exp_string("Processing evidence")?;

    println!("\nPARSING SLASH MESSAGE\n");
    let (_, res) = validator_1
        .exp_regex(r"Slashing [a-z0-9]+ for Duplicate vote in epoch [0-9]+")
        .unwrap();
    println!("\n{res}\n");
    // Wait to commit a block
    validator_1.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    let bg_validator_1 = validator_1.background();

    let exp_processing_epoch = Epoch::from_str(res.split(' ').last().unwrap())
        .unwrap()
        + unbonding_len
        + cubic_offset
        + 1u64;

    // Query slashes
    let mut client = run!(
        test,
        Bin::Client,
        &["slashes", "--node", &validator_one_rpc],
        Some(40)
    )?;
    client.exp_string("No processed slashes found")?;
    client.exp_string("Enqueued slashes for future processing")?;
    let (_, res) = client
        .exp_regex(r"To be processed in epoch [0-9]+")
        .unwrap();
    let processing_epoch =
        Epoch::from_str(res.split(' ').last().unwrap()).unwrap();

    assert_eq!(processing_epoch, exp_processing_epoch);

    println!("\n{processing_epoch}\n");

    // 6. Wait for processing epoch
    loop {
        let epoch = epoch_sleep(&test, &validator_one_rpc, 240)?;
        println!("\nCurrent epoch: {}", epoch);
        if epoch > processing_epoch {
            break;
        }
    }

    let mut client = run!(
        test,
        Bin::Client,
        &[
            "validator-state",
            "--validator",
            "validator-0",
            "--node",
            &validator_one_rpc
        ],
        Some(40)
    )?;
    let _ = client.exp_regex(r"Validator [a-z0-9]+ is jailed").unwrap();

    let mut client = run!(
        test,
        Bin::Client,
        &["slashes", "--node", &validator_one_rpc],
        Some(40)
    )?;
    client.exp_string("Processed slashes:")?;
    client.exp_string("No enqueued slashes found")?;

    let tx_args = vec![
        "unjail-validator",
        "--validator",
        "validator-0",
        "--node",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // Wait until pipeline epoch to see if the validator is back in consensus
    let cur_epoch = epoch_sleep(&test, &validator_one_rpc, 240)?;
    loop {
        let epoch = epoch_sleep(&test, &validator_one_rpc, 240)?;
        println!("\nCurrent epoch: {}", epoch);
        if epoch > cur_epoch + pipeline_len + 1u64 {
            break;
        }
    }
    let mut client = run!(
        test,
        Bin::Client,
        &[
            "validator-state",
            "--validator",
            "validator-0",
            "--node",
            &validator_one_rpc
        ],
        Some(40)
    )?;
    let _ = client
        .exp_regex(r"Validator [a-z0-9]+ is in the .* set")
        .unwrap();

    // 7. Make sure the the first validator can proceed to the next epoch
    epoch_sleep(&test, &validator_one_rpc, 120)?;

    // Make sure there are no errors
    let mut validator_1 = bg_validator_1.foreground();
    validator_1.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    validator_1.exp_string(LEDGER_SHUTDOWN)?;
    validator_1.assert_success();

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. For some transactions that need signature authorization:
///    2a. Generate a new key for an implicit account.
///    2b. Send some funds to the implicit account.
///    2c. Submit the tx with the implicit account as the source, that
///        requires that the account has revealed its PK. This should be done
///        by the client automatically.
///    2d. Submit same tx again, this time the client shouldn't reveal again.
#[test]
fn implicit_account_reveal_pk() -> Result<()> {
    let test = setup::single_node_net()?;

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    // 2. Some transactions that need signature authorization:
    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));
    let txs_args: Vec<Box<dyn Fn(&str) -> Vec<String>>> = vec![
        // A token transfer tx
        Box::new(|source| {
            [
                "transfer",
                "--source",
                source,
                "--target",
                ALBERT,
                "--token",
                NAM,
                "--amount",
                "10.1",
                "--signing-keys",
                source,
                "--node",
                &validator_0_rpc,
            ]
            .into_iter()
            .map(|x| x.to_owned())
            .collect()
        }),
        // A bond
        Box::new(|source| {
            vec![
                "bond",
                "--validator",
                "validator-0",
                "--source",
                source,
                "--amount",
                "10.1",
                "--signing-keys",
                source,
                "--node",
                &validator_0_rpc,
            ]
            .into_iter()
            .map(|x| x.to_owned())
            .collect()
        }),
        // Submit proposal
        Box::new(|source| {
            // Gen data for proposal tx
            let author = find_address(&test, source).unwrap();
            let valid_proposal_json_path = prepare_proposal_data(
                &test,
                author,
                TestWasms::TxProposalCode.read_bytes(),
                12,
            );
            vec![
                "init-proposal",
                "--data-path",
                valid_proposal_json_path.to_str().unwrap(),
                "--signing-keys",
                source,
                "--gas-limit",
                "2000000",
                "--node",
                &validator_0_rpc,
            ]
            .into_iter()
            .map(|x| x.to_owned())
            .collect()
        }),
    ];

    for (ix, tx_args) in txs_args.into_iter().enumerate() {
        let key_alias = format!("key-{ix}");

        // 2a. Generate a new key for an implicit account.
        let mut cmd = run!(
            test,
            Bin::Wallet,
            &["gen", "--alias", &key_alias, "--unsafe-dont-encrypt"],
            Some(20),
        )?;
        cmd.assert_success();

        // Apply the key_alias once the key is generated to obtain tx args
        let tx_args = tx_args(&key_alias);

        // 2b. Send some funds to the implicit account.
        let credit_args = [
            "transfer",
            "--source",
            BERTHA,
            "--target",
            &key_alias,
            "--token",
            NAM,
            "--amount",
            "1000",
            "--signing-keys",
            BERTHA_KEY,
            "--node",
            &validator_0_rpc,
        ];
        let mut client = run!(test, Bin::Client, credit_args, Some(40))?;
        client.assert_success();

        // 2c. Submit the tx with the implicit account as the source.
        let expected_reveal = "Submitting a tx to reveal the public key";
        let mut client = run!(test, Bin::Client, &tx_args, Some(40))?;
        client.exp_string(expected_reveal)?;
        client.assert_success();

        // 2d. Submit same tx again, this time the client shouldn't reveal
        // again.
        let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
        let unread = client.exp_eof()?;
        assert!(!unread.contains(expected_reveal))
    }

    Ok(())
}

#[test]
fn test_epoch_sleep() -> Result<()> {
    // Use slightly longer epochs to give us time to sleep
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.parameters.epochs_per_year =
                epochs_per_year_from_min_duration(30);
            genesis.parameters.parameters.min_num_of_blocks = 1;
            setup::set_validators(1, genesis, base_dir, |_| 0)
        },
        None,
    )?;

    // 1. Run the ledger node
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    wait_for_wasm_pre_compile(&mut ledger)?;

    let _bg_ledger = ledger.background();

    let validator_one_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 2. Query the current epoch
    let start_epoch = get_epoch(&test, &validator_one_rpc).unwrap();

    // 3. Use epoch-sleep to sleep for an epoch
    let args = ["utils", "epoch-sleep", "--node", &validator_one_rpc];
    let mut client = run!(test, Bin::Client, &args, None)?;
    let reached_epoch = parse_reached_epoch(&mut client)?;
    client.assert_success();

    // 4. Confirm the current epoch is larger
    // possibly badly, we assume we get here within 30 seconds of the last step
    // should be fine haha (future debuggers: sorry)
    let current_epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    assert!(current_epoch > start_epoch);
    assert_eq!(current_epoch, reached_epoch);

    Ok(())
}

/// Prepare proposal data in the test's temp dir from the given source address.
/// This can be submitted with "init-proposal" command.
fn prepare_proposal_data(
    test: &setup::Test,
    source: Address,
    data: impl serde::Serialize,
    start_epoch: u64,
) -> PathBuf {
    let valid_proposal_json = json!({
        "proposal": {
            "content": {
                "title": "TheTitle",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
                "motivation": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
                "details": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
                "requires": "2"
            },
            "author": source,
            "voting_start_epoch": start_epoch,
            "voting_end_epoch": start_epoch + 12_u64,
            "grace_epoch": start_epoch + 12u64 + 6_u64,
        },
        "data": data
    });

    let valid_proposal_json_path =
        test.test_dir.path().join("valid_proposal.json");
    generate_proposal_json_file(
        valid_proposal_json_path.as_path(),
        &valid_proposal_json,
    );
    valid_proposal_json_path
}

#[test]
fn deactivate_and_reactivate_validator() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = unbonding_len;
            // genesis.parameters.parameters.min_num_of_blocks = 6;
            // genesis.parameters.parameters.max_expected_time_per_block = 1;
            // genesis.parameters.parameters.epochs_per_year = 31_536_000;
            let mut genesis = setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
            );
            genesis.transactions.bond = Some({
                let wallet = get_pregenesis_wallet(base_dir);
                let validator_1_address = wallet
                    .find_address("validator-1")
                    .expect("Failed to find validator-1 address");
                let mut bonds = genesis.transactions.bond.unwrap();
                bonds
                    .retain(|bond| bond.data.validator != *validator_1_address);
                bonds
            });
            genesis
        },
        None,
    )?;
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(0));
    allow_duplicate_ips(&test, &test.net.chain_id, Who::Validator(1));
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let _bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();

    let validator_1_rpc = get_actor_rpc(&test, Who::Validator(1));

    // Check the state of validator-1
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is in the below-threshold set")?;
    client.assert_success();

    // Deactivate validator-1
    let tx_args = vec![
        "deactivate-validator",
        "--validator",
        "validator-1",
        "--signing-keys",
        "validator-1-balance-key",
        "--node",
        &validator_1_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(1), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let deactivate_epoch = get_epoch(&test, &validator_1_rpc)?;
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!(
                "Timed out waiting for epoch: {}",
                deactivate_epoch + pipeline_len
            );
        }
        let epoch = epoch_sleep(&test, &validator_1_rpc, 40)?;
        if epoch >= deactivate_epoch + pipeline_len {
            break;
        }
    }

    // Check the state of validator-0 again
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is inactive")?;
    client.assert_success();

    // Reactivate validator-1
    let tx_args = vec![
        "reactivate-validator",
        "--validator",
        "validator-1",
        "--signing-keys",
        "validator-1-balance-key",
        "--node",
        &validator_1_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(1), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let reactivate_epoch = get_epoch(&test, &validator_1_rpc)?;
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!(
                "Timed out waiting for epoch: {}",
                reactivate_epoch + pipeline_len
            );
        }
        let epoch = epoch_sleep(&test, &validator_1_rpc, 40)?;
        if epoch >= reactivate_epoch + pipeline_len {
            break;
        }
    }

    // Check the state of validator-0 again
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is in the below-threshold set")?;
    client.assert_success();

    Ok(())
}

/// Change validator metadata
#[test]
fn change_validator_metadata() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // 2. Query the validator metadata loaded from genesis
    let metadata_query_args = vec![
        "validator-metadata",
        "--validator",
        "validator-0",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run!(test, Bin::Client, metadata_query_args.clone(), Some(40))?;
    client.exp_string("Email:")?;
    client.exp_string("No description")?;
    client.exp_string("No website")?;
    client.exp_string("No discord handle")?;
    client.exp_string("commission rate:")?;
    client.exp_string("max change per epoch:")?;
    client.assert_success();

    // 3. Add some metadata to the validator
    let metadata_change_args = vec![
        "change-metadata",
        "--validator",
        "validator-0",
        "--email",
        "theokayestvalidator@namada.net",
        "--description",
        "We are just an okay validator node trying to get by",
        "--website",
        "theokayestvalidator.com",
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        metadata_change_args,
        Some(40)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 4. Query the metadata after the change
    let mut client =
        run!(test, Bin::Client, metadata_query_args.clone(), Some(40))?;
    client.exp_string("Email: theokayestvalidator@namada.net")?;
    client.exp_string(
        "Description: We are just an okay validator node trying to get by",
    )?;
    client.exp_string("Website: theokayestvalidator.com")?;
    client.exp_string("No discord handle")?;
    client.exp_string("commission rate:")?;
    client.exp_string("max change per epoch:")?;
    client.assert_success();

    // 5. Remove the validator website
    let metadata_change_args = vec![
        "change-metadata",
        "--validator",
        "validator-0",
        "--website",
        "",
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        metadata_change_args,
        Some(40)
    )?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // 6. Query the metadata to see that the validator website is removed
    let mut client =
        run!(test, Bin::Client, metadata_query_args.clone(), Some(40))?;
    client.exp_string("Email: theokayestvalidator@namada.net")?;
    client.exp_string(
        "Description: We are just an okay validator node trying to get by",
    )?;
    client.exp_string("No website")?;
    client.exp_string("No discord handle")?;
    client.exp_string("commission rate:")?;
    client.exp_string("max change per epoch:")?;
    client.assert_success();

    Ok(())
}

#[test]
fn test_invalid_validator_txs() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |mut genesis, base_dir: &_| {
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = unbonding_len;
            // genesis.parameters.parameters.min_num_of_blocks = 6;
            // genesis.parameters.parameters.max_expected_time_per_block = 1;
            // genesis.parameters.parameters.epochs_per_year = 31_536_000;
            let mut genesis = setup::set_validators(
                2,
                genesis,
                base_dir,
                default_port_offset,
            );
            genesis.transactions.bond = Some({
                let wallet = get_pregenesis_wallet(base_dir);
                let validator_1_address = wallet
                    .find_address("validator-1")
                    .expect("Failed to find validator-1 address");
                let mut bonds = genesis.transactions.bond.unwrap();
                bonds
                    .retain(|bond| bond.data.validator != *validator_1_address);
                bonds
            });
            genesis
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let _bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));
    let validator_1_rpc = get_actor_rpc(&test, Who::Validator(1));

    // Try to change validator-1 commission rate as validator-0
    let tx_args = vec![
        "change-commission-rate",
        "--validator",
        "validator-1",
        "--commission-rate",
        "0.06",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    // Try to deactivate validator-1 as validator-0
    let tx_args = vec![
        "deactivate-validator",
        "--validator",
        "validator-1",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    // Try to change the validator-1 website as validator-0
    let tx_args = vec![
        "change-metadata",
        "--validator",
        "validator-1",
        "--website",
        "theworstvalidator@namada.net",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    // Deactivate validator-1
    let tx_args = vec![
        "deactivate-validator",
        "--validator",
        "validator-1",
        "--signing-keys",
        "validator-1-balance-key",
        "--node",
        &validator_1_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(1), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    let deactivate_epoch = get_epoch(&test, &validator_1_rpc)?;
    let start = Instant::now();
    let loop_timeout = Duration::new(120, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!(
                "Timed out waiting for epoch: {}",
                deactivate_epoch + pipeline_len
            );
        }
        let epoch = epoch_sleep(&test, &validator_1_rpc, 40)?;
        if epoch >= deactivate_epoch + pipeline_len {
            break;
        }
    }

    // Check the state of validator-1
    let tx_args = vec![
        "validator-state",
        "--validator",
        "validator-1",
        "--node",
        &validator_1_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_regex(r"Validator [a-z0-9]+ is inactive")?;
    client.assert_success();

    // Try to reactivate validator-1 as validator-0
    let tx_args = vec![
        "reactivate-validator",
        "--validator",
        "validator-1",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_REJECTED)?;
    client.assert_success();

    Ok(())
}

/// Test change of consensus key of a validator from consensus set.
///
/// 1. Run 2 genesis validator nodes.
/// 2. Change consensus key of validator-0
/// 3. Check that no new blocks are being created - chain halted because
///    validator-0 consensus change took effect and it cannot sign with the old
///    key anymore
/// 4. Configure validator-0 node with the new key
/// 5. Resume the chain and check that blocks are being created
#[test]
fn change_consensus_key() -> Result<()> {
    let min_num_of_blocks = 6;
    let pipeline_len = 2;
    let test = setup::network(
        |mut genesis, base_dir| {
            genesis.parameters.parameters.min_num_of_blocks = min_num_of_blocks;
            genesis.parameters.parameters.max_expected_time_per_block = 1;
            genesis.parameters.parameters.epochs_per_year = 31_536_000;
            genesis.parameters.pos_params.pipeline_len = pipeline_len;
            genesis.parameters.pos_params.unbonding_len = 4;
            setup::set_validators(2, genesis, base_dir, default_port_offset)
        },
        None,
    )?;

    for i in 0..2 {
        set_ethereum_bridge_mode(
            &test,
            &test.net.chain_id,
            Who::Validator(i),
            ethereum_bridge::ledger::Mode::Off,
            None,
        );
    }

    // =========================================================================
    // 1. Run 2 genesis validator ledger nodes

    let bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let _bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));

    // =========================================================================
    // 2. Change consensus key of validator-0

    let tx_args = vec![
        "change-consensus-key",
        "--validator",
        "validator-0",
        "--signing-keys",
        "validator-0-balance-key",
        "--node",
        &validator_0_rpc,
        "--unsafe-dont-encrypt",
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string(TX_APPLIED_SUCCESS)?;
    client.assert_success();

    // =========================================================================
    // 3. Check that no new blocks are being created - chain halted because
    // validator-0 consensus change took effect and it cannot sign with the old
    // key anymore

    // Wait for the next epoch
    let validator_0_rpc = get_actor_rpc(&test, Who::Validator(0));
    let _epoch = epoch_sleep(&test, &validator_0_rpc, 30)?;

    // The chain should halt before the following (pipeline) epoch
    let _err_report = epoch_sleep(&test, &validator_0_rpc, 30)
        .expect_err("Chain should halt");

    // Load validator-0 wallet
    println!(
        "{}",
        "Setting up the new validator consensus key in CometBFT...".blue()
    );
    let chain_dir = test.get_chain_dir(Who::Validator(0));
    let mut wallet = namada_apps::wallet::load(&chain_dir).unwrap();

    // =========================================================================
    // 4. Configure validator-0 node with the new key

    // Get the new consensus SK
    let new_key_alias = "validator-0-consensus-key-1";
    let new_sk = wallet.find_secret_key(new_key_alias, None).unwrap();
    // Write the key to CometBFT dir
    let cometbft_dir = test.get_cometbft_home(Who::Validator(0));
    namada_apps::node::ledger::tendermint_node::write_validator_key(
        cometbft_dir,
        &new_sk,
    )
    .unwrap();
    println!(
        "{}",
        "Done setting up the new validator consensus key in CometBFT.".blue()
    );

    // =========================================================================
    // 5. Resume the chain and check that blocks are being created

    // Restart validator-0 node
    let mut validator_0 = bg_validator_0.foreground();
    validator_0.interrupt().unwrap();
    // Wait for the node to stop running
    validator_0.exp_string(LEDGER_SHUTDOWN)?;
    validator_0.exp_eof()?;
    drop(validator_0);

    let mut validator_0 = start_namada_ledger_node(&test, Some(0), Some(40))?;
    // Wait to commit a block
    validator_0.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    let _bg_validator_0 = validator_0.background();

    // Continue to make blocks for another epoch
    let _epoch = epoch_sleep(&test, &validator_0_rpc, 40)?;

    Ok(())
}
