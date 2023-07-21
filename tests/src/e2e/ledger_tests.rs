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

use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use data_encoding::HEXLOWER;
use namada::types::address::{btc, eth, masp_rewards, Address};
use namada::types::governance::ProposalType;
use namada::types::storage::Epoch;
use namada::types::token;
use namada_apps::client::tx::CLIShieldedUtils;
use namada_apps::config::ethereum_bridge;
use namada_apps::config::genesis::genesis_config::{
    GenesisConfig, ParametersConfig, PosParamsConfig,
};
use namada_apps::config::utils::convert_tm_addr_to_socket_addr;
use namada_apps::facade::tendermint_config::net::Address as TendermintAddress;
use namada_core::types::token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
use namada_test_utils::TestWasms;
use serde_json::json;
use setup::constants::*;
use setup::Test;

use super::helpers::{
    get_height, is_debug_mode, wait_for_block_height, wait_for_wasm_pre_compile,
};
use super::setup::{get_all_wasms_hashes, set_ethereum_bridge_mode, NamadaCmd};
use crate::e2e::helpers::{
    epoch_sleep, find_address, find_bonded_stake, get_actor_rpc, get_epoch,
    parse_reached_epoch,
};
use crate::e2e::setup::{self, default_port_offset, sleep, Bin, Who};
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
    let mut node =
        run_as!(test, who.clone(), Bin::Node, &["ledger"], timeout_sec)?;
    node.exp_string("Namada ledger node started")?;
    if let Who::Validator(_) = who {
        node.exp_string("This node is a validator")?;
    } else {
        node.exp_string("This node is not a validator")?;
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
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    let cmd_combinations = vec![vec!["ledger"], vec!["ledger", "run"]];

    // Start the ledger as a validator
    for args in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::Validator(0), Bin::Node, args, Some(40))?;
        ledger.exp_string("Namada ledger node started")?;
        ledger.exp_string("This node is a validator")?;
    }

    // Start the ledger as a non-validator
    for args in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::NonValidator, Bin::Node, args, Some(40))?;
        ledger.exp_string("Namada ledger node started")?;
        ledger.exp_string("This node is not a validator")?;
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
        |genesis| setup::set_validators(2, genesis, default_port_offset),
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(1),
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
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));
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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
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

    let validator_0_rpc = get_actor_rpc(&test, &Who::Validator(0));
    let validator_1_rpc = get_actor_rpc(&test, &Who::Validator(1));
    let non_validator_rpc = get_actor_rpc(&test, &Who::NonValidator);

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
        client.exp_string("nam: 1000010.1")?;
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
        &Who::Validator(0),
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
    ledger.exp_string("Namada ledger node has shut down.")?;
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
        &Who::Validator(0),
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
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));
    epoch_sleep(&test, &validator_one_rpc, 30)?;

    // 2. Shut it down
    let mut ledger = bg_ledger.foreground();
    ledger.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    ledger.exp_string("Namada ledger node has shut down.")?;
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

    ledger.exp_string("Namada ledger node started")?;
    // There should be no previous state
    ledger.exp_string("No state could be found")?;
    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    ledger.exp_string("Reached block height 2, suspending.")?;
    let bg_ledger = ledger.background();

    // 2. Query the ledger
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));
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
    ledger.exp_string("Namada ledger node has shut down.")?;
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

    ledger.exp_string("Namada ledger node started")?;
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
    let test = setup::network(|genesis| genesis, None)?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
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
        amount: token::DenominatedAmount {
            amount: token::Amount::native_whole(10),
            denom: token::NATIVE_MAX_DECIMAL_PLACES.into(),
        },
        key: None,
        shielded: None,
    }
    .try_to_vec()
    .unwrap();
    let tx_data_path = test.test_dir.path().join("tx.data");
    std::fs::write(&tx_data_path, transfer).unwrap();
    let tx_data_path = tx_data_path.to_string_lossy();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

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
            "--gas-amount",
            "0",
            "--gas-limit",
            "0",
            "--gas-token",
            NAM,
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
            "--gas-amount",
            "0",
            "--gas-limit",
            "0",
            "--gas-token",
            NAM,
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
            "--gas-amount",
            "0",
            "--gas-limit",
            "0",
            "--gas-token",
            NAM,
            "--node",
            &validator_one_rpc,
        ],
        // 3. Submit a transaction to update an account's validity
        // predicate
        vec![
            "update",
             "--address",
             BERTHA,
             "--code-path",
             VP_USER_WASM,
             "--gas-amount",
             "0",
             "--gas-limit",
             "0",
             "--gas-token",
             NAM,
            "--node",
            &validator_one_rpc,
        ],
        // 4. Submit a custom tx
        vec![
            "tx",
            "--signer",
            BERTHA,
            "--code-path",
            TX_TRANSFER_WASM,
            "--data-path",
            &tx_data_path,
            "--gas-amount",
            "0",
            "--gas-limit",
            "0",
            "--gas-token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        // 5. Submit a tx to initialize a new account
        vec![
            "init-account",
            "--source",
            BERTHA,
            "--public-key",
            // Value obtained from `namada::types::key::ed25519::tests::gen_keypair`
            "001be519a321e29020fa3cbfbfd01bd5e92db134305609270b71dace25b5a21168",
            "--code-path",
            VP_USER_WASM,
            "--alias",
            "Test-Account",
            "--gas-amount",
            "0",
            "--gas-limit",
            "0",
            "--gas-token",
            NAM,
            "--node",
            &validator_one_rpc,
        ],
    // 6. Submit a tx to withdraw from faucet account (requires PoW challenge
    //    solution)
        vec![
            "transfer",
            "--source",
            "faucet",
            "--target",
            ALBERT,
            "--token",
            NAM,
            "--amount",
            "10.1",
            // Faucet withdrawal requires an explicit signer
            "--signer",
            ALBERT,
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
                client.exp_string("Transaction accepted")?;
                client.exp_string("Transaction applied")?;
            }
            client.exp_string("Transaction is valid.")?;
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
            r"nam: \d+(\.\d+)?",
        ),
    ];
    for (query_args, expected) in &query_args_and_expected_response {
        let mut client = run!(test, Bin::Client, query_args, Some(40))?;
        client.exp_regex(expected)?;

        client.assert_success();
    }
    let christel = find_address(&test, CHRISTEL)?;
    // as setup in `genesis/e2e-tests-single-node.toml`
    let christel_balance = token::Amount::native_whole(1000000);
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
            HEXLOWER.encode(&christel_balance.try_to_vec().unwrap()),
        ),
    ];
    for (query_args, expected) in &query_args_and_expected_response {
        let mut client = run!(test, Bin::Client, query_args, Some(40))?;
        client.exp_string(expected)?;

        client.assert_success();
    }

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Attempt to spend 10 BTC at SK(A) to PA(B)
/// 3. Attempt to spend 15 BTC at SK(A) to Bertha
/// 4. Send 20 BTC from Albert to PA(A)
/// 5. Attempt to spend 10 ETH at SK(A) to PA(B)
/// 6. Spend 7 BTC at SK(A) to PA(B)
/// 7. Spend 7 BTC at SK(A) to PA(B)
/// 8. Attempt to spend 7 BTC at SK(A) to PA(B)
/// 9. Spend 6 BTC at SK(A) to PA(B)
/// 10. Assert BTC balance at VK(A) is 0
/// 11. Assert ETH balance at VK(A) is 0
/// 12. Assert balance at VK(B) is 10 BTC
/// 13. Send 10 BTC from SK(B) to Bertha

#[test]
fn masp_txs_and_queries() -> Result<()> {
    // Download the shielded pool parameters before starting node
    let _ = CLIShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(
                    if is_debug_mode() { 3600 } else { 360 },
                ),
                min_num_of_blocks: 1,
                ..genesis.parameters
            };
            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    let _ep1 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    let txs_args = vec![
        // 2. Attempt to spend 10 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "10",
                "--node",
                &validator_one_rpc,
            ],
            "No balance found",
        ),
        // 3. Attempt to spend 15 BTC at SK(A) to Bertha
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "15",
                "--node",
                &validator_one_rpc,
            ],
            "No balance found",
        ),
        // 4. Send 20 BTC from Albert to PA(A)
        (
            vec![
                "transfer",
                "--source",
                ALBERT,
                "--target",
                AA_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "20",
                "--node",
                &validator_one_rpc,
            ],
            "Transaction is valid",
        ),
        // 5. Attempt to spend 10 ETH at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                ETH,
                "--amount",
                "10",
                "--node",
                &validator_one_rpc,
            ],
            "No balance found",
        ),
        // 6. Spend 7 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                AB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--node",
                &validator_one_rpc,
            ],
            "Transaction is valid",
        ),
        // 7. Spend 7 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--node",
                &validator_one_rpc,
            ],
            "Transaction is valid",
        ),
        // 8. Attempt to spend 7 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "7",
                "--node",
                &validator_one_rpc,
            ],
            "is lower than the amount to be transferred and fees",
        ),
        // 9. Spend 6 BTC at SK(A) to PA(B)
        (
            vec![
                "transfer",
                "--source",
                A_SPENDING_KEY,
                "--target",
                BB_PAYMENT_ADDRESS,
                "--token",
                BTC,
                "--amount",
                "6",
                "--node",
                &validator_one_rpc,
            ],
            "Transaction is valid",
        ),
        // 10. Assert BTC balance at VK(A) is 0
        (
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                BTC,
                "--node",
                &validator_one_rpc,
            ],
            "No shielded btc balance found",
        ),
        // 11. Assert ETH balance at VK(A) is 0
        (
            vec![
                "balance",
                "--owner",
                AA_VIEWING_KEY,
                "--token",
                ETH,
                "--node",
                &validator_one_rpc,
            ],
            "No shielded eth balance found",
        ),
        // 12. Assert balance at VK(B) is 10 BTC
        (
            vec![
                "balance",
                "--owner",
                AB_VIEWING_KEY,
                "--node",
                &validator_one_rpc,
            ],
            "btc : 20",
        ),
        // 13. Send 10 BTC from SK(B) to Bertha
        (
            vec![
                "transfer",
                "--source",
                B_SPENDING_KEY,
                "--target",
                BERTHA,
                "--token",
                BTC,
                "--amount",
                "20",
                "--node",
                &validator_one_rpc,
            ],
            "Transaction is valid",
        ),
    ];

    for (tx_args, tx_result) in &txs_args {
        for &dry_run in &[true, false] {
            let tx_args = if dry_run && tx_args[0] == "transfer" {
                vec![tx_args.clone(), vec!["--dry-run"]].concat()
            } else {
                tx_args.clone()
            };
            let mut client = run!(test, Bin::Client, tx_args, Some(720))?;

            if *tx_result == "Transaction is valid" && !dry_run {
                client.exp_string("Transaction accepted")?;
                client.exp_string("Transaction applied")?;
            }
            client.exp_string(tx_result)?;
        }
    }

    Ok(())
}

/// In this test we:
/// 1. Run the ledger node
/// 2. Assert PPA(C) cannot be recognized by incorrect viewing key
/// 3. Assert PPA(C) has not transaction pinned to it
/// 4. Send 20 BTC from Albert to PPA(C)
/// 5. Assert PPA(C) has the 20 BTC transaction pinned to it

#[test]
fn masp_pinned_txs() -> Result<()> {
    // Download the shielded pool parameters before starting node
    let _ = CLIShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(120),
                ..genesis.parameters
            };
            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    // Wait till epoch boundary
    let _ep0 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Assert PPA(C) cannot be recognized by incorrect viewing key
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AC_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.send_line(AB_VIEWING_KEY)?;
    client.exp_string("Supplied viewing key cannot decode transactions to")?;
    client.assert_success();

    // Assert PPA(C) has no transaction pinned to it
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AC_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.send_line(AC_VIEWING_KEY)?;
    client.exp_string("has not yet been consumed")?;
    client.assert_success();

    // Wait till epoch boundary
    let _ep1 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Send 20 BTC from Albert to PPA(C)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT,
            "--target",
            AC_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "20",
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is valid")?;
    client.assert_success();

    // Wait till epoch boundary
    // This makes it more consistent for some reason?
    let _ep2 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Assert PPA(C) has the 20 BTC transaction pinned to it
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AC_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.send_line(AC_VIEWING_KEY)?;
    client.exp_string("Received 20 btc")?;
    client.assert_success();

    // Assert PPA(C) has no NAM pinned to it
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AC_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.send_line(AC_VIEWING_KEY)?;
    client.exp_string("Received no shielded nam")?;
    client.assert_success();

    // Wait till epoch boundary
    let _ep1 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Assert PPA(C) does not NAM pinned to it on epoch boundary
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AC_PAYMENT_ADDRESS,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.send_line(AC_VIEWING_KEY)?;
    client.exp_string("Received no shielded nam")?;
    client.assert_success();

    Ok(())
}

/// In this test we verify that users of the MASP receive the correct rewards
/// for leaving their assets in the pool for varying periods of time.

#[test]
fn masp_incentives() -> Result<()> {
    // The number of decimal places used by BTC amounts.
    const BTC_DENOMINATION: u8 = 8;
    // The number of decimal places used by ETH amounts.
    const ETH_DENOMINATION: u8 = 18;
    // Download the shielded pool parameters before starting node
    let _ = CLIShieldedUtils::new(PathBuf::new());
    // Lengthen epoch to ensure that a transaction can be constructed and
    // submitted within the same block. Necessary to ensure that conversion is
    // not invalidated.
    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(
                    if is_debug_mode() { 340 } else { 85 },
                ),
                min_num_of_blocks: 1,
                ..genesis.parameters
            };
            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    // Wait till epoch boundary
    let ep0 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Send 20 BTC from Albert to PA(A)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT,
            "--target",
            AA_PAYMENT_ADDRESS,
            "--token",
            BTC,
            "--amount",
            "20",
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is valid")?;
    client.assert_success();

    // Assert BTC balance at VK(A) is 20
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            BTC,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("btc: 20")?;
    client.assert_success();

    // Assert NAM balance at VK(A) is 0
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("No shielded nam balance found")?;
    client.assert_success();

    let masp_rewards = masp_rewards();

    // Wait till epoch boundary
    let ep1 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Assert BTC balance at VK(A) is 20
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            BTC,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("btc: 20")?;
    client.assert_success();

    let amt20 = token::Amount::from_uint(20, BTC_DENOMINATION).unwrap();
    let amt10 = token::Amount::from_uint(10, ETH_DENOMINATION).unwrap();

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_1-epoch_0)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt20 * masp_rewards[&btc()]).0 * (ep1.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Assert NAM balance at MASP pool is 20*BTC_reward*(epoch_1-epoch_0)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            MASP,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt20 * masp_rewards[&btc()]).0 * (ep1.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Wait till epoch boundary
    let ep2 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Assert BTC balance at VK(A) is 20
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            BTC,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("btc: 20")?;
    client.assert_success();

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_2-epoch_0)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt20 * masp_rewards[&btc()]).0 * (ep2.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Assert NAM balance at MASP pool is 20*BTC_reward*(epoch_2-epoch_0)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            MASP,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt20 * masp_rewards[&btc()]).0 * (ep2.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Wait till epoch boundary
    let ep3 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Send 10 ETH from Albert to PA(B)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            ALBERT,
            "--target",
            AB_PAYMENT_ADDRESS,
            "--token",
            ETH,
            "--amount",
            "10",
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is valid")?;
    client.assert_success();

    // Assert ETH balance at VK(B) is 10
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            ETH,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("eth: 10")?;
    client.assert_success();

    // Assert NAM balance at VK(B) is 0
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("No shielded nam balance found")?;
    client.assert_success();

    // Wait till epoch boundary
    let ep4 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Assert ETH balance at VK(B) is 10
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            ETH,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("eth: 10")?;
    client.assert_success();

    // Assert NAM balance at VK(B) is 10*ETH_reward*(epoch_4-epoch_3)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt10 * masp_rewards[&eth()]).0 * (ep4.0 - ep3.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_4-epoch_0)+10*ETH_reward*(epoch_4-epoch_3)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            MASP,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = ((amt20 * masp_rewards[&btc()]).0 * (ep4.0 - ep0.0))
        + ((amt10 * masp_rewards[&eth()]).0 * (ep4.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated))?;
    client.assert_success();

    // Wait till epoch boundary
    let ep5 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Send 10 ETH from SK(B) to Christel
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            B_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            ETH,
            "--amount",
            "10",
            "--signer",
            BERTHA,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is valid")?;
    client.assert_success();

    // Assert ETH balance at VK(B) is 0
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            ETH,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("No shielded eth balance found")?;
    client.assert_success();

    // let mut ep = get_epoch(&test, &validator_one_rpc)?;

    // Assert NAM balance at VK(B) is 10*ETH_reward*(ep-epoch_3)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt10 * masp_rewards[&eth()]).0 * (ep5.0 - ep3.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // ep = get_epoch(&test, &validator_one_rpc)?;
    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_5-epoch_0)+10*ETH_reward*(epoch_5-epoch_3)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            MASP,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = ((amt20 * masp_rewards[&btc()]).0 * (ep5.0 - ep0.0))
        + ((amt10 * masp_rewards[&eth()]).0 * (ep5.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated))?;
    client.assert_success();

    // Wait till epoch boundary
    let ep6 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Send 20 BTC from SK(A) to Christel
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            A_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            BTC,
            "--amount",
            "20",
            "--signer",
            ALBERT,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is valid")?;
    client.assert_success();

    // Assert BTC balance at VK(A) is 0
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            BTC,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("No shielded btc balance found")?;
    client.assert_success();

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_6-epoch_0)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt20 * masp_rewards[&btc()]).0 * (ep6.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_6-epoch_0)+20*ETH_reward*(epoch_5-epoch_3)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            MASP,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = ((amt20 * masp_rewards[&btc()]).0 * (ep6.0 - ep0.0))
        + ((amt10 * masp_rewards[&eth()]).0 * (ep5.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Wait till epoch boundary
    let _ep7 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Assert NAM balance at VK(A) is 20*BTC_reward*(epoch_6-epoch_0)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt20 * masp_rewards[&btc()]).0 * (ep6.0 - ep0.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated))?;
    client.assert_success();

    // Assert NAM balance at VK(B) is 10*ETH_reward*(epoch_5-epoch_3)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = (amt10 * masp_rewards[&eth()]).0 * (ep5.0 - ep3.0);
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Assert NAM balance at MASP pool is
    // 20*BTC_reward*(epoch_6-epoch_0)+10*ETH_reward*(epoch_5-epoch_3)
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            MASP,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    let amt = ((amt20 * masp_rewards[&btc()]).0 * (ep6.0 - ep0.0))
        + ((amt10 * masp_rewards[&eth()]).0 * (ep5.0 - ep3.0));
    let denominated = DenominatedAmount {
        amount: amt,
        denom: NATIVE_MAX_DECIMAL_PLACES.into(),
    };
    client.exp_string(&format!("nam: {}", denominated,))?;
    client.assert_success();

    // Wait till epoch boundary to prevent conversion expiry during transaction
    // construction
    let _ep8 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Send 10*ETH_reward*(epoch_5-epoch_3) NAM from SK(B) to Christel
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            B_SPENDING_KEY,
            "--target",
            CHRISTEL,
            "--token",
            NAM,
            "--amount",
            &((amt10 * masp_rewards[&eth()]).0 * (ep5.0 - ep3.0))
                .to_string_native(),
            "--signer",
            BERTHA,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is valid")?;
    client.assert_success();

    // Wait till epoch boundary
    let _ep9 = epoch_sleep(&test, &validator_one_rpc, 720)?;

    // Send 20*BTC_reward*(epoch_6-epoch_0) NAM from SK(A) to Bertha
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "transfer",
            "--source",
            A_SPENDING_KEY,
            "--target",
            BERTHA,
            "--token",
            NAM,
            "--amount",
            &((amt20 * masp_rewards[&btc()]).0 * (ep6.0 - ep0.0))
                .to_string_native(),
            "--signer",
            ALBERT,
            "--node",
            &validator_one_rpc
        ],
        Some(300)
    )?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is valid")?;
    client.assert_success();

    // Assert NAM balance at VK(A) is 0
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AA_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("No shielded nam balance found")?;
    client.assert_success();

    // Assert NAM balance at VK(B) is 0
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            AB_VIEWING_KEY,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("No shielded nam balance found")?;
    client.assert_success();

    // Assert NAM balance at MASP pool is 0
    let mut client = run!(
        test,
        Bin::Client,
        vec![
            "balance",
            "--owner",
            MASP,
            "--token",
            NAM,
            "--node",
            &validator_one_rpc
        ],
        Some(60)
    )?;
    client.exp_string("nam: 0")?;
    client.assert_success();

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
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    // 2. Submit a an invalid transaction (trying to transfer tokens should fail
    // in the user's VP due to the wrong signer)
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    let tx_args = vec![
        "transfer",
        "--source",
        DAEWON,
        "--signing-key",
        ALBERT_KEY,
        "--target",
        ALBERT,
        "--token",
        NAM,
        "--amount",
        "1",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;
    client.exp_string("Transaction is invalid")?;
    client.exp_string(r#""code": "4"#)?;

    client.assert_success();
    let mut ledger = bg_ledger.foreground();
    ledger.exp_string("rejected inner txs: 1")?;

    // Wait to commit a block
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    // 3. Shut it down
    ledger.interrupt()?;
    // Wait for the node to stop running to finish writing the state and tx
    // queue
    ledger.exp_string("Namada ledger node has shut down.")?;
    ledger.exp_eof()?;
    drop(ledger);

    // 4. Restart the ledger
    let mut ledger = start_namada_ledger_node(&test, Some(0), Some(40))?;

    // There should be previous state now
    ledger.exp_string("Last state root hash:")?;
    // Wait for a block by which time the RPC should be ready
    ledger.exp_string("Committed block hash")?;
    let _bg_ledger = ledger.background();

    // 5. Submit an invalid transactions (invalid token address)
    let daewon_lower = DAEWON.to_lowercase();
    let tx_args = vec![
        "transfer",
        "--source",
        DAEWON,
        "--signing-key",
        &daewon_lower,
        "--target",
        ALBERT,
        "--token",
        BERTHA,
        "--amount",
        "1000000.1",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        // Force to ignore client check that fails on the balance check of the
        // source address
        "--force",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction accepted")?;
    client.exp_string("Transaction applied")?;

    client.exp_string("Error trying to apply a transaction")?;

    client.exp_string(r#""code": "3"#)?;

    client.assert_success();
    Ok(())
}

/// PoS bonding, unbonding and withdrawal tests. In this test we:
///
/// 1. Run the ledger node with shorter epochs for faster progression
/// 2. Submit a self-bond for the genesis validator
/// 3. Submit a delegation to the genesis validator
/// 4. Submit an unbond of the self-bond
/// 5. Submit an unbond of the delegation
/// 6. Wait for the unbonding epoch
/// 7. Submit a withdrawal of the self-bond
/// 8. Submit a withdrawal of the delegation
#[test]
fn pos_bonds() -> Result<()> {
    let pipeline_len = 2;
    let unbonding_len = 4;
    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                min_num_of_blocks: 6,
                max_expected_time_per_block: 1,
                epochs_per_year: 31_536_000,
                ..genesis.parameters
            };
            let pos_params = PosParamsConfig {
                pipeline_len,
                unbonding_len,
                ..genesis.pos_params
            };
            GenesisConfig {
                parameters,
                pos_params,
                ..genesis
            }
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    // 2. Submit a self-bond for the genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--amount",
        "10000.0",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 3. Submit a delegation to the genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "5000.0",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 4. Submit an unbond of the self-bond
    let tx_args = vec![
        "unbond",
        "--validator",
        "validator-0",
        "--amount",
        "5100.0",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client
        .exp_string("Amount 5100.000000 withdrawable starting from epoch ")?;
    client.assert_success();

    // 5. Submit an unbond of the delegation
    let tx_args = vec![
        "unbond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "3200.",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    let expected = "Amount 3200.000000 withdrawable starting from epoch ";
    let (_unread, matched) = client.exp_regex(&format!("{expected}.*\n"))?;
    let epoch_raw = matched.trim().split_once(expected).unwrap().1;
    let delegation_withdrawable_epoch = Epoch::from_str(epoch_raw).unwrap();
    client.assert_success();

    // 6. Wait for the delegation withdrawable epoch (the self-bond was unbonded
    // before it)
    let epoch = get_epoch(&test, &validator_one_rpc)?;

    println!(
        "Current epoch: {}, earliest epoch for withdrawal: {}",
        epoch, delegation_withdrawable_epoch
    );
    let start = Instant::now();
    let loop_timeout = Duration::new(60, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!(
                "Timed out waiting for epoch: {}",
                delegation_withdrawable_epoch
            );
        }
        let epoch = epoch_sleep(&test, &validator_one_rpc, 40)?;
        if epoch >= delegation_withdrawable_epoch {
            break;
        }
    }

    // 7. Submit a withdrawal of the self-bond
    let tx_args = vec![
        "withdraw",
        "--validator",
        "validator-0",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 8. Submit a withdrawal of the delegation
    let tx_args = vec![
        "withdraw",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();
    Ok(())
}

/// TODO
#[test]
fn pos_rewards() -> Result<()> {
    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                min_num_of_blocks: 4,
                epochs_per_year: 31_536_000,
                max_expected_time_per_block: 1,
                ..genesis.parameters
            };
            let pos_params = PosParamsConfig {
                pipeline_len: 2,
                unbonding_len: 4,
                ..genesis.pos_params
            };
            let genesis = GenesisConfig {
                parameters,
                pos_params,
                ..genesis
            };
            setup::set_validators(3, genesis, default_port_offset)
        },
        None,
    )?;

    for i in 0..3 {
        set_ethereum_bridge_mode(
            &test,
            &test.net.chain_id,
            &Who::Validator(i),
            ethereum_bridge::ledger::Mode::Off,
            None,
        );
    }

    // 1. Run 3 genesis validator ledger nodes
    let bg_validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();
    let bg_validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?
            .background();
    let bg_validator_2 =
        start_namada_ledger_node_wait_wasm(&test, Some(2), Some(40))?
            .background();

    let validator_zero_rpc = get_actor_rpc(&test, &Who::Validator(0));
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(1));
    let validator_two_rpc = get_actor_rpc(&test, &Who::Validator(2));

    // Submit a delegation from Bertha to validator-0
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "10000.0",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_zero_rpc,
    ];

    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Check that all validator nodes processed the tx with same result
    let validator_0 = bg_validator_0.foreground();
    let validator_1 = bg_validator_1.foreground();
    let validator_2 = bg_validator_2.foreground();

    // let expected_result = "all VPs accepted transaction";
    // validator_0.exp_string(expected_result)?;
    // validator_1.exp_string(expected_result)?;
    // validator_2.exp_string(expected_result)?;

    let _bg_validator_0 = validator_0.background();
    let _bg_validator_1 = validator_1.background();
    let _bg_validator_2 = validator_2.background();

    // Let validator-1 self-bond
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-1",
        "--amount",
        "30000.0",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(1), Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Let validator-2 self-bond
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-2",
        "--amount",
        "25000.0",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_two_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(2), Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Wait some epochs
    let epoch = get_epoch(&test, &validator_zero_rpc)?;
    let wait_epoch = epoch + 4_u64;
    println!(
        "Current epoch: {}, earliest epoch for withdrawal: {}",
        epoch, wait_epoch
    );

    let start = Instant::now();
    let loop_timeout = Duration::new(40, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!("Timed out waiting for epoch: {}", wait_epoch);
        }
        let epoch = epoch_sleep(&test, &validator_zero_rpc, 40)?;
        if dbg!(epoch) >= wait_epoch {
            break;
        }
    }
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
        |genesis| {
            let parameters = ParametersConfig {
                min_num_of_blocks: 2,
                max_expected_time_per_block: 1,
                epochs_per_year: 31_536_000,
                ..genesis.parameters
            };
            let pos_params = PosParamsConfig {
                pipeline_len,
                unbonding_len,
                ..genesis.pos_params
            };
            GenesisConfig {
                parameters,
                pos_params,
                ..genesis
            }
        },
        None,
    )?;

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));
    let validator_alias = "validator-0";

    // 2. Submit a delegation to the genesis validator
    let tx_args = vec![
        "bond",
        "--validator",
        validator_alias,
        "--source",
        BERTHA,
        "--amount",
        "200",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    let (_, res) = client
        .exp_regex(r"withdrawable starting from epoch [0-9]+")
        .unwrap();
    let withdraw_epoch =
        Epoch::from_str(res.split(' ').last().unwrap()).unwrap();
    client.assert_success();

    // 6. Wait for withdraw_epoch
    loop {
        let epoch = epoch_sleep(&test, &validator_one_rpc, 120)?;
        if epoch >= withdraw_epoch {
            break;
        }
    }

    // 7. Check the output of the bonds query
    let tx_args = vec!["bonds", "--ledger-address", &validator_one_rpc];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string(
        "All bonds total active: 200088.000000\r
All bonds total: 200088.000000\r
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
    let validator_stake = 200000_u64;
    let test = setup::network(
        |genesis| {
            assert_eq!(
                genesis.validator.get("validator-0").unwrap().tokens,
                Some(validator_stake),
                "Assuming this stake, we give the same amount to the new \
                 validator to have half of voting power",
            );
            let parameters = ParametersConfig {
                min_num_of_blocks: 4,
                epochs_per_year: 31_536_000,
                max_expected_time_per_block: 1,
                ..genesis.parameters
            };
            let pos_params = PosParamsConfig {
                pipeline_len,
                unbonding_len: 2,
                ..genesis.pos_params
            };
            GenesisConfig {
                parameters,
                pos_params,
                ..genesis
            }
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

    let non_validator_rpc = get_actor_rpc(&test, &Who::NonValidator);

    // 2. Initialize a new validator account with the non-validator node
    let new_validator = "new-validator";
    let new_validator_key = format!("{}-key", new_validator);
    let tx_args = vec![
        "init-validator",
        "--alias",
        new_validator,
        "--source",
        BERTHA,
        "--unsafe-dont-encrypt",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--commission-rate",
        "0.05",
        "--max-commission-rate-change",
        "0.01",
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 3. Submit a delegation to the new validator
    //    First, transfer some tokens to the validator's key for fees:
    let tx_args = vec![
        "transfer",
        "--source",
        BERTHA,
        "--target",
        &new_validator_key,
        "--token",
        NAM,
        "--amount",
        "0.5",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 4. Transfer some NAM to the new validator
    let validator_stake_str = &validator_stake.to_string();
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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 5. Submit a self-bond for the new validator
    let tx_args = vec![
        "bond",
        "--validator",
        new_validator,
        "--amount",
        validator_stake_str,
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &non_validator_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Stop the non-validator node and run it as the new validator
    let mut non_validator = bg_non_validator.foreground();
    non_validator.interrupt()?;
    non_validator.exp_eof()?;

    let loc = format!("{}:{}", std::file!(), std::line!());
    let validator_1_base_dir = test.get_base_dir(&Who::NonValidator);
    let mut validator_1 = setup::run_cmd(
        Bin::Node,
        ["ledger"],
        Some(60),
        &test.working_dir,
        validator_1_base_dir,
        loc,
    )?;

    validator_1.exp_string("Namada ledger node started")?;
    validator_1.exp_string("This node is a validator")?;
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
        token::Amount::native_whole(validator_stake + delegation)
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
        |genesis| genesis,
        // Set 10s consensus timeout to have more time to submit txs
        Some("10s"),
    )?);

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = Arc::new(get_actor_rpc(&test, &Who::Validator(0)));

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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
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
                client.exp_string("Transaction accepted")?;
                client.exp_string("Transaction applied")?;
                client.exp_string("Transaction is valid.")?;
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
    let working_dir = setup::working_dir();

    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(1),
                max_proposal_bytes: Default::default(),
                min_num_of_blocks: 4,
                max_expected_time_per_block: 1,
                vp_whitelist: Some(get_all_wasms_hashes(
                    &working_dir,
                    Some("vp_"),
                )),
                // Enable tx whitelist to test the execution of a
                // non-whitelisted tx by governance
                tx_whitelist: Some(get_all_wasms_hashes(
                    &working_dir,
                    Some("tx_"),
                )),
                ..genesis.parameters
            };

            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;

    let namadac_help = vec!["--help"];

    let mut client = run!(test, Bin::Client, namadac_help, Some(40))?;
    client.exp_string("Namada client command line interface.")?;
    client.assert_success();

    // 1. Run the ledger node
    let bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_0_rpc = get_actor_rpc(&test, &Who::Validator(0));

    // 1.1 Delegate some token
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_0_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 2. Submit valid proposal
    let albert = find_address(&test, ALBERT)?;
    let valid_proposal_json_path = prepare_proposal_data(
        &test,
        albert,
        ProposalType::Default(Some(
            TestWasms::TxProposalCode
                .path()
                .to_string_lossy()
                .to_string(),
        )),
    );
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
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
    client.exp_string("Proposal: 0")?;
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
    client.exp_string("nam: 999500")?;
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
    let invalid_proposal_json = json!(
        {
            "content": {
                "title": "TheTitle",
                "authors": "test@test.com",
                "discussions-to": "www.github.com/anoma/aip/1",
                "created": "2022-03-10T08:54:37Z",
                "license": "MIT",
                "abstract": "Ut convallis eleifend orci vel venenatis. Duis
    vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit
    ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum
    fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra
    varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida
    eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero.
    Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum
    bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue
    viverra enim.",
                "motivation": "Ut convallis eleifend orci vel venenatis. Duis
    vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit
    ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum
    fermentum. Morbi aliquet purus at sollicitudin ultrices.",
                "details": "Ut convallis eleifend orci vel venenatis. Duis
    vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit
    ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum
    fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra
    varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida
    eros.",             "requires": "2"
            },
            "author": albert,
            "voting_start_epoch": 9999_u64,
            "voting_end_epoch": 10000_u64,
            "grace_epoch": 10009_u64,
            "type": {
                "Default":null
                }
        }
    );
    let invalid_proposal_json_path =
        test.test_dir.path().join("invalid_proposal.json");
    generate_proposal_json_file(
        invalid_proposal_json_path.as_path(),
        &invalid_proposal_json,
    );

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        invalid_proposal_json_path.to_str().unwrap(),
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string(
        "Invalid proposal end epoch: difference between proposal start and \
         end epoch must be at least 3 and at max 27 and end epoch must be a \
         multiple of 3",
    )?;
    client.assert_failure();

    // 7. Check invalid proposal was not accepted
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "1",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("No valid proposal was found with id 1")?;
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
    client.exp_string("nam: 999500")?;
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
        "--signer",
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
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    let submit_proposal_vote_delagator = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "nay",
        "--signer",
        BERTHA,
        "--node",
        &validator_one_rpc,
    ];

    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 10. Send a yay vote from a non-validator/non-delegator user
    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--signer",
        ALBERT,
        "--node",
        &validator_one_rpc,
    ];

    // this is valid because the client filter ALBERT delegation and there are
    // none
    let mut client = run!(test, Bin::Client, submit_proposal_vote, Some(15))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

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
    client.exp_string("Result: passed")?;
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
    client.exp_string("nam: 1000000")?;
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

/// Test submission and vote of an ETH proposal.
///
/// 1 - Submit proposal
/// 2 - Vote with delegator and check failure
/// 3 - Vote with validator and check success
/// 4 - Check that proposal passed and funds
#[test]
fn eth_governance_proposal() -> Result<()> {
    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(1),
                max_proposal_bytes: Default::default(),
                min_num_of_blocks: 1,
                max_expected_time_per_block: 1,
                ..genesis.parameters
            };

            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;

    let namadac_help = vec!["--help"];

    let mut client = run!(test, Bin::Client, namadac_help, Some(40))?;
    client.exp_string("Namada client command line interface.")?;
    client.assert_success();

    // Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    // Delegate some token
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 1 - Submit proposal
    let albert = find_address(&test, ALBERT)?;
    let valid_proposal_json_path =
        prepare_proposal_data(&test, albert, ProposalType::ETHBridge);
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ];
    client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Query the proposal
    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "0",
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("Proposal: 0")?;
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
    client.exp_string("nam: 999500")?;
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

    // 2 - Vote with delegator and check failure
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 13 {
        sleep(1);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    use namada::types::key::{self, secp256k1, SigScheme};
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    // Generate a signing key to sign the eth message to sign the eth message to
    // sign the eth message
    let mut rng: ThreadRng = thread_rng();
    let node_sk = secp256k1::SigScheme::generate(&mut rng);
    let signing_key = key::common::SecretKey::Secp256k1(node_sk);
    let msg = "fd34672ab5";
    let vote_arg = format!("{} {}", signing_key, msg);
    let submit_proposal_vote_delagator = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--eth",
        &vote_arg,
        "--signer",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string("Transaction is invalid.")?;
    client.assert_success();

    // 3 - Send a yay vote from a validator
    let vote_arg = format!("{} {}", signing_key, msg);

    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--eth",
        &vote_arg,
        "--signer",
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
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 4 - Wait proposals grace and check proposal author funds
    while epoch.0 < 31 {
        sleep(1);
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
    client.exp_string("nam: 1000000")?;
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

    Ok(())
}

/// Test submission and vote of a PGF proposal
///
/// 1 - Sumbit two proposals
/// 2 - Check balance
/// 3 - Vote for the accepted proposals
/// 4 - Check one proposal passed and the other one didn't
/// 5 - Check funds
#[test]
fn pgf_governance_proposal() -> Result<()> {
    let test = setup::network(
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(1),
                max_proposal_bytes: Default::default(),
                min_num_of_blocks: 4,
                max_expected_time_per_block: 1,
                ..genesis.parameters
            };

            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
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

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    // Delegate some token
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        BERTHA,
        "--amount",
        "900",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 1 - Submit proposal
    let albert = find_address(&test, ALBERT)?;
    let valid_proposal_json_path =
        prepare_proposal_data(&test, albert.clone(), ProposalType::PGFCouncil);
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Sumbit another proposal
    let valid_proposal_json_path =
        prepare_proposal_data(&test, albert, ProposalType::PGFCouncil);
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    let submit_proposal_args = vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--ledger-address",
        &validator_one_rpc,
    ];
    client = run!(test, Bin::Client, submit_proposal_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
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
    client.exp_string("Proposal: 0")?;
    client.assert_success();

    let proposal_query_args = vec![
        "query-proposal",
        "--proposal-id",
        "1",
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, proposal_query_args, Some(40))?;
    client.exp_string("Proposal: 1")?;
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
    client.exp_string("nam: 999000")?;
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
    client.exp_string("nam: 1000")?;
    client.assert_success();

    // 3 - Send a yay vote from a validator
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 13 {
        sleep(1);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let albert_address = find_address(&test, ALBERT)?;
    let arg_vote = format!("{} 1000", albert_address);

    let submit_proposal_vote = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--pgf",
        &arg_vote,
        "--signer",
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
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Send different yay vote from delegator to check majority on 1/3
    let different_vote = format!("{} 900", albert_address);
    let submit_proposal_vote_delagator = vec![
        "vote-proposal",
        "--proposal-id",
        "0",
        "--vote",
        "yay",
        "--pgf",
        &different_vote,
        "--signer",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ];

    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // Send vote to the second proposal from delegator
    let submit_proposal_vote_delagator = vec![
        "vote-proposal",
        "--proposal-id",
        "1",
        "--vote",
        "yay",
        "--pgf",
        &different_vote,
        "--signer",
        BERTHA,
        "--ledger-address",
        &validator_one_rpc,
    ];

    // this is valid because the client filter ALBERT delegation and there are
    // none
    let mut client =
        run!(test, Bin::Client, submit_proposal_vote_delagator, Some(15))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
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
    client.exp_string(&format!(
        "Result: passed with PGF council address: {}, spending cap: 0.001",
        albert_address
    ))?;
    client.assert_success();

    // Query the second proposal and check the it didn't pass
    let query_proposal = vec![
        "query-proposal-result",
        "--proposal-id",
        "1",
        "--ledger-address",
        &validator_one_rpc,
    ];

    client = run!(test, Bin::Client, query_proposal, Some(15))?;
    client.exp_string("Result: rejected")?;
    client.assert_success();

    // 12. Wait proposals grace and check proposal author funds
    while epoch.0 < 31 {
        sleep(1);
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
    client.exp_string("nam: 999500")?;
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
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(1),
                max_proposal_bytes: Default::default(),
                min_num_of_blocks: 4,
                max_expected_time_per_block: 1,
                vp_whitelist: Some(get_all_wasms_hashes(
                    &working_dir,
                    Some("vp_"),
                )),
                // Enable tx whitelist to test the execution of a
                // non-whitelisted tx by governance
                tx_whitelist: Some(get_all_wasms_hashes(
                    &working_dir,
                    Some("tx_"),
                )),
                ..genesis.parameters
            };

            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    // 1.1 Delegate some token
    let tx_args = vec![
        "bond",
        "--validator",
        "validator-0",
        "--source",
        ALBERT,
        "--amount",
        "900",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 2. Create an offline
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
            "voting_start_epoch": 3_u64,
            "voting_end_epoch": 9_u64,
            "grace_epoch": 18_u64,
            "type": {
                "Default": null
                }
        }
    );
    let valid_proposal_json_path =
        test.test_dir.path().join("valid_proposal.json");
    generate_proposal_json_file(
        valid_proposal_json_path.as_path(),
        &valid_proposal_json,
    );

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

    let offline_proposal_args = vec![
        "init-proposal",
        "--data-path",
        valid_proposal_json_path.to_str().unwrap(),
        "--offline",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, offline_proposal_args, Some(15))?;
    client.exp_string("Proposal created: ")?;
    client.assert_success();

    // 3. Generate an offline yay vote
    let mut epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    while epoch.0 <= 2 {
        sleep(1);
        epoch = get_epoch(&test, &validator_one_rpc).unwrap();
    }

    let proposal_path = test.test_dir.path().join("proposal");

    let submit_proposal_vote = vec![
        "vote-proposal",
        "--data-path",
        proposal_path.to_str().unwrap(),
        "--vote",
        "yay",
        "--signer",
        ALBERT,
        "--offline",
        "--node",
        &validator_one_rpc,
    ];

    let mut client = run!(test, Bin::Client, submit_proposal_vote, Some(15))?;
    client.exp_string("Proposal vote created: ")?;
    client.assert_success();

    let expected_file_name = format!("proposal-vote-{}", albert);
    let expected_path_vote = test.test_dir.path().join(expected_file_name);
    assert!(expected_path_vote.exists());

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
    client.exp_string("Result: rejected")?;
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

/// In this test we:
/// 1. Setup 2 genesis validators
/// 2. Initialize a new network with the 2 validators
/// 3. Setup and start the 2 genesis validator nodes and a non-validator node
/// 4. Submit a valid token transfer tx from one validator to the other
/// 5. Check that all the nodes processed the tx with the same result
#[test]
fn test_genesis_validators() -> Result<()> {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::str::FromStr;

    use namada::types::chain::ChainId;
    use namada_apps::config::genesis::genesis_config::{
        self, ValidatorPreGenesisConfig,
    };
    use namada_apps::config::Config;

    // This test is not using the `setup::network`, because we're setting up
    // custom genesis validators
    setup::INIT.call_once(|| {
        if let Err(err) = color_eyre::install() {
            eprintln!("Failed setting up colorful error reports {}", err);
        }
    });

    let working_dir = setup::working_dir();
    let test_dir = setup::TestDir::new();
    let checksums_path = working_dir
        .join("wasm/checksums.json")
        .to_string_lossy()
        .into_owned();

    // Same as in `genesis/e2e-tests-single-node.toml` for `validator-0`
    let net_address_0 = SocketAddr::from_str("127.0.0.1:27656").unwrap();
    let net_address_port_0 = net_address_0.port();
    // Find the first port (ledger P2P) that should be used for a validator at
    // the given index
    let get_first_port = |ix: u8| net_address_port_0 + 6 * (ix as u16 + 1);

    // 1. Setup 2 genesis validators, one with ed25519 keys (0) and one with
    // secp256k1 keys (1)
    let validator_0_alias = "validator-0";
    let validator_1_alias = "validator-1";

    let mut init_genesis_validator_0 = setup::run_cmd(
        Bin::Client,
        [
            "utils",
            "init-genesis-validator",
            "--unsafe-dont-encrypt",
            "--alias",
            validator_0_alias,
            "--scheme",
            "ed25519",
            "--commission-rate",
            "0.05",
            "--max-commission-rate-change",
            "0.01",
            "--net-address",
            &format!("127.0.0.1:{}", get_first_port(0)),
        ],
        Some(5),
        &working_dir,
        &test_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;
    init_genesis_validator_0.assert_success();
    let validator_0_pre_genesis_dir =
        namada_apps::client::utils::validator_pre_genesis_dir(
            test_dir.path(),
            validator_0_alias,
        );
    let config = std::fs::read_to_string(
        namada_apps::client::utils::validator_pre_genesis_file(
            &validator_0_pre_genesis_dir,
        ),
    )
    .unwrap();
    let mut validator_0_config: ValidatorPreGenesisConfig =
        toml::from_str(&config).unwrap();
    let validator_0_config = validator_0_config
        .validator
        .remove(validator_0_alias)
        .unwrap();

    let mut init_genesis_validator_1 = setup::run_cmd(
        Bin::Client,
        [
            "utils",
            "init-genesis-validator",
            "--unsafe-dont-encrypt",
            "--alias",
            validator_1_alias,
            "--scheme",
            "secp256k1",
            "--commission-rate",
            "0.05",
            "--max-commission-rate-change",
            "0.01",
            "--net-address",
            &format!("127.0.0.1:{}", get_first_port(1)),
        ],
        Some(5),
        &working_dir,
        &test_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;
    init_genesis_validator_1.assert_success();
    let validator_1_pre_genesis_dir =
        namada_apps::client::utils::validator_pre_genesis_dir(
            test_dir.path(),
            validator_1_alias,
        );
    let config = std::fs::read_to_string(
        namada_apps::client::utils::validator_pre_genesis_file(
            &validator_1_pre_genesis_dir,
        ),
    )
    .unwrap();
    let mut validator_1_config: ValidatorPreGenesisConfig =
        toml::from_str(&config).unwrap();
    let validator_1_config = validator_1_config
        .validator
        .remove(validator_1_alias)
        .unwrap();

    // 2. Initialize a new network with the 2 validators
    let mut genesis = genesis_config::open_genesis_config(
        working_dir.join(setup::SINGLE_NODE_NET_GENESIS),
    )?;
    let update_validator_config =
        |ix: u8, mut config: genesis_config::ValidatorConfig| {
            // Setup tokens balances and validity predicates
            config.tokens = Some(200000);
            config.non_staked_balance = Some(1000000000000);
            config.validator_vp = Some("vp_user".into());
            // Setup the validator ports same as what
            // `setup::set_validators` would do
            let mut net_address = net_address_0;
            // 6 ports for each validator
            let first_port = get_first_port(ix);
            net_address.set_port(first_port);
            config.net_address = Some(net_address.to_string());
            config
        };
    genesis.validator = HashMap::from_iter([
        (
            validator_0_alias.to_owned(),
            update_validator_config(0, validator_0_config),
        ),
        (
            validator_1_alias.to_owned(),
            update_validator_config(1, validator_1_config),
        ),
    ]);
    let genesis_file = test_dir.path().join("e2e-test-genesis-src.toml");
    genesis_config::write_genesis_config(&genesis, &genesis_file);
    let genesis_path = genesis_file.to_string_lossy();

    let archive_dir = test_dir.path().to_string_lossy().to_string();
    let args = vec![
        "utils",
        "init-network",
        "--unsafe-dont-encrypt",
        "--genesis-path",
        &genesis_path,
        "--chain-prefix",
        "e2e-test",
        "--localhost",
        "--allow-duplicate-ip",
        "--wasm-checksums-path",
        &checksums_path,
        "--archive-dir",
        &archive_dir,
    ];
    let mut init_network = setup::run_cmd(
        Bin::Client,
        args,
        Some(5),
        &working_dir,
        &test_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;

    // Get the generated chain_id` from result of the last command
    let (unread, matched) =
        init_network.exp_regex(r"Derived chain ID: .*\n")?;
    let chain_id_raw =
        matched.trim().split_once("Derived chain ID: ").unwrap().1;
    let chain_id = ChainId::from_str(chain_id_raw.trim())?;
    println!("'init-network' output: {}", unread);
    let net = setup::Network {
        chain_id: chain_id.clone(),
    };
    let test = setup::Test {
        working_dir: working_dir.clone(),
        test_dir,
        net,
        genesis,
        async_runtime: Default::default(),
    };

    // Host the network archive to make it available for `join-network` commands
    let network_archive_server = file_serve::Server::new(&working_dir);
    let network_archive_addr = network_archive_server.addr().to_owned();
    std::thread::spawn(move || {
        network_archive_server.serve().unwrap();
    });

    // 3. Setup and start the 2 genesis validator nodes and a non-validator node

    // Clean-up the chain dir from the existing validator dir that were created
    // by `init-network`, because we want to set them up with `join-network`
    // instead
    let validator_0_base_dir = test.get_base_dir(&Who::Validator(0));
    let validator_1_base_dir = test.get_base_dir(&Who::Validator(1));
    std::fs::remove_dir_all(&validator_0_base_dir).unwrap();
    std::fs::remove_dir_all(&validator_1_base_dir).unwrap();

    std::env::set_var(
        namada_apps::client::utils::ENV_VAR_NETWORK_CONFIGS_SERVER,
        format!("http://{network_archive_addr}/{}", archive_dir),
    );
    let pre_genesis_path = validator_0_pre_genesis_dir.to_string_lossy();
    let mut join_network_val_0 = run_as!(
        test,
        Who::Validator(0),
        Bin::Client,
        [
            "utils",
            "join-network",
            "--chain-id",
            chain_id.as_str(),
            "--pre-genesis-path",
            pre_genesis_path.as_ref(),
            "--dont-prefetch-wasm",
        ],
        Some(5)
    )?;
    join_network_val_0.exp_string("Successfully configured for chain")?;

    let pre_genesis_path = validator_1_pre_genesis_dir.to_string_lossy();
    let mut join_network_val_1 = run_as!(
        test,
        Who::Validator(1),
        Bin::Client,
        [
            "utils",
            "join-network",
            "--chain-id",
            chain_id.as_str(),
            "--pre-genesis-path",
            pre_genesis_path.as_ref(),
            "--dont-prefetch-wasm",
        ],
        Some(5)
    )?;
    join_network_val_1.exp_string("Successfully configured for chain")?;

    // We have to update the ports in the configs again, because the ones from
    // `join-network` use the defaults
    //
    // TODO: use `update_actor_config` from `setup`, instead
    let update_config = |ix: u8, mut config: Config| {
        let first_port = net_address_port_0 + 6 * (ix as u16 + 1);
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

    let validator_0_config = update_config(
        0,
        Config::load(&validator_0_base_dir, &test.net.chain_id, None),
    );
    validator_0_config
        .write(&validator_0_base_dir, &chain_id, true)
        .unwrap();

    let validator_1_config = update_config(
        1,
        Config::load(&validator_1_base_dir, &test.net.chain_id, None),
    );
    validator_1_config
        .write(&validator_1_base_dir, &chain_id, true)
        .unwrap();

    // Copy WASMs to each node's chain dir
    let chain_dir = test.test_dir.path().join(chain_id.as_str());
    setup::copy_wasm_to_chain_dir(
        &working_dir,
        &chain_dir,
        &chain_id,
        test.genesis.validator.keys(),
    );

    let mut validator_0 =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?;
    let mut validator_1 =
        start_namada_ledger_node_wait_wasm(&test, Some(1), Some(40))?;
    let mut non_validator =
        start_namada_ledger_node_wait_wasm(&test, None, Some(40))?;

    // Wait for a first block
    validator_0.exp_string("Committed block hash")?;
    validator_1.exp_string("Committed block hash")?;
    non_validator.exp_string("Committed block hash")?;

    let bg_validator_0 = validator_0.background();
    let bg_validator_1 = validator_1.background();
    let _bg_non_validator = non_validator.background();

    // 4. Submit a valid token transfer tx
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));
    let tx_args = [
        "transfer",
        "--source",
        validator_0_alias,
        "--target",
        validator_1_alias,
        "--token",
        NAM,
        "--amount",
        "10.1",
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 3. Check that all the nodes processed the tx with the same result
    let mut validator_0 = bg_validator_0.foreground();
    let mut validator_1 = bg_validator_1.foreground();

    let expected_result = "successful inner txs: 1";
    // We cannot check this on non-validator node as it might sync without
    // applying the tx itself, but its state should be the same, checked below.
    validator_0.exp_string(expected_result)?;
    validator_1.exp_string(expected_result)?;
    let _bg_validator_0 = validator_0.background();
    let _bg_validator_1 = validator_1.background();

    let validator_0_rpc = get_actor_rpc(&test, &Who::Validator(0));
    let validator_1_rpc = get_actor_rpc(&test, &Who::Validator(1));
    let non_validator_rpc = get_actor_rpc(&test, &Who::NonValidator);

    // Find the block height on the validator
    let after_tx_height = get_height(&test, &validator_0_rpc)?;

    // Wait for the second validator and non-validator to be synced to at least
    // the same height
    wait_for_block_height(&test, &validator_1_rpc, after_tx_height, 10)?;
    wait_for_block_height(&test, &non_validator_rpc, after_tx_height, 10)?;

    let query_balance_args = |ledger_rpc| {
        vec![
            "balance",
            "--owner",
            validator_1_alias,
            "--token",
            NAM,
            "--node",
            ledger_rpc,
        ]
    };
    for ledger_rpc in &[validator_0_rpc, validator_1_rpc, non_validator_rpc] {
        let mut client =
            run!(test, Bin::Client, query_balance_args(ledger_rpc), Some(40))?;
        client.exp_string("nam: 1000000000010.1")?;
        client.assert_success();
    }

    Ok(())
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
        |genesis| {
            (pipeline_len, unbonding_len, cubic_offset) = (
                genesis.pos_params.pipeline_len,
                genesis.pos_params.unbonding_len,
                genesis.pos_params.cubic_slashing_window_length,
            );
            let mut genesis =
                setup::set_validators(4, genesis, default_port_offset);
            // Make faster epochs to be more likely to discover boundary issues
            genesis.parameters.min_num_of_blocks = 2;
            genesis
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::Off,
        None,
    );
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(1),
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
    validator_2.exp_string("Namada ledger node started")?;
    validator_2.exp_string("This node is a validator")?;
    let _bg_validator_2 = validator_2.background();

    let mut validator_3 =
        run_as!(test, Who::Validator(3), Bin::Node, &["ledger"], Some(40))?;
    validator_3.exp_string("Namada ledger node started")?;
    validator_3.exp_string("This node is a validator")?;
    let _bg_validator_3 = validator_3.background();

    // 2. Copy the first genesis validator base-dir
    let validator_0_base_dir = test.get_base_dir(&Who::Validator(0));
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
    validator_0_copy.exp_string("Namada ledger node started")?;
    validator_0_copy.exp_string("This node is a validator")?;
    let _bg_validator_0_copy = validator_0_copy.background();

    // 5. Submit a valid token transfer tx to validator 0
    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));
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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let _client = run!(test, Bin::Client, tx_args, Some(40))?;
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
    let bg_validator_1 = validator_1.background();

    let exp_processing_epoch = Epoch::from_str(res.split(' ').last().unwrap())
        .unwrap()
        + unbonding_len
        + cubic_offset
        + 1u64;

    // Query slashes
    // let tx_args = ["slashes", "--node", &validator_one_rpc];
    // let client = run!(test, Bin::Client, tx_args, Some(40))?;

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
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--node",
        &validator_one_rpc,
    ];
    let mut client =
        run_as!(test, Who::Validator(0), Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction applied with result:")?;
    client.exp_string("Transaction is valid.")?;
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
    validator_1.exp_string("Namada ledger node has shut down.")?;
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
    let test = setup::network(|genesis| genesis, None)?;

    // 1. Run the ledger node
    let _bg_ledger =
        start_namada_ledger_node_wait_wasm(&test, Some(0), Some(40))?
            .background();

    // 2. Some transactions that need signature authorization:
    let validator_0_rpc = get_actor_rpc(&test, &Who::Validator(0));
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
            let source = find_address(&test, source).unwrap();
            let valid_proposal_json_path = prepare_proposal_data(
                &test,
                source,
                ProposalType::Default(None),
            );
            vec![
                "init-proposal",
                "--data-path",
                valid_proposal_json_path.to_str().unwrap(),
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
            &["key", "gen", "--alias", &key_alias, "--unsafe-dont-encrypt"],
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
        |genesis| {
            let parameters = ParametersConfig {
                epochs_per_year: epochs_per_year_from_min_duration(30),
                min_num_of_blocks: 1,
                ..genesis.parameters
            };
            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;

    // 1. Run the ledger node
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    wait_for_wasm_pre_compile(&mut ledger)?;

    let _bg_ledger = ledger.background();

    let validator_one_rpc = get_actor_rpc(&test, &Who::Validator(0));

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
    proposal_type: ProposalType,
) -> PathBuf {
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
            "author": source,
            "voting_start_epoch": 12_u64,
            "voting_end_epoch": 24_u64,
            "grace_epoch": 30_u64,
            "type": proposal_type
        }
    );
    let valid_proposal_json_path =
        test.test_dir.path().join("valid_proposal.json");
    generate_proposal_json_file(
        valid_proposal_json_path.as_path(),
        &valid_proposal_json,
    );
    valid_proposal_json_path
}

/// Convert epoch `min_duration` in seconds to `epochs_per_year` genesis
/// parameter.
fn epochs_per_year_from_min_duration(min_duration: u64) -> u64 {
    60 * 60 * 24 * 365 / min_duration
}
