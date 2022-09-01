//! By default, these tests will run in release mode. This can be disabled
//! by setting environment variable `ANOMA_E2E_DEBUG=true`. For debugging,
//! you'll typically also want to set `RUST_BACKTRACE=1`, e.g.:
//!
//! ```ignore,shell
//! ANOMA_E2E_DEBUG=true RUST_BACKTRACE=1 cargo test e2e::ledger_tests -- --test-threads=1 --nocapture
//! ```
//!
//! To keep the temporary files created by a test, use env var
//! `ANOMA_E2E_KEEP_TEMP=true`.

use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use namada::types::address::{btc, eth, masp_rewards};
use namada::types::token;
use namada_apps::client::tx::ShieldedContext;
use namada_apps::config::genesis::genesis_config::{
    GenesisConfig, ParametersConfig, PosParamsConfig,
};
use serde_json::json;
use setup::constants::*;

use super::setup::working_dir;
use crate::e2e::helpers::{
    epoch_sleep, find_address, find_voting_power, get_actor_rpc, get_epoch,
};
use crate::e2e::setup::{self, sleep, Bin, Who};
use crate::{run, run_as};

/// Test that when we "run-ledger" with all the possible command
/// combinations from fresh state, the node starts-up successfully for both a
/// validator and non-validator user.
#[test]
fn run_ledger() -> Result<()> {
    let test = setup::single_node_net()?;
    let cmd_combinations = vec![vec!["ledger"], vec!["ledger", "run"]];

    // Start the ledger as a validator
    for args in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::Validator(0), Bin::Node, args, Some(40))?;
        ledger.exp_string("Anoma ledger node started")?;
        ledger.exp_string("This node is a validator")?;
    }

    // Start the ledger as a non-validator
    for args in &cmd_combinations {
        let mut ledger =
            run_as!(test, Who::NonValidator, Bin::Node, args, Some(40))?;
        ledger.exp_string("Anoma ledger node started")?;
        ledger.exp_string("This node is a fullnode")?;
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
        |genesis| {
            let genesis = setup::add_validators(1, genesis);
            let parameters = ParametersConfig {
                min_duration: 1,
                min_num_of_blocks: 5,
                ..genesis.parameters
            };
            GenesisConfig {
                parameters,
                ..genesis
            }
        },
        None,
    )?;

    // 1. Run 2 genesis validator ledger nodes and 1 non-validator node
    let args = ["ledger"];
    let mut validator_0 =
        run_as!(test, Who::Validator(0), Bin::Node, args, Some(40))?;
    validator_0.exp_string("Anoma ledger node started")?;
    validator_0.exp_string("This node is a validator")?;
    let mut validator_1 =
        run_as!(test, Who::Validator(1), Bin::Node, args, Some(40))?;
    validator_1.exp_string("Anoma ledger node started")?;
    validator_1.exp_string("This node is a validator")?;
    let mut non_validator =
        run_as!(test, Who::NonValidator, Bin::Node, args, Some(40))?;
    non_validator.exp_string("Anoma ledger node started")?;
    non_validator.exp_string("This node is a fullnode")?;

    let bg_validator_0 = validator_0.background();
    let bg_validator_1 = validator_1.background();
    let bg_non_validator = non_validator.background();

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
        XAN,
        "--amount",
        "10.1",
        "--fee-amount",
        "0",
        "--gas-limit",
        "0",
        "--fee-token",
        XAN,
        "--ledger-address",
        &validator_one_rpc,
    ];
    let mut client = run!(test, Bin::Client, tx_args, Some(40))?;
    client.exp_string("Transaction is valid.")?;
    client.assert_success();

    // 4. Check that all the nodes processed the tx with the same result
    let mut validator_0 = bg_validator_0.foreground();
    let mut validator_1 = bg_validator_1.foreground();
    let mut non_validator = bg_non_validator.foreground();

    let expected_result = "all VPs accepted transaction";
    validator_0.exp_string(expected_result)?;
    validator_1.exp_string(expected_result)?;
    non_validator.exp_string(expected_result)?;

    Ok(())
}
