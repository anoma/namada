//! E2E test helpers

use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, time};

use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use escargot::CargoBuild;
use eyre::eyre;
use namada::types::address::Address;
use namada::types::key::*;
use namada::types::storage::Epoch;
use namada_apps::config::{Config, TendermintMode};

use super::setup::{sleep, Test, ENV_VAR_DEBUG, ENV_VAR_USE_PREBUILT_BINARIES};
use crate::e2e::setup::{Bin, Who, APPS_PACKAGE};
use crate::run;

/// Find the address of an account by its alias from the wallet
pub fn find_address(test: &Test, alias: impl AsRef<str>) -> Result<Address> {
    let mut find = run!(
        test,
        Bin::Wallet,
        &["address", "find", "--alias", alias.as_ref()],
        Some(10)
    )?;
    let (unread, matched) = find.exp_regex("Found address .*")?;
    let address_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let address = Address::from_str(address_str).map_err(|e| {
        eyre!(format!(
            "Address: {} parsed from {}, Error: {}\n\nOutput: {}",
            address_str, matched, e, unread
        ))
    })?;
    println!("Found {}", address);
    Ok(address)
}

/// Find the address of the node's RPC endpoint.
pub fn get_actor_rpc(test: &Test, who: &Who) -> String {
    let base_dir = test.get_base_dir(who);
    let tendermint_mode = match who {
        Who::NonValidator => TendermintMode::Full,
        Who::Validator(_) => TendermintMode::Validator,
    };
    let config =
        Config::load(&base_dir, &test.net.chain_id, Some(tendermint_mode));
    config.ledger.tendermint.rpc_address.to_string()
}

/// Find the address of an account by its alias from the wallet
#[allow(dead_code)]
pub fn find_keypair(
    test: &Test,
    alias: impl AsRef<str>,
) -> Result<common::SecretKey> {
    let mut find = run!(
        test,
        Bin::Wallet,
        &[
            "key",
            "find",
            "--alias",
            alias.as_ref(),
            "--unsafe-show-secret"
        ],
        Some(10)
    )?;
    let (_unread, matched) = find.exp_regex("Public key: .*")?;
    let pk = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let (unread, matched) = find.exp_regex("Secret key: .*")?;
    let sk = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let key = format!("{}{}", sk, pk);
    common::SecretKey::from_str(&key).map_err(|e| {
        eyre!(format!(
            "Key: {} parsed from {}, Error: {}\n\nOutput: {}",
            key, matched, e, unread
        ))
    })
}

/// Find the address of an account by its alias from the wallet
pub fn find_voting_power(
    test: &Test,
    alias: impl AsRef<str>,
    ledger_address: &str,
) -> Result<u64> {
    let mut find = run!(
        test,
        Bin::Client,
        &[
            "voting-power",
            "--validator",
            alias.as_ref(),
            "--ledger-address",
            ledger_address
        ],
        Some(10)
    )?;
    let (unread, matched) = find.exp_regex("voting power: .*")?;
    let voting_power_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    u64::from_str(voting_power_str).map_err(|e| {
        eyre!(format!(
            "Voting power: {} parsed from {}, Error: {}\n\nOutput: {}",
            voting_power_str, matched, e, unread
        ))
    })
}

/// Get the last committed epoch.
pub fn get_epoch(test: &Test, ledger_address: &str) -> Result<Epoch> {
    let mut find = run!(
        test,
        Bin::Client,
        &["epoch", "--ledger-address", ledger_address],
        Some(10)
    )?;
    let (unread, matched) = find.exp_regex("Last committed epoch: .*")?;
    let epoch_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let epoch = u64::from_str(epoch_str).map_err(|e| {
        eyre!(format!(
            "Epoch: {} parsed from {}, Error: {}\n\nOutput: {}",
            epoch_str, matched, e, unread
        ))
    })?;
    Ok(Epoch(epoch))
}

/// Get the last committed block height.
pub fn get_height(test: &Test, ledger_address: &str) -> Result<u64> {
    let mut find = run!(
        test,
        Bin::Client,
        &["block", "--ledger-address", ledger_address],
        Some(10)
    )?;
    let (unread, matched) = find.exp_regex("Last committed block ID: .*")?;
    // Expected `matched` string is e.g.:
    //
    // ```
    // Last committed block F10B5E77F972F68CA051D289474B6E75574B446BF713A7B7B71D7ECFC61A3B21, height: 4, time: 2022-10-20T10:52:28.828745Z
    // ```
    let height_str = strip_trailing_newline(&matched)
        .trim()
        // Find the height part ...
        .split_once("height: ")
        .unwrap()
        // ... take what's after it ...
        .1
        // ... find the next comma ...
        .rsplit_once(',')
        .unwrap()
        // ... and take what's before it.
        .0;
    u64::from_str(height_str).map_err(|e| {
        eyre!(format!(
            "Height parsing failed from {} trimmed from {}, Error: \
             {}\n\nUnread output: {}",
            height_str, matched, e, unread
        ))
    })
}

/// Sleep until the given height is reached or panic when time out is reached
/// before the height
pub fn wait_for_block_height(
    test: &Test,
    ledger_address: &str,
    height: u64,
    timeout_secs: u64,
) -> Result<()> {
    let start = Instant::now();
    let loop_timeout = Duration::new(timeout_secs, 0);
    loop {
        let current = get_height(test, ledger_address)?;
        if current >= height {
            break Ok(());
        }
        if Instant::now().duration_since(start) > loop_timeout {
            panic!("Timed out waiting for height {height}, current {current}");
        }
        sleep(1);
    }
}

/// Are the E2E tests be running in debug mode?
pub fn is_debug_mode() -> bool {
    match env::var(ENV_VAR_DEBUG) {
        Ok(val) => val.to_ascii_lowercase() != "false",
        _ => false,
    }
}

pub fn generate_bin_command(bin_name: &str, manifest_path: &Path) -> Command {
    let use_prebuilt_binaries = match env::var(ENV_VAR_USE_PREBUILT_BINARIES) {
        Ok(var) => var.to_ascii_lowercase() != "false",
        Err(_) => false,
    };

    // Allow to run in debug
    let run_debug = is_debug_mode();

    if !use_prebuilt_binaries {
        let build_cmd = CargoBuild::new()
            .package(APPS_PACKAGE)
            .manifest_path(manifest_path)
            // Explicitly disable dev, in case it's enabled when a test is
            // invoked
            .env("ANOMA_DEV", "false")
            .bin(bin_name);

        let build_cmd = if run_debug {
            build_cmd
        } else {
            // Use the same build settings as `make build-release`
            build_cmd.release()
        };

        let now = time::Instant::now();
        // ideally we would print the compile command here, but escargot doesn't
        // implement Display or Debug for CargoBuild
        println!(
            "\n{}: {}",
            "`cargo build` starting".underline().bright_blue(),
            bin_name
        );

        let command = build_cmd.run().unwrap();
        println!(
            "\n{}: {}ms",
            "`cargo build` finished after".underline().bright_blue(),
            now.elapsed().as_millis()
        );

        command.command()
    } else {
        let dir = if run_debug {
            format!("target/debug/{}", bin_name)
        } else {
            format!("target/release/{}", bin_name)
        };
        println!(
            "\n{}: {}",
            "Running prebuilt binaries from".underline().green(),
            dir
        );
        std::process::Command::new(dir)
    }
}

fn strip_trailing_newline(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input)
}

/// Sleep until the next epoch starts
pub fn epoch_sleep(
    test: &Test,
    ledger_address: &str,
    target: Option<Epoch>,
    timeout_secs: u64,
) -> Result<Epoch> {
    let old_epoch = get_epoch(test, ledger_address)?;
    let start = Instant::now();
    let loop_timeout = Duration::new(timeout_secs, 0);
    loop {
        if Instant::now().duration_since(start) > loop_timeout {
            panic!("Timed out waiting for the next epoch");
        }
        let epoch = get_epoch(test, ledger_address)?;
        if let Some(target) = target {
            if epoch == target {
                break Ok(epoch);
            } else if epoch > target {
                panic!("Missed the target epoch {}", target);
            }
        } else if epoch > old_epoch {
            break Ok(epoch);
        }
        sleep(10);
    }
}
