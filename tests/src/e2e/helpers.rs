//! E2E test helpers

use std::future::Future;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, time};

use borsh::BorshDeserialize;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use data_encoding::HEXLOWER;
use escargot::CargoBuild;
use eyre::eyre;
use namada::ledger::queries::{Rpc, RPC};
use namada::tendermint_rpc::HttpClient;
use namada::token;
use namada::types::address::Address;
use namada::types::key::*;
use namada::types::storage::Epoch;
use namada_apps::config::genesis::chain::DeriveEstablishedAddress;
use namada_apps::config::genesis::templates;
use namada_apps::config::utils::convert_tm_addr_to_socket_addr;
use namada_apps::config::{Config, TendermintMode};
use namada_core::types::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_sdk::wallet::fs::FsWalletUtils;
use namada_sdk::wallet::Wallet;

use super::setup::{
    self, sleep, NamadaBgCmd, NamadaCmd, Test, ENV_VAR_DEBUG,
    ENV_VAR_USE_PREBUILT_BINARIES,
};
use crate::e2e::setup::{Bin, Who, APPS_PACKAGE};
use crate::strings::{LEDGER_STARTED, TX_ACCEPTED, TX_APPLIED_SUCCESS};
use crate::{run, run_as};

/// Instantiate a new [`HttpClient`] to perform RPC requests with.
#[allow(dead_code)]
pub async fn rpc_client_do<'fut, 'usr, U, A, F, R>(
    ledger_address: &str,
    user_data: U,
    mut action: A,
) -> R
where
    'usr: 'fut,
    U: 'usr,
    A: FnMut(Rpc, HttpClient, U) -> F,
    F: Future<Output = R> + 'fut,
{
    let client =
        HttpClient::new(ledger_address).expect("Invalid ledger address");
    action(RPC, client, user_data).await
}

/// Sets up a test chain with a single validator node running in the background,
/// and returns the [`Test`] handle and [`NamadaBgCmd`] for the validator node.
/// It blocks until the node is ready to receive RPC requests from
/// `namadac`.
#[allow(dead_code)]
pub fn setup_single_node_test() -> Result<(Test, NamadaBgCmd)> {
    let test = setup::single_node_net()?;
    run_single_node_test_from(test)
}

/// Same as [`setup_single_node_test`], but use a pre-existing test directory.
pub fn run_single_node_test_from(test: Test) -> Result<(Test, NamadaBgCmd)> {
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, &["ledger"], Some(40))?;
    ledger.exp_string(LEDGER_STARTED)?;
    // TODO(namada#867): we only need to wait until the RPC server is available,
    // not necessarily for a block to be committed
    // ledger.exp_string("Starting RPC HTTP server on")?;
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;
    Ok((test, ledger.background()))
}

/// Initialize an established account.
#[allow(dead_code)]
pub fn init_established_account(
    test: &Test,
    rpc_addr: &str,
    source_alias: &str,
    key_alias: &str,
    established_alias: &str,
) -> Result<()> {
    let init_account_args = vec![
        "init-account",
        "--source",
        source_alias,
        "--public-key",
        key_alias,
        "--alias",
        established_alias,
        "--ledger-address",
        rpc_addr,
    ];
    let mut cmd = run!(test, Bin::Client, init_account_args, Some(40))?;
    cmd.exp_string(TX_ACCEPTED)?;
    cmd.exp_string(TX_APPLIED_SUCCESS)?;
    cmd.assert_success();
    Ok(())
}

/// Find the address of an account by its alias from the wallet
pub fn find_address(test: &Test, alias: impl AsRef<str>) -> Result<Address> {
    let mut find = run!(
        test,
        Bin::Wallet,
        &["find", "--addr", "--alias", alias.as_ref()],
        Some(10)
    )?;
    find.exp_string("Found transparent address:")?;
    let (unread, matched) = find.exp_regex("\".*\": .*")?;
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

/// Find the balance of specific token for an account.
#[allow(dead_code)]
pub fn find_balance(
    test: &Test,
    node: Who,
    token: &Address,
    owner: &Address,
) -> Result<token::Amount> {
    let ledger_address = get_actor_rpc(test, node);
    let balance_key = token::storage_key::balance_key(token, owner);
    let mut bytes = run!(
        test,
        Bin::Client,
        &[
            "query-bytes",
            "--storage-key",
            &balance_key.to_string(),
            "--ledger-address",
            &ledger_address,
        ],
        Some(10)
    )?;
    let (_, matched) = bytes.exp_regex("Found data: 0x.*")?;
    let data_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1[2..]
        .to_string();
    let amount =
        token::Amount::try_from_slice(&HEXLOWER.decode(data_str.as_bytes())?)?;
    bytes.assert_success();
    Ok(amount)
}

/// Find the address of the node's RPC endpoint.
pub fn get_actor_rpc(test: &Test, who: Who) -> String {
    let base_dir = test.get_base_dir(who);
    let tendermint_mode = match who {
        Who::NonValidator => TendermintMode::Full,
        Who::Validator(_) => TendermintMode::Validator,
    };
    let config =
        Config::load(base_dir, &test.net.chain_id, Some(tendermint_mode));
    let socket_addr =
        convert_tm_addr_to_socket_addr(&config.ledger.cometbft.rpc.laddr);
    format!("{}:{}", socket_addr.ip(), socket_addr.port())
}

/// Get some nodes's wallet.
pub fn get_node_wallet(test: &Test, who: Who) -> Wallet<FsWalletUtils> {
    let wallet_store_dir =
        test.get_base_dir(who).join(test.net.chain_id.as_str());
    let mut wallet = FsWalletUtils::new(wallet_store_dir);
    wallet.load().expect("Failed to load wallet");
    wallet
}

/// Get the public key of the validator
pub fn get_validator_pk(test: &Test, who: Who) -> Option<common::PublicKey> {
    let index = match who {
        Who::NonValidator => return None,
        Who::Validator(i) => i,
    };
    let mut wallet = get_node_wallet(test, who);
    let sk = wallet
        .find_secret_key(format!("validator-{index}-balance-key"), None)
        .ok()?;
    Some(sk.ref_to())
}

/// Get a pregenesis wallet.
pub fn get_pregenesis_wallet<P: AsRef<Path>>(
    base_dir_path: P,
) -> Wallet<FsWalletUtils> {
    let mut wallet_store_dir = base_dir_path.as_ref().to_path_buf();
    wallet_store_dir.push("pre-genesis");

    let mut wallet = FsWalletUtils::new(wallet_store_dir);
    wallet.load().expect("Failed to load wallet");

    wallet
}

/// Get a pregenesis public key.
pub fn get_pregenesis_pk<P: AsRef<Path>>(
    alias: &str,
    base_dir_path: P,
) -> Option<common::PublicKey> {
    let mut wallet = get_pregenesis_wallet(base_dir_path);
    let sk = wallet.find_secret_key(alias, None).ok()?;
    Some(sk.ref_to())
}

/// Get a pregenesis public key.
pub fn get_established_addr_from_pregenesis<P: AsRef<Path>>(
    alias: &str,
    base_dir_path: P,
    genesis: &templates::All<templates::Unvalidated>,
) -> Option<Address> {
    let pk = get_pregenesis_pk(alias, base_dir_path)?;
    let established_accounts =
        genesis.transactions.established_account.as_ref()?;
    let acct = established_accounts.iter().find(|&acct| {
        acct.public_keys.len() == 1 && acct.public_keys[0].raw == pk
    })?;
    Some(acct.derive_address())
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
            "find",
            "--keys",
            "--alias",
            alias.as_ref(),
            "--decrypt",
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

/// Find the bonded stake of an account by its alias from the wallet
pub fn find_bonded_stake(
    test: &Test,
    alias: impl AsRef<str>,
    ledger_address: &str,
) -> Result<token::Amount> {
    let mut find = run!(
        test,
        Bin::Client,
        &[
            "bonded-stake",
            "--validator",
            alias.as_ref(),
            "--node",
            ledger_address
        ],
        Some(10)
    )?;
    let (unread, matched) = find.exp_regex("Bonded stake of validator .*")?;
    let bonded_stake_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    token::Amount::from_str(bonded_stake_str, NATIVE_MAX_DECIMAL_PLACES)
        .map_err(|e| {
            eyre!(format!(
                "Bonded stake: {} parsed from {}, Error: {}\n\nOutput: {}",
                bonded_stake_str, matched, e, unread
            ))
        })
}

/// Get the last committed epoch.
pub fn get_epoch(test: &Test, ledger_address: &str) -> Result<Epoch> {
    let mut find = run!(
        test,
        Bin::Client,
        &["epoch", "--node", ledger_address],
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
        &["block", "--node", ledger_address],
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
            return Err(eyre!(
                "Timed out waiting for height {height}, current {current}"
            ));
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

pub(crate) fn strip_trailing_newline(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input)
}

/// Sleep until the next epoch starts
pub fn epoch_sleep(
    test: &Test,
    ledger_address: &str,
    timeout_secs: u64,
) -> Result<Epoch> {
    let mut find = run!(
        test,
        Bin::Client,
        &["utils", "epoch-sleep", "--node", ledger_address],
        Some(timeout_secs)
    )?;
    parse_reached_epoch(&mut find)
}

pub fn parse_reached_epoch(find: &mut NamadaCmd) -> Result<Epoch> {
    let (unread, matched) = find.exp_regex("Reached epoch .*")?;
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

/// Wait for txs and VPs WASM compilations to finish. This is useful to avoid a
/// timeout when submitting a first tx.
pub fn wait_for_wasm_pre_compile(ledger: &mut NamadaCmd) -> Result<()> {
    ledger.exp_string("Finished compiling all")?;
    ledger.exp_string("Finished compiling all")?;
    Ok(())
}

/// Convert epoch `min_duration` in seconds to `epochs_per_year` genesis
/// parameter.
pub fn epochs_per_year_from_min_duration(min_duration: u64) -> u64 {
    60 * 60 * 24 * 365 / min_duration
}
