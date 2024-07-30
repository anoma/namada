use std::ffi::OsStr;
use std::fmt::Display;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, thread, time};

use assert_cmd::assert::OutputAssertExt;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use expectrl::process::unix::{PtyStream, UnixProcess};
use expectrl::session::Session;
use expectrl::stream::log::LogStream;
use expectrl::{ControlCode, Eof, WaitStatus};
use eyre::eyre;
use itertools::{Either, Itertools};
use namada_apps_lib::cli::context::ENV_VAR_CHAIN_ID;
use namada_apps_lib::client::utils::{
    self, validator_pre_genesis_dir, validator_pre_genesis_txs_file,
};
use namada_apps_lib::config::genesis::utils::read_toml;
use namada_apps_lib::config::genesis::{
    templates, transactions, GenesisAddress,
};
use namada_apps_lib::config::{ethereum_bridge, genesis, Config};
use namada_apps_lib::{config, wallet};
use namada_core::address::Address;
use namada_core::collections::HashMap;
use namada_core::key::{RefTo, SchemeType};
use namada_core::string_encoding::StringEncoded;
use namada_core::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_sdk::chain::ChainId;
use namada_sdk::wallet::alias::Alias;
use namada_tx_prelude::token;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::Rng;
use tempfile::{tempdir, tempdir_in, TempDir};

use crate::e2e::helpers::{
    find_gaia_address, generate_bin_command, make_hermes_config,
    update_gaia_config,
};

/// For `color_eyre::install`, which fails if called more than once in the same
/// process
pub static INIT: Once = Once::new();

pub const APPS_PACKAGE: &str = "namada_apps_lib";

/// Env. var for running E2E tests in debug mode
pub const ENV_VAR_DEBUG: &str = "NAMADA_E2E_DEBUG";

/// Env. var for keeping temporary files created by the E2E tests
pub const ENV_VAR_KEEP_TEMP: &str = "NAMADA_E2E_KEEP_TEMP";

/// Env. var for temporary path
const ENV_VAR_TEMP_PATH: &str = "NAMADA_E2E_TEMP_PATH";

/// Env. var to use a set of prebuilt binaries. This variable holds the path to
/// a folder.
pub const ENV_VAR_USE_PREBUILT_BINARIES: &str =
    "NAMADA_E2E_USE_PREBUILT_BINARIES";

/// The E2E tests genesis config source.
/// This file must contain a single validator with alias "validator-0".
/// To add more validators, use the [`set_validators`] function in the call to
/// setup the [`network`].
#[allow(dead_code)]
pub const SINGLE_NODE_NET_GENESIS: &str = "genesis/localnet";
/// An E2E test network.
#[derive(Debug, Clone)]
pub struct Network {
    pub chain_id: ChainId,
}

/// Offset the ports used in the network configuration to avoid shared resources
pub const ANOTHER_CHAIN_PORT_OFFSET: u16 = 1000;

/// Default functions for offsetting ports when
/// adding multiple validators to a network
pub fn default_port_offset(ix: u8) -> u16 {
    6 * ix as u16
}

/// Update the config of some node `who`.
pub fn update_actor_config<F>(
    test: &Test,
    chain_id: &ChainId,
    who: Who,
    update: F,
) where
    F: FnOnce(&mut Config),
{
    let validator_base_dir = test.get_base_dir(who);
    let mut validator_config =
        Config::load(&validator_base_dir, chain_id, None);
    update(&mut validator_config);
    validator_config
        .write(&validator_base_dir, chain_id, true)
        .unwrap();
}

/// Configure validator p2p settings to allow duplicate ips
pub fn allow_duplicate_ips(test: &Test, chain_id: &ChainId, who: Who) {
    update_actor_config(test, chain_id, who, |config| {
        config.ledger.cometbft.p2p.allow_duplicate_ip = true;
    });
}

/// Configures the Ethereum bridge mode of `who`. This should be done before
/// `who` starts running.
pub fn set_ethereum_bridge_mode(
    test: &Test,
    chain_id: &ChainId,
    who: Who,
    mode: ethereum_bridge::ledger::Mode,
    rpc_endpoint: Option<&str>,
) {
    update_actor_config(test, chain_id, who, |config| {
        config.ledger.ethereum_bridge.mode = mode;
        if let Some(addr) = rpc_endpoint {
            config.ledger.ethereum_bridge.oracle_rpc_endpoint = addr.into();
        }
    });
}

/// Set `num` validators to the genesis config. Note that called from inside
/// the [`network`]'s first argument's closure, e.g. `set_validators(2, _)` will
/// configure a network with 2 validators.
///
/// INVARIANT: Do not call this function more than once on the same config.
pub fn set_validators<F>(
    num: u8,
    mut genesis: templates::All<templates::Unvalidated>,
    base_dir: &Path,
    port_offset: F,
) -> templates::All<templates::Unvalidated>
where
    F: Fn(u8) -> u16,
{
    //  for each validator:
    // - generate a balance key
    // - assign balance to the key
    // - invoke `init-genesis-validator` signed by balance key to generate
    //   validator pre-genesis wallet signed genesis txs
    // - add txs to genesis templates
    let wallet_path = base_dir.join("pre-genesis");
    for val in 0..num {
        // init validator dir
        let validator_alias = format!("validator-{val}");
        let pre_genesis_path =
            validator_pre_genesis_dir(base_dir, &validator_alias);
        let pre_genesis_tx_path =
            validator_pre_genesis_txs_file(&pre_genesis_path);
        std::fs::create_dir(&pre_genesis_path).unwrap_or_else(|err| {
            panic!(
                "Failed to create the pre-genesis path for {validator_alias}: \
                 {err}"
            );
        });
        let pre_genesis_tx_path_str = pre_genesis_tx_path.to_string_lossy();
        // generate a balance key
        let mut wallet = wallet::load(&wallet_path)
            .expect("Could not locate pre-genesis wallet used for e2e tests.");
        let alias = format!("validator-{val}-balance-key");
        let (alias, sk) = wallet
            .gen_store_secret_key(
                SchemeType::Ed25519,
                Some(alias),
                true,
                None,
                &mut OsRng,
            )
            .unwrap_or_else(|| {
                panic!("Could not generate new key for validator-{}", val)
            });
        println!("alias: {}, pk: {}", alias, sk.ref_to());
        let validator_address = {
            use namada_apps_lib::config::genesis::chain::DeriveEstablishedAddress;
            let pre_genesis_tx = transactions::EstablishedAccountTx {
                vp: "vp_user".to_string(),
                threshold: 1,
                public_keys: vec![StringEncoded::new(sk.ref_to())],
            };
            let address = pre_genesis_tx.derive_established_address();
            println!(
                "Initializing validator {validator_alias} with address \
                 {address}"
            );
            address
        };
        wallet.insert_address(
            validator_alias.clone(),
            Address::Established(validator_address.clone()),
            true,
        );
        wallet::save(&wallet).unwrap();
        // invoke `init-genesis-established-account` to generate a new
        // established account with the generated balance key
        let args = vec![
            "utils",
            "init-genesis-established-account",
            "--aliases",
            &alias,
            "--path",
            &pre_genesis_tx_path_str,
        ];
        let mut init_established_account = run_cmd(
            Bin::Client,
            args,
            Some(5),
            &working_dir(),
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )
        .unwrap();
        init_established_account.assert_success();
        // assign balance to the implicit addr (i.e. pubkey) + established acc
        let nam_balances = genesis
            .balances
            .token
            .get_mut(&Alias::from_str("nam").expect("Infallible"))
            .expect("NAM balances should exist in pre-genesis wallet already");
        nam_balances.0.insert(
            GenesisAddress::PublicKey(StringEncoded::new(sk.ref_to())),
            token::DenominatedAmount::new(
                token::Amount::from_uint(1000000, NATIVE_MAX_DECIMAL_PLACES)
                    .unwrap(),
                NATIVE_MAX_DECIMAL_PLACES.into(),
            ),
        );
        nam_balances.0.insert(
            GenesisAddress::EstablishedAddress(validator_address.clone()),
            token::DenominatedAmount::new(
                token::Amount::from_uint(2000000, NATIVE_MAX_DECIMAL_PLACES)
                    .unwrap(),
                NATIVE_MAX_DECIMAL_PLACES.into(),
            ),
        );
        // invoke `init-genesis-validator` to promote the generated established
        // account to a validator account
        let net_addr = format!("127.0.0.1:{}", 27656 + port_offset(val));
        let validator_address_str = validator_address.to_string();
        let args = vec![
            "utils",
            "init-genesis-validator",
            "--alias",
            &validator_alias,
            "--address",
            &validator_address_str,
            "--path",
            &pre_genesis_tx_path_str,
            "--net-address",
            &net_addr,
            "--commission-rate",
            "0.05",
            "--max-commission-rate-change",
            "0.01",
            "--email",
            "null@null.net",
            "--self-bond-amount",
            "100000",
            "--unsafe-dont-encrypt",
        ];
        let mut init_genesis_validator = run_cmd(
            Bin::Client,
            args,
            Some(5),
            &working_dir(),
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )
        .unwrap();
        init_genesis_validator.assert_success();
        // invoke `sign-genesis-txs` to sign the validator txs with
        // the generated balance key
        let args = vec![
            "utils",
            "sign-genesis-txs",
            "--alias",
            &validator_alias,
            "--path",
            &pre_genesis_tx_path_str,
            "--output",
            &pre_genesis_tx_path_str,
        ];
        let mut sign_pre_genesis_txs = run_cmd(
            Bin::Client,
            args,
            Some(15),
            &working_dir(),
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )
        .unwrap();
        sign_pre_genesis_txs.assert_success();
        // initialize the validator
        // add generated txs to genesis
        let pre_genesis_txs =
            read_toml(&pre_genesis_tx_path, "transactions.toml").unwrap();
        genesis.transactions.merge(pre_genesis_txs);
        // move validators generated files to their own base dir
        let validator_base_dir = base_dir
            .join(utils::NET_ACCOUNTS_DIR)
            .join(&validator_alias);
        let src_path = validator_pre_genesis_dir(base_dir, &validator_alias);
        let dest_path =
            validator_pre_genesis_dir(&validator_base_dir, &validator_alias);
        println!(
            "{} for {validator_alias} from {} to {}.",
            "Copying pre-genesis validator-wallet".yellow(),
            src_path.to_string_lossy(),
            dest_path.to_string_lossy(),
        );
        fs::create_dir_all(&dest_path).unwrap();
        fs::rename(src_path, dest_path).unwrap();
    }
    genesis
}

/// Setup a network with a single genesis validator node.
pub fn single_node_net() -> Result<Test> {
    network(
        |genesis, base_dir: &_| set_validators(1, genesis, base_dir, |_| 0u16),
        None,
    )
}

/// Setup a configurable network.
pub fn network(
    mut update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
        &Path,
    ) -> templates::All<templates::Unvalidated>,
    consensus_timeout_commit: Option<&'static str>,
) -> Result<Test> {
    INIT.call_once(|| {
        if let Err(err) = color_eyre::install() {
            eprintln!("Failed setting up colorful error reports {}", err);
        }
    });
    let working_dir = working_dir();
    let test_dir = TestDir::new();

    // Open the source genesis file templates
    let templates_dir = working_dir.join("genesis").join("localnet");
    println!(
        "{} {}.",
        "Loading genesis templates from".yellow(),
        templates_dir.to_string_lossy()
    );
    let mut templates =
        genesis::templates::All::read_toml_files(&templates_dir)
            .unwrap_or_else(|_| {
                panic!(
                    "Missing genesis templates files at {}",
                    templates_dir.to_string_lossy()
                )
            });
    // clear existing validator txs and bonds from genesis
    templates.transactions.validator_account = None;
    templates.transactions.bond = None;

    // Update the templates as needed
    templates.parameters.parameters.vp_allowlist =
        Some(get_all_wasms_hashes(&working_dir, Some("vp_")));
    templates.parameters.parameters.tx_allowlist =
        Some(get_all_wasms_hashes(&working_dir, Some("tx_")));
    // Copy the main wallet from templates dir into the base dir.
    {
        let base_dir = test_dir.path();
        let src_path =
            wallet::wallet_file(templates_dir.join("src").join("pre-genesis"));
        let dest_dir = base_dir.join("pre-genesis");
        let dest_path = wallet::wallet_file(&dest_dir);
        println!(
            "{} from {} to {}.",
            "Copying main pre-genesis wallet into a default non-validator \
             base dir"
                .yellow(),
            src_path.to_string_lossy(),
            dest_path.to_string_lossy(),
        );
        fs::create_dir_all(&dest_dir)?;
        fs::copy(&src_path, &dest_path)?;
    }

    // Run the provided function on it
    let templates = update_genesis(templates, test_dir.path());

    // Write the updated genesis templates to the test dir
    let updated_templates_dir = test_dir.path().join("templates");
    create_dir_all(&updated_templates_dir)?;
    println!(
        "{} {}.",
        "Writing updated genesis templates to".yellow(),
        updated_templates_dir.to_string_lossy()
    );
    templates.write_toml_files(&updated_templates_dir)?;

    // Run `init-network` on the updated templates to generate the finalized
    // genesis config and addresses and update WASM checksums
    let templates_path = updated_templates_dir.to_string_lossy().into_owned();
    println!("{}", "Finalizing network from genesis templates.".yellow());
    let checksums_path = working_dir
        .join("wasm/checksums.json")
        .to_string_lossy()
        .into_owned();
    let genesis_dir = test_dir.path().join("genesis");
    let archive_dir = genesis_dir.to_string_lossy().to_string();
    let mut args = vec![
        "utils",
        "init-network",
        "--templates-path",
        &templates_path,
        "--chain-prefix",
        "e2e-test",
        "--wasm-checksums-path",
        &checksums_path,
        "--genesis-time",
        namada_core::time::test_utils::GENESIS_TIME,
        "--archive-dir",
        &archive_dir,
    ];
    if let Some(consensus_timeout_commit) = consensus_timeout_commit {
        args.push("--consensus-timeout-commit");
        args.push(consensus_timeout_commit)
    }
    let mut init_network = run_cmd(
        Bin::Client,
        args,
        Some(15),
        &working_dir,
        &genesis_dir,
        format!("{}:{}", std::file!(), std::line!()),
    )?;

    // Get the generated chain_id from result of the last command
    let (unread, matched) =
        init_network.exp_regex(r"Derived chain ID: .*\n")?;
    let chain_id_raw =
        matched.trim().split_once("Derived chain ID: ").unwrap().1;
    let chain_id = ChainId::from_str(chain_id_raw.trim())?;
    println!("'init-network' unread output: {}", unread);
    let net = Network { chain_id };
    init_network.assert_success();

    drop(init_network);

    // Set the network archive dir to make it available for `join-network`
    // commands
    std::env::set_var(
        namada_apps_lib::client::utils::ENV_VAR_NETWORK_CONFIGS_DIR,
        archive_dir,
    );

    let validator_aliases = templates
        .transactions
        .validator_account
        .as_ref()
        .map(|txs| {
            Either::Right(
                // hacky way to get all the validator indexes :-)
                (0..txs.len()).map(|index| format!("validator-{index}")),
            )
        })
        .unwrap_or(Either::Left([].into_iter()));

    // Setup a dir for every validator and non-validator using their
    // pre-genesis wallets
    for alias in validator_aliases {
        let validator_base_dir =
            test_dir.path().join(utils::NET_ACCOUNTS_DIR).join(&alias);

        // Copy the main wallet from templates dir into validator's base dir.
        {
            let dest_dir = validator_base_dir.join("pre-genesis");
            let dest_path = wallet::wallet_file(&dest_dir);
            let base_dir = test_dir.path();
            let src_dir = base_dir.join("pre-genesis");
            let src_path = wallet::wallet_file(&src_dir);
            println!(
                "{} for {alias} from {} to {}.",
                "Copying main pre-genesis wallet".yellow(),
                src_path.to_string_lossy(),
                dest_path.to_string_lossy(),
            );
            fs::create_dir_all(&dest_dir)?;
            fs::copy(&src_path, &dest_path)?;
        }
        println!("{} {}.", "Joining network with ".yellow(), alias);
        let validator_base_dir =
            test_dir.path().join(utils::NET_ACCOUNTS_DIR).join(&alias);
        let mut join_network = run_cmd(
            Bin::Client,
            [
                "utils",
                "join-network",
                "--add-persistent-peers",
                "--chain-id",
                net.chain_id.as_str(),
                "--genesis-validator",
                &alias,
                "--dont-prefetch-wasm",
            ],
            Some(5),
            &working_dir,
            &validator_base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )?;
        join_network.exp_string("Successfully configured for chain")?;
        join_network.assert_success();
        copy_wasm_to_chain_dir(
            &working_dir,
            &validator_base_dir,
            &net.chain_id,
        );
    }

    // Setup a dir for a non-validator using the pre-genesis wallet
    {
        let base_dir = test_dir.path();
        println!(
            "{}.",
            "Joining network with a default non-validator node".yellow()
        );
        let mut join_network = run_cmd(
            Bin::Client,
            [
                "utils",
                "join-network",
                "--add-persistent-peers",
                "--chain-id",
                net.chain_id.as_str(),
                "--dont-prefetch-wasm",
            ],
            Some(5),
            &working_dir,
            base_dir,
            format!("{}:{}", std::file!(), std::line!()),
        )?;
        join_network.exp_string("Successfully configured for chain")?;
        join_network.assert_success();
    }

    copy_wasm_to_chain_dir(&working_dir, test_dir.path(), &net.chain_id);

    // Set the chain id
    std::env::set_var(ENV_VAR_CHAIN_ID, net.chain_id.to_string());

    Ok(Test {
        working_dir,
        test_dir,
        net,
        async_runtime: Default::default(),
    })
}

/// Namada binaries
#[derive(Debug)]
#[allow(dead_code)]
pub enum Bin {
    Node,
    Client,
    Wallet,
    Relayer,
}

#[derive(Debug)]
pub struct Test {
    /// The dir where the tests run from, usually the repo root dir
    pub working_dir: PathBuf,
    /// Temporary test directory is used as the default base-dir for running
    /// Namada cmds
    pub test_dir: TestDir,
    pub net: Network,
    pub async_runtime: LazyAsyncRuntime,
}

#[derive(Debug)]
pub struct TestDir(Either<TempDir, PathBuf>);

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        match &self.0 {
            Either::Left(temp_dir) => temp_dir.path(),
            Either::Right(path) => path.as_ref(),
        }
    }
}

impl TestDir {
    /// Setup a `TestDir` in a temporary directory. The directory will be
    /// automatically deleted after the test run, unless `ENV_VAR_KEEP_TEMP`
    /// is set to `true`.
    pub fn new() -> Self {
        let keep_temp = match env::var(ENV_VAR_KEEP_TEMP) {
            Ok(val) => val.to_ascii_lowercase() != "false",
            _ => false,
        };

        let path_to_tmp = env::var(ENV_VAR_TEMP_PATH);
        let temp_dir: TempDir = match path_to_tmp {
            Ok(path) => tempdir_in(path),
            _ => tempdir(),
        }
        .unwrap();
        if keep_temp {
            let path = temp_dir.into_path();
            println!(
                "{}: \"{}\"",
                "Keeping test directory at".underline().yellow(),
                path.to_string_lossy()
            );
            Self(Either::Right(path))
        } else {
            Self(Either::Left(temp_dir))
        }
    }

    /// Get the [`Path`] to the test directory.
    pub fn path(&self) -> &Path {
        self.as_ref()
    }
}

impl Drop for Test {
    fn drop(&mut self) {
        if let Either::Right(path) = &self.test_dir.0 {
            println!(
                "{}: \"{}\"",
                "Keeping test directory at".underline().yellow(),
                path.to_string_lossy()
            );
        }
    }
}

#[derive(Debug)]
pub struct LazyAsyncRuntime(Lazy<tokio::runtime::Runtime>);

impl Default for LazyAsyncRuntime {
    fn default() -> Self {
        Self(Lazy::new(|| tokio::runtime::Runtime::new().unwrap()))
    }
}

// Internally used macros only for attaching source locations to commands
#[macro_use]
mod macros {
    /// Get an [`NamadaCmd`] to run an Namada binary. By default, these will run
    /// in release mode. This can be disabled by setting environment
    /// variable `NAMADA_E2E_DEBUG=true`.
    /// On [`NamadaCmd`], you can then call e.g. `exp_string` or `exp_regex` to
    /// look for an expected output from the command.
    ///
    /// Arguments:
    /// - the test [`super::Test`]
    /// - which binary to run [`super::Bin`]
    /// - arguments, which implement `IntoIterator<Item = &str>`, e.g.
    ///   `&["cmd"]`
    /// - optional timeout in seconds `Option<u64>`
    ///
    /// This is a helper macro that adds file and line location to the
    /// [`super::run_cmd`] function call.
    #[macro_export]
    macro_rules! run {
        ($test:expr, $bin:expr, $args:expr, $timeout_sec:expr $(,)?) => {{
            // The file and line will expand to the location that invoked
            // `run_cmd!`
            let loc = format!("{}:{}", std::file!(), std::line!());
            $test.run_cmd($bin, $args, $timeout_sec, loc)
        }};
    }

    /// Get an [`NamadaCmd`] to run an Namada binary. By default, these will run
    /// in release mode. This can be disabled by setting environment
    /// variable `NAMADA_E2E_DEBUG=true`.
    /// On [`NamadaCmd`], you can then call e.g. `exp_string` or `exp_regex` to
    /// look for an expected output from the command.
    ///
    /// Arguments:
    /// - the test [`super::Test`]
    /// - who to run this command as [`super::Who`]
    /// - which binary to run [`super::Bin`]
    /// - arguments, which implement `IntoIterator<item = &str>`, e.g.
    ///   `&["cmd"]`
    /// - optional timeout in seconds `Option<u64>`
    ///
    /// This is a helper macro that adds file and line location to the
    /// [`super::run_cmd`] function call.
    #[macro_export]
    macro_rules! run_as {
        (
            $test:expr,
            $who:expr,
            $bin:expr,
            $args:expr,
            $timeout_sec:expr $(,)?
        ) => {{
            // The file and line will expand to the location that invoked
            // `run_cmd!`
            let loc = format!("{}:{}", std::file!(), std::line!());
            $test.run_cmd_as($who, $bin, $args, $timeout_sec, loc)
        }};
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Who {
    // A non-validator
    NonValidator,
    // Genesis validator with a given index, starting from `0`
    Validator(u64),
}

impl Test {
    /// Use the `run!` macro instead of calling this method directly to get
    /// automatic source location reporting.
    ///
    /// Get an [`NamadaCmd`] to run an Namada binary. By default, these will run
    /// in release mode. This can be disabled by setting environment
    /// variable `NAMADA_E2E_DEBUG=true`.
    pub fn run_cmd<I, S>(
        &self,
        bin: Bin,
        args: I,
        timeout_sec: Option<u64>,
        loc: String,
    ) -> Result<NamadaCmd>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_cmd_as(Who::NonValidator, bin, args, timeout_sec, loc)
    }

    /// Use the `run!` macro instead of calling this method directly to get
    /// automatic source location reporting.
    ///
    /// Get an [`NamadaCmd`] to run an Namada binary. By default, these will run
    /// in release mode. This can be disabled by setting environment
    /// variable `NAMADA_E2E_DEBUG=true`.
    pub fn run_cmd_as<I, S>(
        &self,
        who: Who,
        bin: Bin,
        args: I,
        timeout_sec: Option<u64>,
        loc: String,
    ) -> Result<NamadaCmd>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let base_dir = self.get_base_dir(who);
        run_cmd(bin, args, timeout_sec, &self.working_dir, base_dir, loc)
    }

    pub fn get_base_dir(&self, who: Who) -> PathBuf {
        match who {
            Who::NonValidator => self.test_dir.path().to_owned(),
            Who::Validator(index) => self
                .test_dir
                .path()
                .join(utils::NET_ACCOUNTS_DIR)
                .join(format!("validator-{}", index)),
        }
    }

    pub fn get_chain_dir(&self, who: Who) -> PathBuf {
        self.get_base_dir(who).join(self.net.chain_id.as_str())
    }

    pub fn get_cometbft_home(&self, who: Who) -> PathBuf {
        self.get_chain_dir(who)
            .join(namada_apps_lib::config::COMETBFT_DIR)
    }

    /// Get an async runtime.
    pub fn async_runtime(&self) -> &tokio::runtime::Runtime {
        Lazy::force(&self.async_runtime.0)
    }
}

/// A helper that should be ran on start of every e2e test case.
pub fn working_dir() -> PathBuf {
    let working_dir = fs::canonicalize("../..").unwrap();

    // Check that cometbft is either on $PATH or `COMETBFT` env var is set
    if std::env::var("COMETBFT").is_err() {
        Command::new("which")
            .arg("cometbft")
            .assert()
            .try_success()
            .expect(
                "The env variable COMETBFT must be set and point to a local \
                 build of the cometbft abci++ branch, or the cometbft binary \
                 must be on PATH",
            );
    }
    working_dir
}

/// A command under test
pub struct NamadaCmd {
    pub session: Session<UnixProcess, LogStream<PtyStream, File>>,
    pub cmd_str: String,
    pub log_path: PathBuf,
}

impl Display for NamadaCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\nLogs: {}",
            self.cmd_str,
            self.log_path.to_string_lossy()
        )
    }
}

/// A command under test running on a background thread
pub struct NamadaBgCmd {
    join_handle: std::thread::JoinHandle<NamadaCmd>,
    abort_send: std::sync::mpsc::Sender<()>,
}

impl NamadaBgCmd {
    /// Re-gain control of a background command (created with
    /// [`NamadaCmd::background()`]) to check its output.
    pub fn foreground(self) -> NamadaCmd {
        self.abort_send.send(()).unwrap();
        self.join_handle.join().unwrap()
    }
}

impl NamadaCmd {
    /// Keep reading the session's output in a background thread to prevent the
    /// buffer from filling up. Call [`NamadaBgCmd::foreground()`] on the
    /// returned [`NamadaBgCmd`] to stop the loop and return back the original
    /// command.
    pub fn background(self) -> NamadaBgCmd {
        let (abort_send, abort_recv) = std::sync::mpsc::channel();
        let join_handle = std::thread::spawn(move || {
            let mut cmd = self;
            loop {
                match abort_recv.try_recv() {
                    Ok(())
                    | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return cmd;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
                cmd.session.is_matched(Eof).unwrap();
            }
        });
        NamadaBgCmd {
            join_handle,
            abort_send,
        }
    }

    /// Assert that the process exited with success
    pub fn assert_success(&mut self) {
        // Make sure that there is no unread output first
        let _ = self.exp_eof().unwrap();

        let process = self.session.get_process();
        let status = process.wait().unwrap();
        assert_eq!(WaitStatus::Exited(process.pid(), 0), status);
    }

    /// Assert that the process exited with failure
    #[allow(dead_code)]
    pub fn assert_failure(&mut self) {
        // Make sure that there is no unread output first
        let _ = self.exp_eof().unwrap();

        let process = self.session.get_process();
        let status = process.wait().unwrap();
        assert_ne!(WaitStatus::Exited(process.pid(), 0), status);
    }

    /// Wait until provided string is seen on stdout of child process.
    /// Return the yet unread output (without the matched string)
    ///
    /// Wrapper over the inner `PtySession`'s functions with custom error
    /// reporting.
    pub fn exp_string(&mut self, needle: &str) -> Result<String> {
        let found = self
            .session
            .expect(needle)
            .map_err(|e| eyre!(format!("{}\n Needle: {}", e, needle)))?;
        if found.is_empty() {
            Err(eyre!(
                "Expected needle not found\nCommand: {}\n Needle: {}",
                self,
                needle
            ))
        } else {
            String::from_utf8(found.before().to_vec())
                .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))
        }
    }

    /// Wait until provided regex is seen on stdout of child process.
    /// Return a tuple:
    /// 1. the yet unread output
    /// 2. the matched regex
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting as well as converting bytes back to `String`.
    pub fn exp_regex(&mut self, regex: &str) -> Result<(String, String)> {
        let found = self
            .session
            .expect(expectrl::Regex(regex))
            .map_err(|e| eyre!(format!("{}", e)))?;
        if found.is_empty() {
            Err(eyre!(
                "Expected regex not found: {}\nCommand: {}",
                regex,
                self
            ))
        } else {
            let unread = String::from_utf8(found.before().to_vec())
                .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))?;
            let matched =
                String::from_utf8(found.matches().next().unwrap().to_vec())
                    .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))?;
            Ok((unread, matched))
        }
    }

    /// Wait until we see EOF (i.e. child process has terminated)
    /// Return all the yet unread output
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting.
    #[allow(dead_code)]
    pub fn exp_eof(&mut self) -> Result<String> {
        let found = self.session.expect(Eof).map_err(|e| eyre!("{}", e))?;
        if found.is_empty() {
            Err(eyre!("Expected EOF\nCommand: {}", self))
        } else {
            String::from_utf8(found.before().to_vec())
                .map_err(|e| eyre!(format!("Error: {}\nCommand: {}", e, self)))
        }
    }

    /// Send ctrl-c to to interrupt or terminate.
    pub fn interrupt(&mut self) -> Result<()> {
        self.send_control(ControlCode::EndOfText)
    }

    /// Send a control code to the running process and consume resulting output
    /// line (which is empty because echo is off)
    ///
    /// E.g. `send_control(ControlCode::EndOfText)` sends ctrl-c. Upper/smaller
    /// case does not matter.
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting.
    pub fn send_control(&mut self, c: ControlCode) -> Result<()> {
        self.session
            .send(c)
            .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))
    }

    /// send line to repl (and flush output) and then, if echo_on=true wait for
    /// the input to appear.
    /// Return: number of bytes written
    ///
    /// Wrapper over the inner `Session`'s functions with custom error
    /// reporting.
    pub fn send_line(&mut self, line: &str) -> Result<()> {
        self.session
            .send_line(line)
            .map_err(|e| eyre!("Error: {}\nCommand: {}", e, self))
    }
}

impl Drop for NamadaCmd {
    fn drop(&mut self) {
        // attempt to clean up the process
        println!(
            "{}: {}",
            "> Sending Ctrl+C to command".underline().yellow(),
            self.cmd_str,
        );
        let _result = self.interrupt();
        match self.exp_eof() {
            Err(error) => {
                eprintln!(
                    "\n{}: {}\n{}: {}",
                    "> Error ensuring command is finished".underline().red(),
                    self.cmd_str,
                    "Error".underline().red(),
                    error,
                );
            }
            Ok(output) => {
                println!(
                    "\n{}: {}",
                    "> Command finished".underline().green(),
                    self.cmd_str,
                );
                let output = output.trim();
                if !output.is_empty() {
                    println!(
                        "\n{}: {}\n\n{}",
                        "> Unread output for command".underline().yellow(),
                        self.cmd_str,
                        output
                    );
                } else {
                    println!(
                        "\n{}: {}",
                        "> No unread output for command".underline().green(),
                        self.cmd_str
                    );
                }
            }
        }
    }
}

/// Get a [`Command`] to run an Namada binary. By default, these will run in
/// release mode. This can be disabled by setting environment variable
/// `NAMADA_E2E_DEBUG=true`.
pub fn run_cmd<I, S>(
    bin: Bin,
    args: I,
    timeout_sec: Option<u64>,
    working_dir: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
    loc: String,
) -> Result<NamadaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // Root cargo workspace manifest path
    let (bin_name, log_level) = match bin {
        Bin::Node => ("namadan", "info"),
        Bin::Client => ("namadac", "tendermint_rpc=debug"),
        Bin::Wallet => ("namadaw", "info"),
        Bin::Relayer => ("namadar", "info"),
    };

    let mut run_cmd = generate_bin_command(
        bin_name,
        &working_dir.as_ref().join("Cargo.toml"),
    );

    run_cmd
        .env("NAMADA_LOG", log_level)
        .env("NAMADA_CMT_STDOUT", "true")
        .env("CMT_LOG_LEVEL", "info")
        .env("NAMADA_LOG_COLOR", "false")
        .current_dir(working_dir)
        .args(["--base-dir", &base_dir.as_ref().to_string_lossy()]);

    run_cmd.args(args);

    let args: String =
        run_cmd.get_args().map(|s| s.to_string_lossy()).join(" ");
    let cmd_str =
        format!("{} {}", run_cmd.get_program().to_string_lossy(), args);

    let session = Session::spawn(run_cmd).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}\n{}: {}",
            "Failed to run".underline().red(),
            cmd_str,
            "Location".underline().red(),
            loc,
            "Error".underline().red(),
            e
        )
    })?;

    let log_path = {
        let mut rng = rand::thread_rng();
        let log_dir = base_dir.as_ref().join("logs");
        fs::create_dir_all(&log_dir)?;
        log_dir.join(format!(
            "{}-{}-{}.log",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            bin_name,
            rng.gen::<u64>()
        ))
    };
    let logger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    let mut session = expectrl::session::log(session, logger).unwrap();

    session.set_expect_timeout(timeout_sec.map(std::time::Duration::from_secs));

    let mut cmd_process = NamadaCmd {
        session,
        cmd_str,
        log_path,
    };

    println!("{}:\n{}", "> Running".underline().green(), &cmd_process);

    if let Bin::Node = &bin {
        // When running a node command, we need to wait a bit before checking
        // status
        sleep(1);

        // If the command failed, try print out its output
        if let Ok(WaitStatus::Exited(_, result)) =
            cmd_process.session.get_process().status()
        {
            if result != 0 {
                let output = cmd_process.exp_eof().unwrap_or_else(|err| {
                    format!("No output found, error: {}", err)
                });
                return Err(eyre!(
                    "\n\n{}: {}\n{}: {} \n\n{}: {}",
                    "Failed to run".underline().red(),
                    cmd_process.cmd_str,
                    "Location".underline().red(),
                    loc,
                    "Output".underline().red(),
                    output,
                ));
            }
        }
    }

    Ok(cmd_process)
}

/// Sleep for given `seconds`.
pub fn sleep(seconds: u64) {
    thread::sleep(time::Duration::from_secs(seconds));
}

pub fn setup_hermes(test_a: &Test, test_b: &Test) -> Result<()> {
    println!("\n{}", "Setting up Hermes".underline().green(),);

    make_hermes_config(test_a, test_b)?;

    for test in [test_a, test_b] {
        let chain_id = test.net.chain_id.as_str();
        let chain_dir = test.test_dir.as_ref().join(chain_id);
        let key_file_path = if chain_id == constants::GAIA_CHAIN_ID {
            chain_dir.join(format!("{}_seed.json", constants::GAIA_RELAYER))
        } else {
            wallet::wallet_file(chain_dir)
        };
        let args = [
            "keys",
            "add",
            "--chain",
            chain_id,
            "--key-file",
            &key_file_path.to_string_lossy(),
        ];
        let mut hermes = run_hermes_cmd(test, args, Some(10))?;
        hermes.assert_success();
    }

    Ok(())
}

pub fn run_hermes_cmd<I, S>(
    test: &Test,
    args: I,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut run_cmd = Command::new("hermes");
    let hermes_dir = test.test_dir.as_ref().join("hermes");
    run_cmd.current_dir(hermes_dir.clone());
    let config_path = hermes_dir.join("config.toml");
    run_cmd.args(["--config", &config_path.to_string_lossy()]);
    run_cmd.args(args);

    let args: String =
        run_cmd.get_args().map(|s| s.to_string_lossy()).join(" ");
    let cmd_str =
        format!("{} {}", run_cmd.get_program().to_string_lossy(), args);

    let session = Session::spawn(run_cmd).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}",
            "Failed to run Hermes".underline().red(),
            cmd_str,
            "Error".underline().red(),
            e
        )
    })?;

    let log_path = {
        let mut rng = rand::thread_rng();
        let log_dir = test.get_base_dir(Who::NonValidator).join("logs");
        std::fs::create_dir_all(&log_dir)?;
        log_dir.join(format!(
            "{}-hermes-{}.log",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            rng.gen::<u64>()
        ))
    };
    let logger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    let mut session = expectrl::session::log(session, logger).unwrap();

    session.set_expect_timeout(timeout_sec.map(std::time::Duration::from_secs));

    let cmd_process = NamadaCmd {
        session,
        cmd_str,
        log_path,
    };

    println!("{}:\n{}", "> Running".underline().green(), &cmd_process);

    Ok(cmd_process)
}

pub fn setup_gaia() -> Result<Test> {
    let working_dir = working_dir();
    let test_dir = TestDir::new();
    let gaia_dir = test_dir.as_ref().join(constants::GAIA_CHAIN_ID);
    let net = Network {
        chain_id: ChainId(constants::GAIA_CHAIN_ID.to_string()),
    };
    let test = Test {
        working_dir,
        test_dir,
        net,
        async_runtime: Default::default(),
    };

    // initialize
    let args = [
        "--chain-id",
        constants::GAIA_CHAIN_ID,
        "init",
        constants::GAIA_CHAIN_ID,
    ];
    let mut gaia = run_gaia_cmd(&test, args, Some(10))?;
    gaia.assert_success();

    for role in [
        constants::GAIA_USER,
        constants::GAIA_RELAYER,
        constants::GAIA_VALIDATOR,
    ] {
        let key_file =
            format!("{}/{role}_seed.json", gaia_dir.to_string_lossy());
        let args = [
            "keys",
            "add",
            role,
            "--keyring-backend",
            "test",
            "--output",
            "json",
        ];
        let mut gaia = run_gaia_cmd(&test, args, Some(10))?;
        let result = gaia.exp_string("\n")?;
        let mut file = File::create(key_file).unwrap();
        file.write_all(result.as_bytes()).map_err(|e| {
            eyre!(format!("Writing a Gaia key file failed: {}", e))
        })?;
    }

    // Add tokens to a user account
    let account = find_gaia_address(&test, constants::GAIA_USER)?;
    let args = [
        "genesis",
        "add-genesis-account",
        &account,
        "10000stake,1000samoleans",
    ];
    let mut gaia = run_gaia_cmd(&test, args, Some(10))?;
    gaia.assert_success();

    // Add the stake token to the relayer
    let account = find_gaia_address(&test, constants::GAIA_RELAYER)?;
    let args = ["genesis", "add-genesis-account", &account, "10000stake"];
    let mut gaia = run_gaia_cmd(&test, args, Some(10))?;
    gaia.assert_success();

    // Add the stake token to the validator
    let validator = find_gaia_address(&test, constants::GAIA_VALIDATOR)?;
    let stake = "100000000000stake";
    let args = ["genesis", "add-genesis-account", &validator, stake];
    let mut gaia = run_gaia_cmd(&test, args, Some(10))?;
    gaia.assert_success();

    // stake
    let args = [
        "genesis",
        "gentx",
        constants::GAIA_VALIDATOR,
        stake,
        "--keyring-backend",
        "test",
        "--chain-id",
        constants::GAIA_CHAIN_ID,
    ];
    let mut gaia = run_gaia_cmd(&test, args, Some(10))?;
    gaia.assert_success();

    let args = ["genesis", "collect-gentxs"];
    let mut gaia = run_gaia_cmd(&test, args, Some(10))?;
    gaia.assert_success();

    update_gaia_config(&test)?;

    Ok(test)
}

pub fn run_gaia_cmd<I, S>(
    test: &Test,
    args: I,
    timeout_sec: Option<u64>,
) -> Result<NamadaCmd>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut run_cmd = Command::new("gaiad");
    let gaia_dir = test.test_dir.as_ref().join("gaia");
    run_cmd.args(["--home", &gaia_dir.to_string_lossy()]);
    run_cmd.args(args);

    let args: String =
        run_cmd.get_args().map(|s| s.to_string_lossy()).join(" ");
    let cmd_str =
        format!("{} {}", run_cmd.get_program().to_string_lossy(), args);

    let session = Session::spawn(run_cmd).map_err(|e| {
        eyre!(
            "\n\n{}: {}\n{}: {}",
            "Failed to run Gaia".underline().red(),
            cmd_str,
            "Error".underline().red(),
            e
        )
    })?;

    let log_path = {
        let mut rng = rand::thread_rng();
        let log_dir = test.get_base_dir(Who::NonValidator).join("logs");
        std::fs::create_dir_all(&log_dir)?;
        log_dir.join(format!(
            "{}-gaia-{}.log",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
            rng.gen::<u64>()
        ))
    };
    let logger = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    let mut session = expectrl::session::log(session, logger).unwrap();

    session.set_expect_timeout(timeout_sec.map(std::time::Duration::from_secs));

    let cmd_process = NamadaCmd {
        session,
        cmd_str,
        log_path,
    };

    println!("{}:\n{}", "> Running".underline().green(), &cmd_process);

    Ok(cmd_process)
}

#[allow(dead_code)]
pub mod constants {
    // Paths to the WASMs used for tests
    pub use namada_sdk::tx::TX_IBC_WASM;

    // User addresses aliases
    pub const ALBERT: &str = "Albert";
    pub const ALBERT_KEY: &str = "Albert-key";
    pub const BERTHA: &str = "Bertha";
    pub const BERTHA_KEY: &str = "Bertha-key";
    pub const CHRISTEL: &str = "Christel";
    pub const CHRISTEL_KEY: &str = "Christel-key";
    pub const DAEWON: &str = "Daewon";
    pub const DAEWON_KEY: &str = "Daewon-key";
    pub const ESTER: &str = "Ester";
    pub const MATCHMAKER_KEY: &str = "matchmaker-key";

    // Shielded spending and viewing keys and payment addresses
    pub const A_SPENDING_KEY: &str = "zsknam1qdrk9kd8qqqqpqy3pxzxu2kexydl7ug22s3808htl604emmz9qlde9cl9mx6euhvh3cpl9w7guustfzjxsyaeqtefhden6q8776t9cr9vkqztj7u0mgs5k9nz945sypev9ppptn5d85as3ccsnu3q6g3acqp2gpsrwe6naqg3stqp43uk9x2cj79gcxuum8a7jayjqlv4ptcfnunqkqzsj6m2r3sn8ft0tyqqpv28nghe4ag68eccaqx7v5f65he95g5uwq2wr4yuqc06jgc7";
    pub const B_SPENDING_KEY: &str = "zsknam1qdml0zguqqqqpqx8elavks722m0cjelgh3r044cfregyw049jze9lwha2cfqdqnekecnttdvygd6s784kch2v3wjs45g5z0n36hpqv5ruy8jjfu5mz2snl8ljyz79h3szmyf43zve79l6hwnlfk94r422tfwr2f62vvgkeqvc4z2dgrvqy033ymq5ylz3gmf6wdzhsdmzm0h9uv9374x755rzgvmcxhxntu6v63acqktv6zk390e9pd6vr0pzqaq6auu59kwpnw0haczfyju8";
    // A payment address derived from A_SPENDING_KEY
    pub const AA_PAYMENT_ADDRESS: &str = "znam1ky620tz7z658cralqt693qpvk42wvth468zp38nqvq2apmex5rfut3dfqm2asrsqv0tc7saqje7";
    // A payment address derived from B_SPENDING_KEY
    pub const AB_PAYMENT_ADDRESS: &str = "znam1zxt8e22uz666ce7hxqpc69yfj3tpd9v26ep2epwn34kvyuwjh98hhre9897shcjj4cnqugwlv4q";
    // A viewing key derived from B_SPENDING_KEY
    pub const AB_VIEWING_KEY: &str = "zvknam1qdml0zguqqqqpqx8elavks722m0cjelgh3r044cfregyw049jze9lwha2cfqdqnekem0xdqf9ytuhaxzeunyl7svgvxjv5g73m24k7w0h6q7wtvcltvlzynzhc5grlfgv7037lfh8w3su5krnzzzjh4nsleydtlns4gl0vmnc4z2dgrvqy033ymq5ylz3gmf6wdzhsdmzm0h9uv9374x755rzgvmcxhxntu6v63acqktv6zk390e9pd6vr0pzqaq6auu59kwpnw0hacdsfkws";
    // A payment address derived from B_VIEWING_KEY
    pub const BB_PAYMENT_ADDRESS: &str = "znam1mqt0ja2zccy70du2d6rcr77jscgq3gkekfvhrqe7zkxa8rr3qsjsrd66gxnrykdmdeh5wmglmcm";
    // A viewing key derived from A_SPENDING_KEY
    pub const AA_VIEWING_KEY: &str = "zvknam1qdrk9kd8qqqqpqy3pxzxu2kexydl7ug22s3808htl604emmz9qlde9cl9mx6euhvhnc63hymme53jz3mmwrzfkr9tk82nqacf5vlmj9du3s3rjz0h6usnh47pw0ufw4u6yrfvf95wfa9xj0m8pcrns9yh90s0jkf3cqy2z7c3stqp43uk9x2cj79gcxuum8a7jayjqlv4ptcfnunqkqzsj6m2r3sn8ft0tyqqpv28nghe4ag68eccaqx7v5f65he95g5uwq2wr4yuqc8djdrp";
    pub const C_SPENDING_KEY: &str = "zsknam1qdy5g4udqqqqpqrfdzej0s45m8s6nprder4udwqm3ql8wx34e8f46dv8cwnmcjp40uj3qy5tgetj27jytvxk4vpa3pjsd80y332nj542w39wta8lsrzqzs822ydgmz5g2sd2k29hxc3uh77v5cmcext799fxn6sa9rd3zuggl6flgjz7wz9wwu9kxd4rth4clw6ug4drxln96y96nf8fmvgm5eddm93azuzlkjj0dpw343ukwcfuvkdhd772539cskgggcqsaaf0j7czshjwe";
    // A viewing key derived from C_SPENDING_KEY
    pub const AC_VIEWING_KEY: &str = "zvknam1qdy5g4udqqqqpqrfdzej0s45m8s6nprder4udwqm3ql8wx34e8f46dv8cwnmcjp40lr4vutffut7ed5x6egd6etcdh9sxh3j9fe5dshhrn3nq4yfp78gt8ve59y4vnu45xlt93vtrzsxtwlxjjgu2p496lc3ye8m83qplsqfl6flgjz7wz9wwu9kxd4rth4clw6ug4drxln96y96nf8fmvgm5eddm93azuzlkjj0dpw343ukwcfuvkdhd772539cskgggcqsaaf0j7cfyd3jr";
    // A viewing key derived from C_VIEWING_KEY
    pub const AC_PAYMENT_ADDRESS: &str = "znam1xv4ml6fp3zqjhw20xj3srd75cq8tyejdst0xweq60c70732ty2chd2v39tllpzf4uf6s66vfm6w";

    //  Native VP aliases
    pub const GOVERNANCE_ADDRESS: &str = "governance";
    pub const MASP: &str = "masp";

    // Fungible token addresses
    pub const NAM: &str = "NAM";
    pub const BTC: &str = "BTC";
    pub const ETH: &str = "ETH";
    pub const DOT: &str = "DOT";

    // Bite-sized tokens
    pub const SCHNITZEL: &str = "Schnitzel";
    pub const APFEL: &str = "Apfel";
    pub const KARTOFFEL: &str = "Kartoffel";

    // Gaia
    pub const GAIA_RPC: &str = "127.0.0.1:26657";
    pub const GAIA_CHAIN_ID: &str = "gaia";
    pub const GAIA_USER: &str = "user";
    pub const GAIA_RELAYER: &str = "relayer";
    pub const GAIA_VALIDATOR: &str = "validator";
    pub const GAIA_COIN: &str = "samoleans";
}

/// Copy WASM files from the `wasm` directory to every node's chain dir.
pub fn copy_wasm_to_chain_dir(
    working_dir: &Path,
    test_dir: &Path,
    chain_id: &ChainId,
    // genesis_validator_keys: impl Iterator<Item = &'a String>,
) {
    // Copy the built WASM files from "wasm" directory in the root of the
    // project.
    let built_wasm_dir = working_dir.join(config::DEFAULT_WASM_DIR);
    let opts = fs_extra::dir::DirOptions { depth: 1 };
    let wasm_files: Vec<_> =
        fs_extra::dir::get_dir_content2(&built_wasm_dir, &opts)
            .unwrap()
            .files
            .into_iter()
            .map(PathBuf::from)
            .filter(|path| {
                matches!(path.extension().and_then(OsStr::to_str), Some("wasm"))
            })
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
    if wasm_files.is_empty() {
        panic!(
            "No WASM files found in {}. Please build or download them them \
             first.",
            built_wasm_dir.to_string_lossy()
        );
    }
    let chain_dir = test_dir.join(chain_id.as_str());
    let target_wasm_dir = chain_dir.join(config::DEFAULT_WASM_DIR);
    for file in &wasm_files {
        std::fs::copy(
            working_dir.join("wasm").join(file),
            target_wasm_dir.join(file),
        )
        .unwrap();
    }
}

pub fn get_all_wasms_hashes(
    working_dir: &Path,
    filter: Option<&str>,
) -> Vec<String> {
    let checksums_path = working_dir.join("wasm/checksums.json");
    let checksums_content = fs::read_to_string(checksums_path).unwrap();
    let checksums: HashMap<String, String> =
        serde_json::from_str(&checksums_content).unwrap();
    let filter_prefix = filter.unwrap_or_default();
    checksums
        .values()
        .filter_map(|wasm| {
            if wasm.contains(filter_prefix) {
                Some(
                    wasm.split('.').collect::<Vec<&str>>()[1]
                        .to_owned()
                        .to_lowercase(),
                )
            } else {
                None
            }
        })
        .collect()
}
