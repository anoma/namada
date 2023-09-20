use std::mem::ManuallyDrop;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use color_eyre::eyre::{eyre, Result};
use namada::ledger::wallet::alias::Alias;
use namada_apps::cli::args;
use namada_apps::client::utils::PRE_GENESIS_DIR;
use namada_apps::config;
use namada_apps::config::genesis::chain::Finalized;
use namada_apps::config::genesis::templates::load_and_validate;
use namada_apps::config::genesis::templates;
use namada_apps::config::TendermintMode;
use namada_apps::facade::tendermint::Timeout;
use namada_apps::facade::tendermint_proto::google::protobuf::Timestamp;
use namada_apps::node::ledger::shell::testing::node::MockNode;
use namada_apps::node::ledger::shell::testing::utils::TestDir;
use namada_apps::node::ledger::shell::Shell;
use namada_apps::wallet::pre_genesis;
use namada_core::types::chain::ChainIdPrefix;

use crate::e2e::setup::{copy_wasm_to_chain_dir, SINGLE_NODE_NET_GENESIS};

/// Env. var for keeping temporary files created by the integration tests
const ENV_VAR_KEEP_TEMP: &str = "NAMADA_INT_KEEP_TEMP";

/// Setup a network with a single genesis validator node.
pub fn setup() -> Result<MockNode> {
    initialize_genesis()
}

/// Setup folders with genesis, configs, wasm, etc.
pub fn initialize_genesis() -> Result<MockNode> {
    let working_dir = std::fs::canonicalize("..").unwrap();
    let keep_temp = match std::env::var(ENV_VAR_KEEP_TEMP) {
        Ok(val) => val.to_ascii_lowercase() != "false",
        _ => false,
    };
    let test_dir = TestDir::new();
    let template_dir = working_dir.join(SINGLE_NODE_NET_GENESIS);

    // Copy genesis files to test directory.
    let templates = templates::All::read_toml_files(&template_dir)
        .expect("Missing genesis files");
    let genesis_path = test_dir.path().join("int-test-genesis-src");
    std::fs::create_dir(&genesis_path)
        .expect("Could not create test chain directory.");
    templates
        .write_toml_files(&genesis_path)
        .expect("Could not write genesis files into test chain directory.");

    // Finalize the genesis config to derive the chain ID
    let templates = load_and_validate(&template_dir)
        .expect("Missing or invalid genesis files");
    let genesis_time = Default::default();
    let chain_id_prefix = ChainIdPrefix::from_str("integration-test").unwrap();
    let genesis = config::genesis::chain::finalize(
        templates,
        chain_id_prefix.clone(),
        genesis_time,
        Timeout::from_str("30s").unwrap(),
    );
    let chain_id = &genesis.metadata.chain_id;

    // Run `init-network` to generate the finalized genesis config, keys and
    // addresses and update WASM checksums
    let wasm_checksums_path = working_dir.join("wasm/checksums.json");
    let global_args = args::Global {
        chain_id: Some(chain_id.clone()),
        base_dir: test_dir.path().to_path_buf(),
        wasm_dir: Some(test_dir.path().join(chain_id.as_str()).join("wasm")),
    };
    // setup genesis file
    namada_apps::client::utils::init_network(
        global_args.clone(),
        args::InitNetwork {
            templates_path: genesis_path,
            wasm_checksums_path,
            chain_id_prefix,
            consensus_timeout_commit: Timeout::from_str("30s").unwrap(),
            dont_archive: true,
            archive_dir: None,
            genesis_time,
        },
    );

    finalize_wallet(&template_dir, &global_args, genesis);
    create_node(test_dir, global_args, keep_temp)
}

/// Add the address from the finalized genesis to the wallet.
/// Additionally add the validator keys to the wallet.
fn finalize_wallet(
    template_dir: &Path,
    global_args: &args::Global,
    genesis: Finalized,
) {
    let pre_genesis_path = template_dir.join("src").join(PRE_GENESIS_DIR);
    let validator_alias_and_dir =
        Some(("validator-0", pre_genesis_path.join("validator-0")));
    // Pre-load the validator pre-genesis wallet and its keys to validate that
    // everything is in place
    let validator_alias_and_pre_genesis_wallet =
        validator_alias_and_dir.map(|(validator_alias, pre_genesis_dir)| {
            (
                Alias::from(validator_alias),
                pre_genesis::load(&pre_genesis_dir).unwrap_or_else(|err| {
                    panic!("Error loading validator pre-genesis wallet {err}")
                }),
            )
        });

    // Try to load pre-genesis wallet
    let pre_genesis_wallet = namada_apps::wallet::load(&pre_genesis_path);
    let chain_dir = global_args
        .base_dir
        .join(global_args.chain_id.as_ref().unwrap().as_str());
    // Derive wallet from genesis
    let wallet = genesis.derive_wallet(
        &chain_dir,
        pre_genesis_wallet,
        validator_alias_and_pre_genesis_wallet,
    );
    namada_apps::wallet::save(&wallet).unwrap();
}

/// Create a mock ledger node.
fn create_node(
    test_dir: TestDir,
    global_args: args::Global,
    keep_temp: bool,
) -> Result<MockNode> {
    // look up the chain id from the global file.
    let chain_id = global_args.chain_id.unwrap_or_default();

    // copy compiled wasms into the wasm directory
    copy_wasm_to_chain_dir(
        &std::fs::canonicalize("..").unwrap(),
        &global_args.base_dir,
        &chain_id,
    );

    // instantiate and initialize the ledger node.
    let (sender, recv) = tokio::sync::mpsc::unbounded_channel();
    let node = MockNode {
        shell: Arc::new(Mutex::new(Shell::new(
            config::Ledger::new(
                global_args.base_dir,
                chain_id.clone(),
                TendermintMode::Validator,
            ),
            global_args
                .wasm_dir
                .expect("Wasm path not provided to integration test setup."),
            sender,
            None,
            None,
            50 * 1024 * 1024, // 50 kiB
            50 * 1024 * 1024, // 50 kiB
        ))),
        test_dir: ManuallyDrop::new(test_dir),
        keep_temp,
        _broadcast_recv: recv,
        results: Arc::new(Mutex::new(vec![])),
    };
    let init_req = namada_apps::facade::tower_abci::request::InitChain {
        time: Some(Timestamp {
            seconds: 0,
            nanos: 0,
        }),
        chain_id: chain_id.to_string(),
        consensus_params: None,
        validators: vec![],
        app_state_bytes: vec![],
        initial_height: 0,
    };
    {
        let mut locked = node.shell.lock().unwrap();
        locked
            .init_chain(init_req)
            .map_err(|e| eyre!("Failed to initialize ledger: {:?}", e))?;
        locked.commit();
    }

    Ok(node)
}
