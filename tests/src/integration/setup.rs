use std::mem::ManuallyDrop;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use color_eyre::eyre::{eyre, Result};
use namada_apps::cli::args;
use namada_apps::config;
use namada_apps::config::genesis::genesis_config;
use namada_apps::config::genesis::genesis_config::GenesisConfig;
use namada_apps::config::TendermintMode;
use namada_apps::facade::tendermint::Timeout;
use namada_apps::facade::tendermint_proto::google::protobuf::Timestamp;
use namada_apps::node::ledger::shell::testing::node::MockNode;
use namada_apps::node::ledger::shell::testing::utils::TestDir;
use namada_apps::node::ledger::shell::Shell;
use namada_core::types::address::Address;
use namada_core::types::chain::{ChainId, ChainIdPrefix};
use toml::value::Table;

use crate::e2e::setup::{
    copy_wasm_to_chain_dir, get_all_wasms_hashes, SINGLE_NODE_NET_GENESIS,
};

/// Env. var for keeping temporary files created by the integration tests
const ENV_VAR_KEEP_TEMP: &str = "NAMADA_INT_KEEP_TEMP";

/// Setup a network with a single genesis validator node.
pub fn setup() -> Result<MockNode> {
    initialize_genesis(|genesis| genesis)
}

/// Setup folders with genesis, configs, wasm, etc.
pub fn initialize_genesis(
    mut update_genesis: impl FnMut(GenesisConfig) -> GenesisConfig,
) -> Result<MockNode> {
    let working_dir = std::fs::canonicalize("..").unwrap();
    let keep_temp = match std::env::var(ENV_VAR_KEEP_TEMP) {
        Ok(val) => val.to_ascii_lowercase() != "false",
        _ => false,
    };
    let test_dir = TestDir::new();

    // Open the source genesis file
    let mut genesis = genesis_config::open_genesis_config(
        working_dir.join(SINGLE_NODE_NET_GENESIS),
    )?;

    genesis.parameters.vp_whitelist =
        Some(get_all_wasms_hashes(&working_dir, Some("vp_")));
    genesis.parameters.tx_whitelist =
        Some(get_all_wasms_hashes(&working_dir, Some("tx_")));

    // Run the provided function on it
    let genesis = update_genesis(genesis);

    // Run `init-network` to generate the finalized genesis config, keys and
    // addresses and update WASM checksums
    let genesis_path = test_dir.path().join("e2e-test-genesis-src.toml");
    genesis_config::write_genesis_config(&genesis, &genesis_path);
    let wasm_checksums_path = working_dir.join("wasm/checksums.json");

    // setup genesis file
    namada_apps::client::utils::init_network(
        args::Global {
            chain_id: None,
            base_dir: test_dir.path().to_path_buf(),
            wasm_dir: None,
        },
        args::InitNetwork {
            genesis_path,
            wasm_checksums_path,
            chain_id_prefix: ChainIdPrefix::from_str("integration-test")
                .unwrap(),
            unsafe_dont_encrypt: true,
            consensus_timeout_commit: Timeout::from_str("1s").unwrap(),
            localhost: true,
            allow_duplicate_ip: true,
            dont_archive: true,
            archive_dir: None,
        },
    );

    create_node(test_dir, &genesis, keep_temp)
}

/// Create a mock ledger node.
fn create_node(
    base_dir: TestDir,
    genesis: &GenesisConfig,
    keep_temp: bool,
) -> Result<MockNode> {
    // look up the chain id from the global file.
    let chain_id = if let toml::Value::String(chain_id) =
        toml::from_str::<Table>(
            &std::fs::read_to_string(
                base_dir.path().join("global-config.toml"),
            )
            .unwrap(),
        )
        .unwrap()
        .get("default_chain_id")
        .unwrap()
    {
        chain_id.to_string()
    } else {
        return Err(eyre!("Could not read chain id from global-config.toml"));
    };

    // the directory holding compiled wasm
    let wasm_dir = base_dir.path().join(Path::new(&chain_id)).join("wasm");
    // copy compiled wasms into the wasm directory
    let chain_id = ChainId::from_str(&chain_id).unwrap();
    copy_wasm_to_chain_dir(
        &std::fs::canonicalize("..").unwrap(),
        &base_dir.path().join(Path::new(&chain_id.to_string())),
        &chain_id,
        genesis.validator.keys(),
    );

    // instantiate and initialize the ledger node.
    let (sender, recv) = tokio::sync::mpsc::unbounded_channel();
    let node = MockNode {
        shell: Arc::new(Mutex::new(Shell::new(
            config::Ledger::new(
                base_dir.path(),
                chain_id.clone(),
                TendermintMode::Validator
            ),
            wasm_dir,
            sender,
            None,
            None,
            50 * 1024 * 1024, // 50 kiB
            50 * 1024 * 1024, // 50 kiB
            Address::from_str("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").unwrap(),
        ))),
        test_dir: ManuallyDrop::new(base_dir),
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
            .init_chain(init_req, 1)
            .map_err(|e| eyre!("Failed to initialize ledger: {:?}", e))?;
        locked.commit();
    }

    Ok(node)
}
