use std::fs;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use color_eyre::eyre::{eyre, Result};
use namada_apps_lib::cli::args;
use namada_apps_lib::config::genesis::templates::{self, load_and_validate};
use namada_apps_lib::config::{self, TendermintMode};
use namada_apps_lib::wallet;
use namada_apps_lib::wallet::defaults::derive_template_dir;
use namada_node::shell::testing::node::{
    mock_services, InnerMockNode, MockNode, MockServicesCfg,
    MockServicesController, MockServicesPackage, SalvageableTestDir,
};
use namada_node::shell::testing::utils::TestDir;
use namada_node::shell::Shell;
use namada_node::tendermint_config::net::Address as TendermintAddress;
use namada_sdk::address::Address;
use namada_sdk::chain::{ChainId, ChainIdPrefix};
use namada_sdk::collections::HashMap;
use namada_sdk::dec::Dec;
use namada_sdk::io::StdIo;
use namada_sdk::tendermint::Timeout;
use namada_sdk::tendermint_proto::google::protobuf::Timestamp;
use namada_sdk::token;
use test_log::test;

use super::setup;
use crate::e2e::setup::{
    constants, copy_wasm_to_chain_dir, default_port_offset, ensure_hot_key,
};
use crate::integration::helpers::find_address;

#[test]
fn test_transfers() {
    // Spawn tokio runtime for RPC servers
    let rt = tokio::runtime::Runtime::new().unwrap();

    // 1. Setup 2 Namada chains with unique IDs
    let (node_a, _services_a) =
        initialize_genesis(0, |genesis| genesis, Some("chain-a")).unwrap();
    let nam_addr = find_address(&node_a, constants::NAM).unwrap();
    let test_dir_a = node_a.test_dir.path().to_owned();
    // Node A uses port 26777
    let port_a = 26777_u16;
    let _rpc_handle_a = node_a.clone().start_rpc_server(&rt, port_a);

    let chain_id_a = node_a.shell.lock().unwrap().chain_id.clone();
    let (node_b, _services_b) =
        initialize_genesis(1, |genesis| genesis, Some("chain-b")).unwrap();
    let test_dir_b = node_b.test_dir.path().to_owned();
    // Node B uses port 26783
    let port_b = 26783_u16;
    let chain_id_b = node_b.shell.lock().unwrap().chain_id.clone();
    let _rpc_handle_b = node_b.clone().start_rpc_server(&rt, port_b);

    let nam_addr_b = find_address(&node_a, constants::NAM).unwrap();
    // The NAM address is the same on both chains because its derived from the
    // same config, but that's ok
    assert_eq!(nam_addr, nam_addr_b);

    // 2. Configure hermes
    let hermes_config = make_hermes_config(
        port_a,
        &chain_id_a,
        &test_dir_a,
        port_b,
        &chain_id_b,
        &test_dir_b,
        &nam_addr,
    )
    .unwrap();

    // 3. Add wallet keys in Hermes for the chains
    for (node, chain_id) in [(&node_a, &chain_id_a), (&node_b, &chain_id_b)] {
        let chain_dir = node.test_dir.path().join(chain_id.as_str());
        dbg!(chain_id);
        hermes_add_keys(&hermes_config, chain_id, chain_dir);
    }

    // NOTE: Must have a block header before channel setup, otherwise the IBC
    // transaction fails with "No host block header"
    node_a.finalize_and_commit(None);
    node_b.finalize_and_commit(None);

    // 4. Setup a Hermes channel between the chains
    hermes_create_channel(&hermes_config, &chain_id_a, &chain_id_b);

    // 5. Make a transfer
    todo!()
}

// Roughly equivalent to "hermes create channel" CLI command
fn hermes_create_channel(
    config: &hermes::Config,
    chain_a: &ChainId,
    chain_b: &ChainId,
) {
    use hermes::commands::{
        connection_delay, Channel, Connection, ForeignClient, Ordering, PortId,
    };

    let hermes_chain_a =
        hermes::commands::ChainId::from_str(chain_a.as_str()).unwrap();
    let hermes_chain_b =
        hermes::commands::ChainId::from_str(chain_b.as_str()).unwrap();

    let chains = hermes::cli_utils::ChainHandlePair::spawn(
        config,
        &hermes_chain_a,
        &hermes_chain_b,
    )
    .unwrap();

    let client_a =
        ForeignClient::new(chains.src.clone(), chains.dst.clone()).unwrap();
    let client_b = ForeignClient::new(chains.dst.clone(), chains.src).unwrap();

    // Create the connection.
    let con = Connection::new(client_a, client_b, connection_delay()).unwrap();

    let port_a = PortId::from_str("transfer").unwrap();
    let port_b = PortId::from_str("transfer").unwrap();
    let order = Ordering::Unordered;
    // Finally create the channel.
    let channel = Channel::new(con, order, port_a, port_b, None).unwrap();
}

// Roughly equivalent to "hermes keys add" CLI command
fn hermes_add_keys(
    config: &hermes::Config,
    chain_id: &ChainId,
    chain_dir: PathBuf,
) {
    let hermes_chain_id =
        hermes::commands::ChainId::from_str(chain_id.as_str()).unwrap();
    let key_file = wallet::wallet_file(chain_dir);
    let chain_config = config.find_chain(&hermes_chain_id).unwrap();
    let key_name = chain_config.key_name().to_string();
    // The default HD path from hermes
    // `crates/relayer-cli/src/commands/keys/add.rs`
    let hd_path =
        hermes::commands::StandardHDPath::from_str("m/44'/118'/0'/0/0")
            .unwrap();

    let _key = hermes::commands::add_key(
        &chain_config,
        &key_name,
        &key_file,
        &hd_path,
        false,
    )
    .unwrap();
}

fn make_hermes_config(
    port_a: u16,
    chain_id_a: &ChainId,
    dir_a: &Path,
    port_b: u16,
    chain_id_b: &ChainId,
    dir_b: &Path,
    nam: &Address,
) -> Result<hermes::Config> {
    use toml::map::Map;
    use toml::Value;

    let mut config = Map::new();

    let mut global = Map::new();
    global.insert("log_level".to_owned(), Value::String("debug".to_owned()));
    config.insert("global".to_owned(), Value::Table(global));

    let mut mode = Map::new();
    let mut clients = Map::new();
    clients.insert("enabled".to_owned(), Value::Boolean(true));
    clients.insert("refresh".to_owned(), Value::Boolean(true));
    clients.insert("misbehaviour".to_owned(), Value::Boolean(true));
    mode.insert("clients".to_owned(), Value::Table(clients));

    let mut connections = Map::new();
    connections.insert("enabled".to_owned(), Value::Boolean(false));
    mode.insert("connections".to_owned(), Value::Table(connections));

    let mut channels = Map::new();
    channels.insert("enabled".to_owned(), Value::Boolean(false));
    mode.insert("channels".to_owned(), Value::Table(channels));

    let mut packets = Map::new();
    packets.insert("enabled".to_owned(), Value::Boolean(true));
    packets.insert("clear_interval".to_owned(), Value::Integer(30));
    packets.insert("clear_on_start".to_owned(), Value::Boolean(true));
    packets.insert("tx_confirmation".to_owned(), Value::Boolean(true));
    mode.insert("packets".to_owned(), Value::Table(packets));

    config.insert("mode".to_owned(), Value::Table(mode));

    let mut telemetry = Map::new();
    telemetry.insert("enabled".to_owned(), Value::Boolean(false));
    telemetry.insert("host".to_owned(), Value::String("127.0.0.1".to_owned()));
    telemetry.insert("port".to_owned(), Value::Integer(3001));
    config.insert("telemetry".to_owned(), Value::Table(telemetry));

    let chains = vec![
        make_hermes_chain_config(port_a, chain_id_a, dir_a, nam),
        make_hermes_chain_config(port_b, chain_id_b, dir_b, nam),
    ];

    config.insert("chains".to_owned(), Value::Array(chains));

    let toml = toml::to_vec(&Value::Table(config)).unwrap();

    let config: hermes::Config = toml::from_slice(&toml).unwrap();
    Ok(config)
}

fn make_hermes_chain_config(
    port: u16,
    chain_id: &ChainId,
    dir: &Path,
    nam: &Address,
) -> toml::Value {
    use toml::map::Map;
    use toml::Value;

    let chain_id = chain_id.as_str();
    let rpc_addr = format!("127.0.0.1:{port}");

    let mut table = Map::new();
    table.insert("mode".to_owned(), Value::String("push".to_owned()));
    let url = format!("ws://{}/websocket", rpc_addr);
    table.insert("url".to_owned(), Value::String(url));
    table.insert("batch_delay".to_owned(), Value::String("500ms".to_owned()));
    let event_source = Value::Table(table);

    let mut chain = Map::new();
    chain.insert("id".to_owned(), Value::String(chain_id.to_owned()));
    chain.insert("type".to_owned(), Value::String("Namada".to_owned()));
    chain.insert(
        "rpc_addr".to_owned(),
        Value::String(format!("http://{rpc_addr}")),
    );
    // The grpc isn't used for Namada, but it's required
    chain.insert(
        "grpc_addr".to_owned(),
        Value::String("http://127.0.0.1:9090".to_owned()),
    );
    chain.insert("event_source".to_owned(), event_source);
    chain.insert("account_prefix".to_owned(), Value::String("".to_owned()));
    chain.insert(
        "key_name".to_owned(),
        Value::String(ensure_hot_key(constants::CHRISTEL_KEY).to_owned()),
    );
    chain.insert("store_prefix".to_owned(), Value::String("ibc".to_owned()));
    let mut table = Map::new();
    table.insert("price".to_owned(), Value::Float(0.000001));
    table.insert("denom".to_owned(), Value::String(nam.to_string()));
    chain.insert("gas_price".to_owned(), Value::Table(table));

    chain.insert("max_block_time".to_owned(), Value::String("60s".to_owned()));
    chain.insert(
        "key_store_folder".to_owned(),
        Value::String(dir.to_string_lossy().to_string()),
    );

    Value::Table(chain)
}

/// Setup folders with genesis, configs, wasm, etc.
/// This is similar to the fn with same name in
/// `crates/tests/src/integration/setup.rs`, but it allows to setup multiple
/// nodes by offsetting their ports by the given `node_index`.
fn initialize_genesis(
    node_index: u8,
    mut update_genesis: impl FnMut(
        templates::All<templates::Unvalidated>,
    ) -> templates::All<templates::Unvalidated>,
    chain_prefix: Option<&str>,
) -> Result<(MockNode, MockServicesController)> {
    let working_dir = std::fs::canonicalize("../..").unwrap();
    let keep_temp = match std::env::var(setup::ENV_VAR_KEEP_TEMP) {
        Ok(val) => val.to_ascii_lowercase() != "false",
        _ => false,
    };
    let test_dir = TestDir::new();
    let template_dir = derive_template_dir(&working_dir);

    // Copy genesis files to test directory.
    let mut templates = templates::All::read_toml_files(&template_dir)
        .expect("Missing genesis files");
    for (_, config) in templates.tokens.token.iter_mut() {
        config.masp_params = Some(token::ShieldedParams {
            max_reward_rate: Dec::from_str("0.1").unwrap(),
            kp_gain_nom: Dec::from_str("0.1").unwrap(),
            kd_gain_nom: Dec::from_str("0.1").unwrap(),
            locked_amount_target: 1_000_000u64,
        });
    }
    let templates = update_genesis(templates);
    let genesis_path = test_dir.path().join("int-test-genesis-src");
    std::fs::create_dir(&genesis_path)
        .expect("Could not create test chain directory.");
    templates
        .write_toml_files(&genesis_path)
        .expect("Could not write genesis files into test chain directory.");

    // Finalize the genesis config to derive the chain ID
    let templates = load_and_validate(&genesis_path)
        .expect("Missing or invalid genesis files");
    let genesis_time = Default::default();
    let chain_id_prefix =
        ChainIdPrefix::from_str(chain_prefix.unwrap_or("integration-test"))
            .unwrap();
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
        is_pre_genesis: true,
        chain_id: Some(chain_id.clone()),
        base_dir: test_dir.path().to_path_buf(),
        wasm_dir: Some(test_dir.path().join(chain_id.as_str()).join("wasm")),
    };

    // Create genesis chain release archive
    let release_archive_path = namada_apps_lib::client::utils::init_network(
        global_args.clone(),
        args::InitNetwork {
            templates_path: genesis_path,
            wasm_checksums_path,
            chain_id_prefix,
            consensus_timeout_commit: Timeout::from_str("30s").unwrap(),
            archive_dir: Some(test_dir.path().to_path_buf()),
            genesis_time,
        },
    );

    // Decode and unpack the release archive
    let mut archive = {
        let decoder = flate2::read::GzDecoder::new(
            fs::File::open(&release_archive_path).unwrap(),
        );
        tar::Archive::new(decoder)
    };
    archive.unpack(&global_args.base_dir).unwrap();
    _ = archive;

    // Remove release archive
    fs::remove_file(release_archive_path).unwrap();

    let eth_bridge_params = genesis.get_eth_bridge_params();
    let auto_drive_services = {
        // NB: for now, the only condition that
        // dictates whether mock services should
        // be enabled is if the Ethereum bridge
        // is enabled at genesis
        eth_bridge_params.is_some()
    };
    let enable_eth_oracle = {
        // NB: we only enable the oracle if the
        // Ethereum bridge is enabled at genesis
        eth_bridge_params.is_some()
    };
    let services_cfg = MockServicesCfg {
        auto_drive_services,
        enable_eth_oracle,
    };
    setup::finalize_wallet(&template_dir, &global_args, genesis);
    create_node(node_index, test_dir, global_args, keep_temp, services_cfg)
}

/// Create a mock ledger node.
/// This is similar to the fn with same name in
/// `crates/tests/src/integration/setup.rs`, but it allows to setup multiple
/// nodes by offsetting their ports by the given `index`.
fn create_node(
    index: u8,
    test_dir: TestDir,
    global_args: args::Global,
    keep_temp: bool,
    services_cfg: MockServicesCfg,
) -> Result<(MockNode, MockServicesController)> {
    // look up the chain id from the global file.
    let chain_id = global_args.chain_id.unwrap_or_default();

    // copy compiled wasms into the wasm directory
    copy_wasm_to_chain_dir(
        &std::fs::canonicalize("../..").unwrap(),
        &global_args.base_dir,
        &chain_id,
    );

    // instantiate and initialize the ledger node.
    let MockServicesPackage {
        auto_drive_services,
        services,
        shell_handlers,
        controller,
    } = mock_services(services_cfg);

    let config = {
        let mut config = config::Ledger::new(
            global_args.base_dir,
            chain_id.clone(),
            TendermintMode::Validator,
        );
        let offset = default_port_offset(20 + index);
        let incr_port = |addr: &mut TendermintAddress| {
            if let TendermintAddress::Tcp { port, .. } = addr {
                *port += offset;
            }
        };
        incr_port(&mut config.cometbft.p2p.laddr);
        incr_port(&mut config.cometbft.rpc.laddr);
        incr_port(&mut config.cometbft.proxy_app);
        config
    };

    let node = MockNode(Arc::new(InnerMockNode {
        shell: Mutex::new(Shell::new(
            config,
            global_args
                .wasm_dir
                .expect("Wasm path not provided to integration test setup."),
            shell_handlers.tx_broadcaster,
            shell_handlers.eth_oracle_channels,
            None,
            None,
            50 * 1024 * 1024, // 50 kiB
            50 * 1024 * 1024, // 50 kiB
        )),
        test_dir: SalvageableTestDir {
            keep_temp,
            test_dir: ManuallyDrop::new(test_dir),
        },
        services,
        tx_result_codes: Mutex::new(vec![]),
        tx_results: Mutex::new(vec![]),
        blocks: Mutex::new(HashMap::new()),
        auto_drive_services,
    }));
    let init_req =
        namada_apps_lib::tendermint::abci::request::InitChain {
            time: Timestamp {
                seconds: 0,
                nanos: 0,
            }
            .try_into().unwrap(),
            chain_id: chain_id.to_string(),
            consensus_params:
                namada_apps_lib::tendermint::consensus::params::Params {
                    block: namada_apps_lib::tendermint::block::Size {
                        max_bytes: 0,
                        max_gas: 0,
                        time_iota_ms: 0,
                    },
                    evidence:
                     namada_apps_lib::tendermint::evidence::Params {
                        max_age_num_blocks:  0,
                        max_age_duration: namada_apps_lib::tendermint::evidence::Duration(core::time::Duration::MAX),
                        max_bytes: 0,
                    },
                    validator: namada_apps_lib::tendermint::consensus::params::ValidatorParams {
                        pub_key_types: vec![]
                    },
                    version: None,
                    abci: namada_apps_lib::tendermint::consensus::params::AbciParams {
                        vote_extensions_enable_height: None,
                    },
                },
            validators: vec![],
            app_state_bytes: vec![].into(),
            initial_height: 0_u32.into(),
        };
    {
        let mut locked = node.shell.lock().unwrap();
        locked
            .init_chain(init_req, 1)
            .map_err(|e| eyre!("Failed to initialize ledger: {:?}", e))?;
        // set the height of the first block (should be 1)
        locked.state.in_mem_mut().block.height = 1.into();
        locked.commit();
    }

    Ok((node, controller))
}
