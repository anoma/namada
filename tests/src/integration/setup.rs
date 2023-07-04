use std::cell::RefCell;
use std::env;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::str::FromStr;

use color_eyre::eyre::{eyre, Result, Report};
use namada::ledger::events::log::EventLog;
use namada::ledger::queries::router::test_rpc::TEST_RPC;
use namada::ledger::queries::{
    Client, EncodedResponseQuery, RequestCtx, RequestQuery, Router,
};
use namada::tendermint_rpc::{Error, SimpleRequest};
use namada::vm::{wasm, WasmCacheRoAccess, WasmCacheRwAccess};
use namada_apps::cli::args;
use namada_apps::config;
use namada_apps::config::genesis::genesis_config;
use namada_apps::config::genesis::genesis_config::GenesisConfig;
use namada_apps::config::TendermintMode;
use namada_apps::facade::tendermint::{self, Timeout};
use namada_apps::facade::tendermint_proto::google::protobuf::Timestamp;
use namada_apps::facade::tendermint_rpc;
use namada_apps::node::ledger::shell::Shell;
use namada_apps::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
use namada_core::ledger::storage::mockdb::MockDB;
use namada_core::ledger::storage::{
    LastBlock, Sha256Hasher, WlStorage, EPOCH_SWITCH_BLOCKS_DELAY,
};
use namada_core::types::address::Address;
use namada_core::types::chain::{ChainId, ChainIdPrefix};
use namada_core::types::hash::Hash;
use namada_core::types::storage::{BlockHash, BlockHeight, Epoch, Header};
use namada_core::types::time::DateTimeUtc;
use tempfile::TempDir;
use tokio::sync::mpsc::UnboundedReceiver;
use toml::value::Table;
use namada::tendermint_rpc::endpoint::abci_info;
use namada_apps::facade::tendermint_rpc::endpoint::abci_info::AbciInfo;
use namada_apps::facade::tendermint_rpc::endpoint::{block, block_results, blockchain, commit, consensus_params, consensus_state, net_info, status};
use namada_apps::facade::tendermint_rpc::error::Error as RpcError;

use crate::e2e::setup::{
    copy_wasm_to_chain_dir, get_all_wasms_hashes, TestDir, ENV_VAR_KEEP_TEMP,
    SINGLE_NODE_NET_GENESIS,
};

pub struct MockNode {
    shell: RefCell<Shell<MockDB, Sha256Hasher>>,
    _broadcast_recv: UnboundedReceiver<Vec<u8>>,
}

impl Deref for MockNode {
    type Target = Shell<MockDB, Sha256Hasher>;

    fn deref(&self) -> &Self::Target {
        &*self.shell.borrow()
    }
}

impl DerefMut for MockNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.shell.get_mut()
    }
}

impl MockNode {
    pub fn next_epoch(&mut self) -> Epoch {
        self.wl_storage.storage.next_epoch_min_start_height =
            self.wl_storage.storage.get_last_block_height() + 1;
        self.wl_storage.storage.next_epoch_min_start_time = DateTimeUtc::now();
        let next_epoch_min_start_height =
            self.wl_storage.storage.next_epoch_min_start_height;
        if let Some(LastBlock { height, .. }) =
            self.wl_storage.storage.last_block.as_mut()
        {
            *height = next_epoch_min_start_height;
        }
        self.finalize_and_commit();

        for _ in 0..EPOCH_SWITCH_BLOCKS_DELAY {
            self.finalize_and_commit();
        }
        self.wl_storage.storage.get_current_epoch().0
    }

    /// Simultaneously call the `FinalizeBlock` and
    /// `Commit` handlers.
    pub fn finalize_and_commit(&mut self) {
        let mut req = FinalizeBlock {
            hash: BlockHash([0u8; 32]),
            header: Header {
                hash: Hash([0; 32]),
                time: DateTimeUtc::now(),
                next_validators_hash: Hash([0; 32]),
            },
            byzantine_validators: vec![],
            txs: vec![],
            proposer_address: vec![],
            votes: vec![],
        };
        req.header.time = DateTimeUtc::now();
        self.finalize_block(req).expect("Test failed");
        self.shell.commit();
    }

    fn client<'a>(&mut self, args: Vec<&'a str>) {}
}

#[async_trait::async_trait(?Send)]
impl Client for MockNode{
    type Error = Report;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> std::result::Result<EncodedResponseQuery, Self::Error> {
        let rpc = TEST_RPC;
        let data = data.unwrap_or_default();
        let height = height.unwrap_or_default();
        // Handle a path by invoking the `RPC.handle` directly with the
        // borrowed storage
        let request = RequestQuery {
            data,
            path,
            height,
            prove,
        };

        let ctx = RequestCtx {
            wl_storage: &self.wl_storage,
            event_log: self.event_log(),
            vp_wasm_cache: self.vp_wasm_cache.read_only(),
            tx_wasm_cache: self.tx_wasm_cache.read_only(),
            storage_read_past_height_limit: None,
        };
        let response = rpc.handle(ctx, &request).unwrap();
        Ok(response)
    }

    async fn perform<R>(
        &self,
        request: R,
    ) -> std::result::Result<R::Response, RpcError>
    where
        R: SimpleRequest,
    {
        unreachable!()
    }


    /// `/abci_info`: get information about the ABCI application.
    async fn abci_info(&self) -> Result<abci_info::AbciInfo, Self::Error> {
        Ok(AbciInfo{
            data: "Namada".to_string(),
            version: "test".to_string(),
            app_version: 0,
            last_block_height: self.wl_storage
                .storage
                .last_block
                .map(|b| b.height.0)
                .unwrap_or_default()
                .into(),
            last_block_app_hash: self.wl_storage
                .storage
                .last_block
                .map(|b| b.hash.0)
                .unwrap_or_default()
                .to_vec(),
        })
    }

    /// `/broadcast_tx_sync`: broadcast a transaction, returning the response
    /// from `CheckTx`.
    async fn broadcast_tx_sync(
        &self,
        tx: namada::tendermint::abci::Transaction,
    ) -> Result<tendermint_rpc::endpoint::broadcast::tx_sync::Response, RpcError>
    {
        let mut resp = tendermint_rpc::endpoint::broadcast::tx_sync::Response {
            code: Default::default(),
            data: Default::default(),
            log: Default::default(),
            hash: tendermint::abci::transaction::Hash::new([0; 32]),
        };
        let tx_bytes = tx.0;
        let req = namada_apps::facade::tendermint_proto::abci::RequestProcessProposal{
            txs: vec![tx_bytes],
            ..Default::default()
        };
        resp.code = (self.shell.borrow_mut().process_proposal(req).status as u32).into();
        if resp.code.is_ok() {
            let req = FinalizeBlock {
                hash: BlockHash([0u8; 32]),
                header: Header {
                    hash: Hash([0; 32]),
                    time: DateTimeUtc::now(),
                    next_validators_hash: Hash([0; 32]),
                },
                byzantine_validators: vec![],
                txs: vec![tx_bytes],
                proposer_address: vec![],
                votes: vec![],
            };
            self.shell.borrow_mut().finalize_block(req);
        }
        Ok(resp)
    }

    /// `/block`: get the latest block.
    async fn latest_block(&self) -> Result<block::Response, RpcError> {
        unreachable!()
    }

    /// `/block`: get block at a given height.
    async fn block<H>(&self, height: H) -> Result<block::Response, RpcError>
        where
            H: Into<namada::tendermint::block::Height> + Send,
    {
        unreachable!()
    }

    /// `/block_search`: search for blocks by BeginBlock and EndBlock events.
    async fn block_search(
        &self,
        query: namada::tendermint_rpc::query::Query,
        page: u32,
        per_page: u8,
        order: namada::tendermint_rpc::Order,
    ) -> Result<tendermint_rpc::endpoint::block_search::Response, RpcError>
    {
        self.perform(tendermint_rpc::endpoint::block_search::Request::new(
            query, page, per_page, order,
        ))
            .await
    }

    /// `/block_results`: get ABCI results for a block at a particular height.
    async fn block_results<H>(
        &self,
        height: H,
    ) -> Result<tendermint_rpc::endpoint::block_results::Response, RpcError>
        where
            H: Into<namada::tendermint::block::Height> + Send,
    {
        self.perform(tendermint_rpc::endpoint::block_results::Request::new(
            height.into(),
        ))
            .await
    }

    /// `/tx_search`: search for transactions with their results.
    async fn tx_search(
        &self,
        query: namada::tendermint_rpc::query::Query,
        prove: bool,
        page: u32,
        per_page: u8,
        order: namada::tendermint_rpc::Order,
    ) -> Result<tendermint_rpc::endpoint::tx_search::Response, RpcError> {
        self.perform(tendermint_rpc::endpoint::tx_search::Request::new(
            query, prove, page, per_page, order,
        ))
            .await
    }

    /// `/abci_query`: query the ABCI application
    async fn abci_query<V>(
        &self,
        path: Option<namada::tendermint::abci::Path>,
        data: V,
        height: Option<namada::tendermint::block::Height>,
        prove: bool,
    ) -> Result<tendermint_rpc::endpoint::abci_query::AbciQuery, RpcError>
        where
            V: Into<Vec<u8>> + Send,
    {
        Ok(self
            .perform(tendermint_rpc::endpoint::abci_query::Request::new(
                path, data, height, prove,
            ))
            .await?
            .response)
    }

    /// `/block_results`: get ABCI results for the latest block.
    async fn latest_block_results(
        &self,
    ) -> Result<block_results::Response, RpcError> {
        todo!()
    }

    /// `/blockchain`: get block headers for `min` <= `height` <= `max`.
    ///
    /// Block headers are returned in descending order (highest first).
    ///
    /// Returns at most 20 items.
    async fn blockchain<H>(
        &self,
        min: H,
        max: H,
    ) -> Result<blockchain::Response, RpcError>
        where
            H: Into<namada::tendermint::block::Height> + Send,
    {
        todo!()
    }

    /// `/commit`: get block commit at a given height.
    async fn commit<H>(&self, height: H) -> Result<commit::Response, RpcError>
        where
            H: Into<namada::tendermint::block::Height> + Send,
    {
        self.perform(commit::Request::new(height.into())).await
    }

    /// `/consensus_params`: get current consensus parameters at the specified
    /// height.
    async fn consensus_params<H>(
        &self,
        height: H,
    ) -> Result<consensus_params::Response, RpcError>
        where
            H: Into<namada::tendermint::block::Height> + Send,
    {
        self.perform(consensus_params::Request::new(Some(height.into())))
            .await
    }

    /// `/consensus_state`: get current consensus state
    async fn consensus_state(
        &self,
    ) -> Result<consensus_state::Response, RpcError> {
        self.perform(consensus_state::Request::new()).await
    }

    /// `/consensus_params`: get the latest consensus parameters.
    async fn latest_consensus_params(
        &self,
    ) -> Result<consensus_params::Response, RpcError> {
        self.perform(consensus_params::Request::new(None)).await
    }

    /// `/commit`: get the latest block commit
    async fn latest_commit(&self) -> Result<commit::Response, RpcError> {
        self.perform(commit::Request::default()).await
    }

    /// `/health`: get node health.
    ///
    /// Returns empty result (200 OK) on success, no response in case of an
    /// error.
    async fn health(&self) -> Result<(), RpcError> {
        Ok(())
    }

    /// `/net_info`: obtain information about P2P and other network connections.
    async fn net_info(&self) -> Result<net_info::Response, RpcError> {
        unreachable!()
    }

    /// `/status`: get Tendermint status including node info, pubkey, latest
    /// block hash, app hash, block height and time.
    async fn status(&self) -> Result<status::Response, RpcError> {
       unreachable!()
    }

}

/// Setup a network with a single genesis validator node.
pub fn setup() -> Result<MockNode> {
    initialize_genesis(|genesis| genesis)
}

/// Setup folders with genesis, configs, wasm, etc.
pub fn initialize_genesis(
    mut update_genesis: impl FnMut(GenesisConfig) -> GenesisConfig,
) -> Result<MockNode> {
    let working_dir = std::fs::canonicalize("..").unwrap();
    // env::set_var(ENV_VAR_KEEP_TEMP, "true");
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
            chain_id_prefix: ChainIdPrefix::from_str("integration-test".into())
                .unwrap(),
            unsafe_dont_encrypt: true,
            consensus_timeout_commit: Timeout::from_str("1s").unwrap(),
            localhost: true,
            allow_duplicate_ip: true,
            dont_archive: true,
            archive_dir: None,
        },
    );

    create_node(test_dir.path(), &genesis)
}

/// Create a mock ledger node.
fn create_node(base_dir: &Path, genesis: &GenesisConfig) -> Result<MockNode> {
    // look up the chain id from the genesis file.
    let chain_id = if let toml::Value::String(chain_id) =
        toml::from_str::<Table>(
            &std::fs::read_to_string(base_dir.join("global-config.toml"))
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
    let wasm_dir = base_dir.join(Path::new(&chain_id)).join("wasm");
    // copy compiled wasms into the wasm directory
    let chain_id = ChainId::from_str(&chain_id).unwrap();
    copy_wasm_to_chain_dir(
        &std::fs::canonicalize("..").unwrap(),
        &base_dir.join(Path::new(&chain_id.to_string())),
        &chain_id,
        genesis.validator.keys(),
    );

    // instantiate and initialize the ledger node.
    let (sender, recv) = tokio::sync::mpsc::unbounded_channel();
    let mut node = MockNode {
        shell: Shell::new(
            config::Ledger::new(
                base_dir,
                chain_id.clone(),
                TendermintMode::Validator
            ),
            wasm_dir,
            sender,
            None,
            50 * 1024 * 1024, // 50 kiB
            50 * 1024 * 1024, // 50 kiB
            Address::from_str("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").unwrap(),
        ),
        _broadcast_recv: recv,
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
    node.shell
        .init_chain(init_req, 1)
        .map_err(|e| eyre!("Failed to initialize ledger: {:?}", e))?;
    Ok(node)
}
