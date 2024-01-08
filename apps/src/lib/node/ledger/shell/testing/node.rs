use std::future::poll_fn;
use std::mem::ManuallyDrop;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use color_eyre::eyre::{Report, Result};
use data_encoding::HEXUPPER;
use itertools::Either;
use lazy_static::lazy_static;
use namada::eth_bridge::oracle::config::Config as OracleConfig;
use namada::ledger::dry_run_tx;
use namada::ledger::events::log::dumb_queries;
use namada::ledger::queries::{
    EncodedResponseQuery, RequestCtx, RequestQuery, Router, RPC,
};
use namada::proof_of_stake::pos_queries::PosQueries;
use namada::proof_of_stake::storage::{
    read_consensus_validator_set_addresses_with_stake,
    validator_consensus_key_handle,
};
use namada::proof_of_stake::types::WeightedValidator;
use namada::state::{LastBlock, Sha256Hasher, EPOCH_SWITCH_BLOCKS_DELAY};
use namada::tendermint::abci::response::Info;
use namada::tendermint::abci::types::VoteInfo;
use namada::tendermint_rpc::SimpleRequest;
use namada::types::control_flow::time::Duration;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::ethereum_structs;
use namada::types::hash::Hash;
use namada::types::key::tm_consensus_key_raw_hash;
use namada::types::storage::{BlockHash, BlockHeight, Epoch, Header};
use namada::types::time::DateTimeUtc;
use namada_sdk::queries::Client;
use namada_sdk::tx::data::ResultCode;
use regex::Regex;
use tokio::sync::mpsc;

use crate::facade::tendermint_proto::v0_37::abci::{
    RequestPrepareProposal, RequestProcessProposal,
};
use crate::facade::tendermint_rpc::error::Error as RpcError;
use crate::facade::{tendermint, tendermint_rpc};
use crate::node::ledger::ethereum_oracle::test_tools::mock_web3_client::{
    TestOracle, Web3Client, Web3Controller,
};
use crate::node::ledger::ethereum_oracle::{
    control, last_processed_block, try_process_eth_events,
};
use crate::node::ledger::shell::testing::utils::TestDir;
use crate::node::ledger::shell::{EthereumOracleChannels, Shell};
use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
    FinalizeBlock, ProcessedTx,
};
use crate::node::ledger::shims::abcipp_shim_types::shim::response::TxResult;
use crate::node::ledger::storage;

/// Mock Ethereum oracle used for testing purposes.
struct MockEthOracle {
    /// The inner oracle.
    oracle: TestOracle,
    /// The inner oracle's configuration.
    config: OracleConfig,
    /// The inner oracle's next block to process.
    next_block_to_process: tokio::sync::RwLock<ethereum_structs::BlockHeight>,
}

impl MockEthOracle {
    /// Updates the state of the Ethereum oracle.
    ///
    /// This includes sending any confirmed Ethereum events to
    /// the shell and updating the height of the next Ethereum
    /// block to process. Upon a successfully processed block,
    /// this functions returns `true`.
    async fn drive(&self) -> bool {
        try_process_eth_events(
            &self.oracle,
            &self.config,
            &*self.next_block_to_process.read().await,
        )
        .await
        .process_new_block()
    }
}

/// Services mocking the operation of the ledger's various async tasks.
pub struct MockServices {
    /// Receives transactions that are supposed to be broadcasted
    /// to the network.
    tx_receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Mock Ethereum oracle, that processes blocks from Ethereum
    /// in order to find events emitted by a transaction to vote on.
    ethereum_oracle: MockEthOracle,
}

/// Actions to be performed by the mock node, as a result
/// of driving [`MockServices`].
pub enum MockServiceAction {
    /// The ledger should broadcast new transactions.
    BroadcastTxs(Vec<Vec<u8>>),
    /// Progress to the next Ethereum block to process.
    IncrementEthHeight,
}

impl MockServices {
    /// Drive the internal state machine of the mock node's services.
    async fn drive(&self) -> Vec<MockServiceAction> {
        let mut actions = vec![];

        // process new eth events
        // NOTE: this may result in a deadlock, if the events
        // sent to the shell exceed the capacity of the oracle's
        // events channel!
        if self.ethereum_oracle.drive().await {
            actions.push(MockServiceAction::IncrementEthHeight);
        }

        // receive txs from the broadcaster
        let txs = {
            let mut txs = vec![];
            let mut tx_receiver = self.tx_receiver.lock().await;

            while let Some(tx) = poll_fn(|cx| match tx_receiver.poll_recv(cx) {
                Poll::Pending => Poll::Ready(None),
                poll => poll,
            })
            .await
            {
                txs.push(tx);
            }

            txs
        };
        if !txs.is_empty() {
            actions.push(MockServiceAction::BroadcastTxs(txs));
        }

        actions
    }
}

/// Controller of various mock node services.
pub struct MockServicesController {
    /// Ethereum oracle controller.
    pub eth_oracle: Web3Controller,
    /// Handler to the Ethereum oracle sender channel.
    ///
    /// Bypasses the Ethereum oracle service and sends
    /// events directly to the [`Shell`].
    pub eth_events: mpsc::Sender<EthereumEvent>,
    /// Transaction broadcaster handle.
    pub tx_broadcaster: mpsc::UnboundedSender<Vec<u8>>,
}

/// Service handlers to be passed to a [`Shell`], when building
/// a mock node.
pub struct MockServiceShellHandlers {
    /// Transaction broadcaster handle.
    pub tx_broadcaster: mpsc::UnboundedSender<Vec<u8>>,
    /// Ethereum oracle channel handlers.
    pub eth_oracle_channels: Option<EthereumOracleChannels>,
}

/// Mock services data returned by [`mock_services`].
pub struct MockServicesPackage {
    /// Whether to automatically drive mock services or not.
    pub auto_drive_services: bool,
    /// Mock services stored by the [`MockNode`].
    pub services: MockServices,
    /// Handlers to mock services stored by the [`Shell`].
    pub shell_handlers: MockServiceShellHandlers,
    /// Handler to the mock services controller.
    pub controller: MockServicesController,
}

/// Mock services config.
pub struct MockServicesCfg {
    /// Whether to automatically drive mock services or not.
    pub auto_drive_services: bool,
    /// Whether to enable the Ethereum oracle or not.
    pub enable_eth_oracle: bool,
}

/// Instantiate mock services for a node.
pub fn mock_services(cfg: MockServicesCfg) -> MockServicesPackage {
    let (_, eth_client) = Web3Client::setup();
    let (eth_sender, eth_receiver) = mpsc::channel(1000);
    let (last_processed_block_sender, last_processed_block_receiver) =
        last_processed_block::channel();
    let (control_sender, control_receiver) = control::channel();
    let eth_oracle_controller = eth_client.controller();
    let oracle = TestOracle::new(
        Either::Left(eth_client),
        eth_sender.clone(),
        last_processed_block_sender,
        Duration::from_millis(5),
        Duration::from_secs(30),
        control_receiver,
    );
    let eth_oracle_channels = EthereumOracleChannels::new(
        eth_receiver,
        control_sender,
        last_processed_block_receiver,
    );
    let (tx_broadcaster, tx_receiver) = mpsc::unbounded_channel();
    let ethereum_oracle = MockEthOracle {
        oracle,
        config: Default::default(),
        next_block_to_process: tokio::sync::RwLock::new(Default::default()),
    };
    MockServicesPackage {
        auto_drive_services: cfg.auto_drive_services,
        services: MockServices {
            ethereum_oracle,
            tx_receiver: tokio::sync::Mutex::new(tx_receiver),
        },
        shell_handlers: MockServiceShellHandlers {
            tx_broadcaster: tx_broadcaster.clone(),
            eth_oracle_channels: cfg
                .enable_eth_oracle
                .then_some(eth_oracle_channels),
        },
        controller: MockServicesController {
            eth_oracle: eth_oracle_controller,
            eth_events: eth_sender,
            tx_broadcaster,
        },
    }
}

/// Status of tx
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeResults {
    /// Success
    Ok,
    /// Rejected by Process Proposal
    Rejected(TxResult),
    /// Failure in application in Finalize Block
    Failed(ResultCode),
}

pub struct MockNode {
    pub shell: Arc<Mutex<Shell<storage::PersistentDB, Sha256Hasher>>>,
    pub test_dir: ManuallyDrop<TestDir>,
    pub keep_temp: bool,
    pub results: Arc<Mutex<Vec<NodeResults>>>,
    pub services: Arc<MockServices>,
    pub auto_drive_services: bool,
}

impl Drop for MockNode {
    fn drop(&mut self) {
        unsafe {
            if !self.keep_temp {
                ManuallyDrop::take(&mut self.test_dir).clean_up()
            } else {
                println!(
                    "Keeping tempfile at {}",
                    self.test_dir.path().to_string_lossy()
                );
                ManuallyDrop::drop(&mut self.test_dir)
            }
        }
    }
}

impl MockNode {
    pub async fn handle_service_action(&self, action: MockServiceAction) {
        match action {
            MockServiceAction::BroadcastTxs(txs) => {
                self.submit_txs(txs);
            }
            MockServiceAction::IncrementEthHeight => {
                *self
                    .services
                    .ethereum_oracle
                    .next_block_to_process
                    .write()
                    .await += 1.into();
            }
        }
    }

    pub async fn drive_mock_services(&self) {
        for action in self.services.drive().await {
            self.handle_service_action(action).await;
        }
    }

    async fn drive_mock_services_bg(&self) {
        if self.auto_drive_services {
            self.drive_mock_services().await;
        }
    }

    pub fn genesis_dir(&self) -> PathBuf {
        self.test_dir
            .path()
            .join(self.shell.lock().unwrap().chain_id.to_string())
    }

    pub fn genesis_path(&self) -> PathBuf {
        self.test_dir
            .path()
            .join(format!("{}.toml", self.shell.lock().unwrap().chain_id))
    }

    pub fn wasm_dir(&self) -> PathBuf {
        self.genesis_path().join("wasm")
    }

    pub fn wallet_path(&self) -> PathBuf {
        self.genesis_dir().join("wallet.toml")
    }

    pub fn current_epoch(&self) -> Epoch {
        self.shell.lock().unwrap().wl_storage.storage.last_epoch
    }

    pub fn next_epoch(&mut self) -> Epoch {
        {
            let mut locked = self.shell.lock().unwrap();

            let next_epoch_height =
                locked.wl_storage.storage.get_last_block_height() + 1;
            locked.wl_storage.storage.next_epoch_min_start_height =
                next_epoch_height;
            locked.wl_storage.storage.next_epoch_min_start_time =
                DateTimeUtc::now();
            let next_epoch_min_start_height =
                locked.wl_storage.storage.next_epoch_min_start_height;
            if let Some(LastBlock { height, .. }) =
                locked.wl_storage.storage.last_block.as_mut()
            {
                *height = next_epoch_min_start_height;
            }
        }
        self.finalize_and_commit();

        for _ in 0..EPOCH_SWITCH_BLOCKS_DELAY {
            self.finalize_and_commit();
        }
        self.shell
            .lock()
            .unwrap()
            .wl_storage
            .storage
            .get_current_epoch()
            .0
    }

    /// Get the address of the block proposer and the votes for the block
    fn prepare_request(&self) -> (Vec<u8>, Vec<VoteInfo>) {
        let (val1, ck) = {
            let locked = self.shell.lock().unwrap();
            let params = locked.wl_storage.pos_queries().get_pos_params();
            let current_epoch = locked.wl_storage.storage.get_current_epoch().0;
            let consensus_set: Vec<WeightedValidator> =
                read_consensus_validator_set_addresses_with_stake(
                    &locked.wl_storage,
                    current_epoch,
                )
                .unwrap()
                .into_iter()
                .collect();

            let val1 = consensus_set[0].clone();
            let ck = validator_consensus_key_handle(&val1.address)
                .get(&locked.wl_storage, current_epoch, &params)
                .unwrap()
                .unwrap();
            (val1, ck)
        };

        let hash_string = tm_consensus_key_raw_hash(&ck);
        let pkh1 = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
        let votes = vec![VoteInfo {
            validator: tendermint::abci::types::Validator {
                address: pkh1.clone().try_into().unwrap(),
                power: (u128::try_from(val1.bonded_stake).expect("Test failed")
                    as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];

        (pkh1, votes)
    }

    /// Simultaneously call the `FinalizeBlock` and
    /// `Commit` handlers.
    pub fn finalize_and_commit(&self) {
        let (proposer_address, votes) = self.prepare_request();

        let mut locked = self.shell.lock().unwrap();

        // build finalize block abci request
        let req = {
            // check if we have protocol txs to be included
            // in the finalize block request
            let txs = {
                let req = RequestPrepareProposal {
                    proposer_address: proposer_address.clone().into(),
                    ..Default::default()
                };
                let txs = locked.prepare_proposal(req).txs;

                txs.into_iter()
                    .map(|tx| ProcessedTx {
                        tx,
                        result: TxResult {
                            code: 0,
                            info: String::new(),
                        },
                    })
                    .collect()
            };
            FinalizeBlock {
                hash: BlockHash([0u8; 32]),
                header: Header {
                    hash: Hash([0; 32]),
                    time: DateTimeUtc::now(),
                    next_validators_hash: Hash([0; 32]),
                },
                byzantine_validators: vec![],
                txs,
                proposer_address,
                votes,
            }
        };

        locked.finalize_block(req).expect("Test failed");
        locked.commit();
    }

    /// Advance to a block height that allows
    /// txs
    fn advance_to_allowed_block(&self) {
        loop {
            let not_allowed =
                { self.shell.lock().unwrap().encrypted_txs_not_allowed() };
            if not_allowed {
                self.finalize_and_commit();
            } else {
                break;
            }
        }
    }

    /// Send a tx through Process Proposal and Finalize Block
    /// and register the results.
    fn submit_txs(&self, txs: Vec<Vec<u8>>) {
        // The block space allocator disallows encrypted txs in certain blocks.
        // Advance to block height that allows txs.
        self.advance_to_allowed_block();
        let (proposer_address, votes) = self.prepare_request();

        let req = RequestProcessProposal {
            txs: txs.clone().into_iter().map(|tx| tx.into()).collect(),
            proposer_address: proposer_address.clone().into(),
            ..Default::default()
        };
        let mut locked = self.shell.lock().unwrap();
        let (result, tx_results) = locked.process_proposal(req);

        let mut errors: Vec<_> = tx_results
            .iter()
            .map(|e| {
                if e.code == 0 {
                    NodeResults::Ok
                } else {
                    NodeResults::Rejected(e.clone())
                }
            })
            .collect();
        if result != tendermint::abci::response::ProcessProposal::Accept {
            self.results.lock().unwrap().append(&mut errors);
            return;
        }

        // process proposal succeeded, now run finalize block
        let req = FinalizeBlock {
            hash: BlockHash([0u8; 32]),
            header: Header {
                hash: Hash([0; 32]),
                time: DateTimeUtc::now(),
                next_validators_hash: Hash([0; 32]),
            },
            byzantine_validators: vec![],
            txs: txs
                .into_iter()
                .zip(tx_results.into_iter())
                .map(|(tx, result)| ProcessedTx {
                    tx: tx.into(),
                    result,
                })
                .collect(),
            proposer_address,
            votes,
        };

        // process the results
        let resp = locked.finalize_block(req).unwrap();
        let mut error_codes = resp
            .events
            .into_iter()
            .map(|e| {
                let code = ResultCode::from_u32(
                    e.attributes
                        .get("code")
                        .map(|e| u32::from_str(e).unwrap())
                        .unwrap_or_default(),
                )
                .unwrap();
                if code == ResultCode::Ok {
                    NodeResults::Ok
                } else {
                    NodeResults::Failed(code)
                }
            })
            .collect::<Vec<_>>();
        self.results.lock().unwrap().append(&mut error_codes);
        locked.commit();
    }

    /// Check that applying a tx succeeded.
    pub fn success(&self) -> bool {
        self.results
            .lock()
            .unwrap()
            .iter()
            .all(|r| *r == NodeResults::Ok)
    }

    pub fn clear_results(&self) {
        self.results.lock().unwrap().clear();
    }

    pub fn assert_success(&self) {
        if !self.success() {
            panic!(
                "Assert failed: The node did not execute \
                 successfully:\nErrors:\n    {:?}",
                self.results.lock().unwrap()
            );
        } else {
            self.clear_results();
        }
    }
}

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
impl<'a> Client for &'a MockNode {
    type Error = Report;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> std::result::Result<EncodedResponseQuery, Self::Error> {
        self.drive_mock_services_bg().await;
        let rpc = RPC;
        let data = data.unwrap_or_default();
        let latest_height = {
            self.shell
                .lock()
                .unwrap()
                .wl_storage
                .storage
                .last_block
                .as_ref()
                .map(|b| b.height)
                .unwrap_or_default()
        };
        let height = height.unwrap_or(latest_height);
        // Handle a path by invoking the `RPC.handle` directly with the
        // borrowed storage
        let request = RequestQuery {
            data: data.into(),
            path,
            height: height.try_into().unwrap(),
            prove,
        };
        let borrowed = self.shell.lock().unwrap();
        let ctx = RequestCtx {
            wl_storage: &borrowed.wl_storage,
            event_log: borrowed.event_log(),
            vp_wasm_cache: borrowed.vp_wasm_cache.read_only(),
            tx_wasm_cache: borrowed.tx_wasm_cache.read_only(),
            storage_read_past_height_limit: None,
        };
        if request.path == "/shell/dry_run_tx" {
            dry_run_tx(ctx, &request)
        } else {
            rpc.handle(ctx, &request)
        }
        .map_err(Report::new)
    }

    async fn perform<R>(
        &self,
        _request: R,
    ) -> std::result::Result<R::Output, RpcError>
    where
        R: SimpleRequest,
    {
        unreachable!()
    }

    /// `/abci_info`: get information about the ABCI application.
    async fn abci_info(&self) -> Result<Info, RpcError> {
        self.drive_mock_services_bg().await;
        let locked = self.shell.lock().unwrap();
        Ok(Info {
            data: "Namada".to_string(),
            version: "test".to_string(),
            app_version: 0,
            last_block_height: locked
                .wl_storage
                .storage
                .last_block
                .as_ref()
                .map(|b| b.height.0 as u32)
                .unwrap_or_default()
                .into(),
            last_block_app_hash: locked
                .wl_storage
                .storage
                .last_block
                .as_ref()
                .map(|b| b.hash.0)
                .unwrap_or_default()
                .to_vec()
                .try_into()
                .unwrap(),
        })
    }

    /// `/broadcast_tx_sync`: broadcast a transaction, returning the response
    /// from `CheckTx`.
    async fn broadcast_tx_sync(
        &self,
        tx: impl Into<Vec<u8>>,
    ) -> Result<tendermint_rpc::endpoint::broadcast::tx_sync::Response, RpcError>
    {
        self.drive_mock_services_bg().await;
        let mut resp = tendermint_rpc::endpoint::broadcast::tx_sync::Response {
            code: Default::default(),
            data: Default::default(),
            log: Default::default(),
            hash: tendermint::Hash::default(),
        };
        let tx_bytes: Vec<u8> = tx.into();
        self.submit_txs(vec![tx_bytes]);
        if !self.success() {
            // TODO: submit_txs should return the correct error code + message
            resp.code = 1337.into();
            return Ok(resp);
        } else {
            self.clear_results();
        }
        let (proposer_address, _) = self.prepare_request();
        let req = RequestPrepareProposal {
            proposer_address: proposer_address.into(),
            ..Default::default()
        };
        let txs: Vec<Vec<u8>> = {
            let locked = self.shell.lock().unwrap();
            locked.prepare_proposal(req).txs
        }
        .into_iter()
        .map(|tx| tx.into())
        .collect();
        if !txs.is_empty() {
            self.submit_txs(txs);
        }
        Ok(resp)
    }

    /// `/block_search`: search for blocks by BeginBlock and EndBlock events.
    async fn block_search(
        &self,
        query: namada::tendermint_rpc::query::Query,
        _page: u32,
        _per_page: u8,
        _order: namada::tendermint_rpc::Order,
    ) -> Result<tendermint_rpc::endpoint::block_search::Response, RpcError>
    {
        self.drive_mock_services_bg().await;
        let matcher = parse_tm_query(query);
        let borrowed = self.shell.lock().unwrap();
        // we store an index into the event log as a block
        // height in the response of the query... VERY NAISSSE
        let matching_events = borrowed.event_log().iter().enumerate().flat_map(
            |(index, event)| {
                if matcher.matches(event) {
                    Some(EncodedEvent(index as u64))
                } else {
                    None
                }
            },
        );
        let blocks = matching_events
            .map(|encoded_event| namada::tendermint_rpc::endpoint::block::Response {
                block_id: Default::default(),
                block: namada::tendermint_proto::types::Block {
                    header: Some(namada::tendermint_proto::types::Header {
                        version: Some(namada::tendermint_proto::version::Consensus {
                            block: 0,
                            app: 0,
                        }),
                        chain_id: "Namada".try_into().unwrap(),
                        height: encoded_event.0 as i64,
                        time: None,
                        last_block_id: None,
                        last_commit_hash: vec![],
                        data_hash: vec![],
                        validators_hash: vec![],
                        next_validators_hash: vec![],
                        consensus_hash: vec![],
                        app_hash: vec![],
                        last_results_hash: vec![],
                        evidence_hash: vec![],
                        proposer_address: vec![]

                    }),
                    data: Default::default(),
                    evidence: Default::default(),
                    last_commit: Some(namada::tendermint_proto::types::Commit {
                        height: encoded_event.0 as i64,
                        round: 0,
                        block_id: Some(namada::tendermint_proto::types::BlockId {
                            hash: vec![0u8; 32],
                            part_set_header: Some(namada::tendermint_proto::types::PartSetHeader {
                                total: 1,
                                hash: vec![1; 32],
                            }),
                        }),
                        signatures: vec![],
                    }),
                }.try_into().unwrap(),
            })
            .collect::<Vec<_>>();

        Ok(namada::tendermint_rpc::endpoint::block_search::Response {
            total_count: blocks.len() as u32,
            blocks,
        })
    }

    /// `/block_results`: get ABCI results for a block at a particular height.
    async fn block_results<H>(
        &self,
        height: H,
    ) -> Result<tendermint_rpc::endpoint::block_results::Response, RpcError>
    where
        H: Into<namada::tendermint::block::Height> + Send,
    {
        self.drive_mock_services_bg().await;
        let height = height.into();
        let encoded_event = EncodedEvent(height.value());
        let locked = self.shell.lock().unwrap();
        let events: Vec<_> = locked
            .event_log()
            .iter()
            .enumerate()
            .flat_map(|(index, event)| {
                if index == encoded_event.log_index() {
                    Some(event)
                } else {
                    None
                }
            })
            .map(|event| namada::tendermint::abci::Event {
                kind: event.event_type.to_string(),
                attributes: event
                    .attributes
                    .iter()
                    .map(|(k, v)| namada::tendermint::abci::EventAttribute {
                        key: k.parse().unwrap(),
                        value: v.parse().unwrap(),
                        index: true,
                    })
                    .collect(),
            })
            .collect();
        let has_events = !events.is_empty();

        Ok(tendermint_rpc::endpoint::block_results::Response {
            height,
            txs_results: None,
            finalize_block_events: vec![],
            begin_block_events: None,
            end_block_events: has_events.then_some(events),
            validator_updates: vec![],
            consensus_param_updates: None,
            app_hash: namada::tendermint::hash::AppHash::default(),
        })
    }

    /// `/tx_search`: search for transactions with their results.
    async fn tx_search(
        &self,
        _query: namada::tendermint_rpc::query::Query,
        _prove: bool,
        _page: u32,
        _per_page: u8,
        _order: namada::tendermint_rpc::Order,
    ) -> Result<tendermint_rpc::endpoint::tx_search::Response, RpcError> {
        // In the past, some cli commands for masp called this. However, these
        // commands are not currently supported, so we do not need to fill
        // in this function for now.
        unreachable!()
    }

    /// `/health`: get node health.
    ///
    /// Returns empty result (200 OK) on success, no response in case of an
    /// error.
    async fn health(&self) -> Result<(), RpcError> {
        self.drive_mock_services_bg().await;
        Ok(())
    }
}

/// Parse a Tendermint query.
fn parse_tm_query(
    query: namada::tendermint_rpc::query::Query,
) -> dumb_queries::QueryMatcher {
    const QUERY_PARSING_REGEX_STR: &str =
        r"^tm\.event='NewBlock' AND (accepted|applied)\.hash='([^']+)'$";

    lazy_static! {
        /// Compiled regular expression used to parse Tendermint queries.
        static ref QUERY_PARSING_REGEX: Regex = Regex::new(QUERY_PARSING_REGEX_STR).unwrap();
    }

    let query = query.to_string();
    let captures = QUERY_PARSING_REGEX.captures(&query).unwrap();

    match captures.get(0).unwrap().as_str() {
        "accepted" => dumb_queries::QueryMatcher::accepted(
            captures.get(1).unwrap().as_str().try_into().unwrap(),
        ),
        "applied" => dumb_queries::QueryMatcher::applied(
            captures.get(1).unwrap().as_str().try_into().unwrap(),
        ),
        _ => unreachable!("We only query accepted or applied txs"),
    }
}

/// A Namada event log index and event type encoded as
/// a Tendermint block height.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
struct EncodedEvent(u64);

impl EncodedEvent {
    /// Get the encoded event log index.
    const fn log_index(self) -> usize {
        self.0 as usize
    }
}
