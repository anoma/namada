use std::mem::ManuallyDrop;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use color_eyre::eyre::{Report, Result};
use data_encoding::HEXUPPER;
use lazy_static::lazy_static;
use namada::ledger::events::log::dumb_queries;
use namada::ledger::queries::{
    EncodedResponseQuery, RequestCtx, RequestQuery, Router, RPC,
};
use namada::ledger::storage::{
    LastBlock, Sha256Hasher, EPOCH_SWITCH_BLOCKS_DELAY,
};
use namada::proof_of_stake::pos_queries::PosQueries;
use namada::proof_of_stake::types::WeightedValidator;
use namada::proof_of_stake::{
    read_consensus_validator_set_addresses_with_stake,
    validator_consensus_key_handle,
};
use namada::sdk::queries::Client;
use namada::tendermint_proto::abci::VoteInfo;
use namada::tendermint_rpc::endpoint::abci_info;
use namada::tendermint_rpc::SimpleRequest;
use namada::types::hash::Hash;
use namada::types::key::tm_consensus_key_raw_hash;
use namada::types::storage::{BlockHash, BlockHeight, Epoch, Header};
use namada::types::time::DateTimeUtc;
use num_traits::cast::FromPrimitive;
use regex::Regex;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::facade::tendermint_proto::abci::response_process_proposal::ProposalStatus;
use crate::facade::tendermint_proto::abci::{
    RequestPrepareProposal, RequestProcessProposal,
};
use crate::facade::tendermint_rpc::endpoint::abci_info::AbciInfo;
use crate::facade::tendermint_rpc::error::Error as RpcError;
use crate::facade::{tendermint, tendermint_rpc};
use crate::node::ledger::shell::testing::utils::TestDir;
use crate::node::ledger::shell::{ErrorCodes, Shell};
use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
    FinalizeBlock, ProcessedTx,
};
use crate::node::ledger::shims::abcipp_shim_types::shim::response::TxResult;
use crate::node::ledger::storage;

/// Status of tx
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeResults {
    /// Success
    Ok,
    /// Rejected by Process Proposal
    Rejected(TxResult),
    /// Failure in application in Finalize Block
    Failed(ErrorCodes),
}

pub struct MockNode {
    pub shell: Arc<Mutex<Shell<storage::PersistentDB, Sha256Hasher>>>,
    pub test_dir: ManuallyDrop<TestDir>,
    pub keep_temp: bool,
    pub _broadcast_recv: UnboundedReceiver<Vec<u8>>,
    pub results: Arc<Mutex<Vec<NodeResults>>>,
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
            validator: Some(namada::tendermint_proto::abci::Validator {
                address: pkh1.clone(),
                power: u128::try_from(val1.bonded_stake).unwrap() as i64,
            }),
            signed_last_block: true,
        }];

        (pkh1, votes)
    }

    /// Simultaneously call the `FinalizeBlock` and
    /// `Commit` handlers.
    pub fn finalize_and_commit(&self) {
        let (proposer_address, votes) = self.prepare_request();

        let mut req = FinalizeBlock {
            hash: BlockHash([0u8; 32]),
            header: Header {
                hash: Hash([0; 32]),
                time: DateTimeUtc::now(),
                next_validators_hash: Hash([0; 32]),
            },
            byzantine_validators: vec![],
            txs: vec![],
            proposer_address,
            votes,
        };
        req.header.time = DateTimeUtc::now();
        let mut locked = self.shell.lock().unwrap();
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
    fn submit_tx(&self, tx_bytes: Vec<u8>) {
        // The block space allocator disallows txs in certain blocks.
        // Advance to block height that allows txs.
        self.advance_to_allowed_block();
        let (proposer_address, votes) = self.prepare_request();

        let req = RequestProcessProposal {
            txs: vec![tx_bytes.clone()],
            proposer_address: proposer_address.clone(),
            ..Default::default()
        };
        let mut locked = self.shell.lock().unwrap();
        let mut result = locked.process_proposal(req);

        let mut errors: Vec<_> = result
            .tx_results
            .iter()
            .map(|e| {
                if e.code == 0 {
                    NodeResults::Ok
                } else {
                    NodeResults::Rejected(e.clone())
                }
            })
            .collect();
        if result.status != i32::from(ProposalStatus::Accept) {
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
            txs: vec![ProcessedTx {
                tx: tx_bytes,
                result: result.tx_results.remove(0),
            }],
            proposer_address,
            votes,
        };

        // process the results
        let resp = locked.finalize_block(req).unwrap();
        let mut error_codes = resp
            .events
            .into_iter()
            .map(|e| {
                let code = ErrorCodes::from_u32(
                    e.attributes
                        .get("code")
                        .map(|e| u32::from_str(e).unwrap())
                        .unwrap_or_default(),
                )
                .unwrap();
                if code == ErrorCodes::Ok {
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

#[async_trait::async_trait(?Send)]
impl<'a> Client for &'a MockNode {
    type Error = Report;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> std::result::Result<EncodedResponseQuery, Self::Error> {
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
            data,
            path,
            height,
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
        rpc.handle(ctx, &request).map_err(Report::new)
    }

    async fn perform<R>(
        &self,
        _request: R,
    ) -> std::result::Result<R::Response, RpcError>
    where
        R: SimpleRequest,
    {
        unreachable!()
    }

    /// `/abci_info`: get information about the ABCI application.
    async fn abci_info(&self) -> Result<abci_info::AbciInfo, RpcError> {
        let locked = self.shell.lock().unwrap();
        Ok(AbciInfo {
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
        let tx_bytes: Vec<u8> = tx.into();
        self.submit_tx(tx_bytes);
        if !self.success() {
            resp.code = tendermint::abci::Code::Err(1337); // TODO: submit_tx should return the correct error code + message
            return Ok(resp);
        } else {
            self.clear_results();
        }
        let (proposer_address, _) = self.prepare_request();
        let req = RequestPrepareProposal {
            proposer_address,
            ..Default::default()
        };
        let tx_bytes = {
            let locked = self.shell.lock().unwrap();
            locked.prepare_proposal(req).txs.remove(0)
        };
        self.submit_tx(tx_bytes);
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
            .map(|event| namada::tendermint::abci::responses::Event {
                type_str: event.event_type.to_string(),
                attributes: event
                    .attributes
                    .iter()
                    .map(|(k, v)| namada::tendermint::abci::tag::Tag {
                        key: k.parse().unwrap(),
                        value: v.parse().unwrap(),
                    })
                    .collect(),
            })
            .collect();
        let has_events = !events.is_empty();

        Ok(tendermint_rpc::endpoint::block_results::Response {
            height,
            txs_results: None,
            begin_block_events: None,
            end_block_events: has_events.then_some(events),
            validator_updates: vec![],
            consensus_param_updates: None,
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
