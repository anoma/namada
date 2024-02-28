use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
use namada::core::hash::Hash;
use namada::core::key::tm_raw_hash_to_string;
use namada::core::storage::{BlockHash, BlockHeight};
use namada::proof_of_stake::storage::find_validator_by_raw_hash;
use namada::time::{DateTimeUtc, Utc};
use namada::tx::data::hash_tx;
use namada::tx::Tx;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedSender;
use tower::Service;

use super::abcipp_shim_types::shim::request::{FinalizeBlock, ProcessedTx};
use super::abcipp_shim_types::shim::{Error, Request, Response, TxBytes};
use crate::config;
use crate::config::{Action, ActionAtHeight};
use crate::facade::tendermint::v0_37::abci::response::DeliverTx;
use crate::facade::tendermint::v0_37::abci::{
    request, Request as Req, Response as Resp,
};
use crate::facade::tendermint_proto::v0_37::abci::ResponseDeliverTx;
use crate::facade::tower_abci::BoxError;
use crate::node::ledger::shell::{EthereumOracleChannels, Shell};

/// The shim wraps the shell, which implements ABCI++.
/// The shim makes a crude translation between the ABCI interface currently used
/// by tendermint and the shell's interface.
#[derive(Debug)]
pub struct AbcippShim {
    service: Shell,
    begin_block_request: Option<request::BeginBlock>,
    delivered_txs: Vec<TxBytes>,
    shell_recv: std::sync::mpsc::Receiver<(
        Req,
        tokio::sync::oneshot::Sender<Result<Resp, BoxError>>,
    )>,
}

impl AbcippShim {
    /// Create a shell with a ABCI service that passes messages to and from the
    /// shell.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: config::Ledger,
        wasm_dir: PathBuf,
        broadcast_sender: UnboundedSender<Vec<u8>>,
        eth_oracle: Option<EthereumOracleChannels>,
        db_cache: &rocksdb::Cache,
        vp_wasm_compilation_cache: u64,
        tx_wasm_compilation_cache: u64,
    ) -> (Self, AbciService, broadcast::Sender<()>) {
        // We can use an unbounded channel here, because tower-abci limits the
        // the number of requests that can come in

        let (shell_send, shell_recv) = std::sync::mpsc::channel();
        let (server_shutdown, _) = broadcast::channel::<()>(1);
        let action_at_height = config.shell.action_at_height.clone();
        (
            Self {
                service: Shell::new(
                    config,
                    wasm_dir,
                    broadcast_sender,
                    eth_oracle,
                    Some(db_cache),
                    vp_wasm_compilation_cache,
                    tx_wasm_compilation_cache,
                ),
                begin_block_request: None,
                delivered_txs: vec![],
                shell_recv,
            },
            AbciService {
                shell_send,
                shutdown: server_shutdown.clone(),
                action_at_height,
                suspended: false,
            },
            server_shutdown,
        )
    }

    /// Get the hash of the txs in the block
    pub fn get_hash(&self) -> Hash {
        let bytes: Vec<u8> =
            self.delivered_txs.iter().flat_map(Clone::clone).collect();
        hash_tx(bytes.as_slice())
    }

    /// Run the shell's blocking loop that receives messages from the
    /// [`AbciService`].
    pub fn run(mut self) {
        while let Ok((req, resp_sender)) = self.shell_recv.recv() {
            let resp = match req {
                Req::ProcessProposal(proposal) => self
                    .service
                    .call(Request::ProcessProposal(proposal))
                    .map_err(Error::from)
                    .and_then(|resp| resp.try_into()),
                Req::BeginBlock(block) => {
                    // we save this data to be forwarded to finalize later
                    self.begin_block_request = Some(block);
                    Ok(Resp::BeginBlock(Default::default()))
                }
                Req::DeliverTx(tx) => {
                    let mut deliver: DeliverTx = Default::default();
                    // Attach events to this transaction if possible
                    if Tx::try_from(&tx.tx[..]).is_ok() {
                        let resp = ResponseDeliverTx::default();
                        deliver.events = resp
                            .events
                            .into_iter()
                            .map(|v| TryFrom::try_from(v).unwrap())
                            .collect();
                    }
                    self.delivered_txs.push(tx.tx);
                    Ok(Resp::DeliverTx(deliver))
                }
                Req::EndBlock(_) => {
                    let begin_block_request =
                        self.begin_block_request.take().unwrap();
                    let block_time = begin_block_request
                        .header
                        .time
                        .try_into()
                        .expect("valid RFC3339 block time");

                    let tm_raw_hash_string = tm_raw_hash_to_string(
                        begin_block_request.header.proposer_address,
                    );
                    let block_proposer = find_validator_by_raw_hash(
                        &self.service.state,
                        tm_raw_hash_string,
                    )
                    .unwrap()
                    .expect(
                        "Unable to find native validator address of block \
                         proposer from tendermint raw hash",
                    );

                    let (processing_results, _) = self.service.process_txs(
                        &self.delivered_txs,
                        block_time,
                        &block_proposer,
                    );
                    let mut txs = Vec::with_capacity(self.delivered_txs.len());
                    let mut delivered = vec![];
                    std::mem::swap(&mut self.delivered_txs, &mut delivered);
                    for (result, tx) in processing_results
                        .into_iter()
                        .zip(delivered.into_iter())
                    {
                        txs.push(ProcessedTx { tx, result });
                    }
                    let mut end_block_request: FinalizeBlock =
                        begin_block_request.into();
                    let hash = self.get_hash();
                    end_block_request.hash = BlockHash::from(hash);
                    end_block_request.txs = txs;
                    self.service
                        .call(Request::FinalizeBlock(end_block_request))
                        .map_err(Error::from)
                        .and_then(|res| match res {
                            Response::FinalizeBlock(resp) => {
                                Ok(Resp::EndBlock(crate::facade::tendermint_proto::v0_37::abci::ResponseEndBlock::from(resp).try_into().unwrap()))
                            }
                            _ => Err(Error::ConvertResp(res)),
                        })
                }
                _ => match Request::try_from(req.clone()) {
                    Ok(request) => self
                        .service
                        .call(request)
                        .map(Resp::try_from)
                        .map_err(Error::Shell)
                        .and_then(|inner| inner),
                    Err(err) => Err(err),
                },
            };

            let resp = resp.map_err(|e| e.into());
            if resp_sender.send(resp).is_err() {
                tracing::info!("ABCI response channel is closed")
            }
        }
    }
}

/// Indicates how [`AbciService`] should
/// check whether or not it needs to take
/// action.
#[derive(Debug)]
enum CheckAction {
    /// No check necessary.
    NoAction,
    /// Check a given block height.
    Check(i64),
    /// The action been taken.
    AlreadySuspended,
}

#[derive(Debug)]
pub struct AbciService {
    /// A channel for forwarding requests to the shell
    shell_send: std::sync::mpsc::Sender<(
        Req,
        tokio::sync::oneshot::Sender<Result<Resp, BoxError>>,
    )>,
    /// Indicates if the consensus connection is suspended.
    suspended: bool,
    /// This resolves the non-completing futures returned to tower-abci
    /// during suspension.
    shutdown: broadcast::Sender<()>,
    /// An action to be taken at a specified block height.
    action_at_height: Option<ActionAtHeight>,
}

impl AbciService {
    /// Check if we are at a block height with a scheduled action.
    /// If so, perform the action.
    fn maybe_take_action(
        action_at_height: Option<ActionAtHeight>,
        check: CheckAction,
        mut shutdown_recv: broadcast::Receiver<()>,
    ) -> (bool, Option<<Self as Service<Req>>::Future>) {
        let hght = match check {
            CheckAction::AlreadySuspended => BlockHeight::from(u64::MAX),
            CheckAction::Check(hght) => BlockHeight::from(hght as u64),
            CheckAction::NoAction => BlockHeight::default(),
        };
        match action_at_height {
            Some(ActionAtHeight {
                height,
                action: Action::Suspend,
            }) if height <= hght => {
                if height == hght {
                    tracing::info!(
                        "Reached block height {}, suspending.",
                        height
                    );
                    tracing::warn!(
                        "\x1b[93mThis feature is intended for debugging \
                         purposes. Note that on shutdown a spurious panic \
                         message will be produced.\x1b[0m"
                    )
                }
                (
                    true,
                    Some(
                        async move {
                            shutdown_recv.recv().await.unwrap();
                            Err(BoxError::from(
                                "Not all tendermint responses were processed. \
                                 If the `--suspended` flag was passed, you \
                                 may ignore this error.",
                            ))
                        }
                        .boxed(),
                    ),
                )
            }
            Some(ActionAtHeight {
                height,
                action: Action::Halt,
            }) if height == hght => {
                tracing::info!(
                    "Reached block height {}, halting the chain.",
                    height
                );
                (
                    false,
                    Some(
                        async move {
                            Err(BoxError::from(format!(
                                "Reached block height {}, halting the chain.",
                                height
                            )))
                        }
                        .boxed(),
                    ),
                )
            }
            _ => (false, None),
        }
    }

    /// If we are not taking special action for this request,
    /// forward it normally.
    fn forward_request(&mut self, req: Req) -> <Self as Service<Req>>::Future {
        let (resp_send, recv) = tokio::sync::oneshot::channel();
        let result = self.shell_send.send((req.clone(), resp_send));
        async move {
            let genesis_time = if let Req::InitChain(ref init) = req {
                Some(
                    DateTimeUtc::try_from(init.time)
                        .expect("Should be able to parse genesis time."),
                )
            } else {
                None
            };
            if let Err(err) = result {
                // The shell has shut-down
                return Err(err.into());
            }
            recv.await
                .unwrap_or_else(|err| {
                    tracing::info!("ABCI response channel didn't respond");
                    Err(err.into())
                })
                .map(|res| {
                    // emit a log line stating that we are sleeping until
                    // genesis.
                    if let Some(Ok(sleep_time)) = genesis_time
                        .map(|t| t.0.signed_duration_since(Utc::now()).to_std())
                    {
                        if !sleep_time.is_zero() {
                            tracing::info!(
                                "Waiting for ledger genesis time: {:?}, time \
                                 left: {:?}",
                                genesis_time.unwrap(),
                                sleep_time
                            );
                        }
                    }
                    res
                })
        }
        .boxed()
    }

    /// Given the type of request, determine if we need to check
    /// to possibly take an action.
    fn get_action(&self, req: &Req) -> Option<CheckAction> {
        match req {
            Req::PrepareProposal(req) => {
                Some(CheckAction::Check(req.height.into()))
            }
            Req::ProcessProposal(req) => {
                Some(CheckAction::Check(req.height.into()))
            }
            Req::EndBlock(req) => Some(CheckAction::Check(req.height)),
            Req::BeginBlock(_)
            | Req::DeliverTx(_)
            | Req::InitChain(_)
            | Req::CheckTx(_)
            | Req::Commit => {
                if self.suspended {
                    Some(CheckAction::AlreadySuspended)
                } else {
                    Some(CheckAction::NoAction)
                }
            }
            _ => None,
        }
    }
}

/// The ABCI tower service implementation sends and receives messages to and
/// from the [`AbcippShim`] for requests from Tendermint.
impl Service<Req> for AbciService {
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Resp, BoxError>> + Send + 'static>>;
    type Response = Resp;

    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        // Nothing to check as the sender's channel is unbounded
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let action = self.get_action(&req);
        if let Some(action) = action {
            let (suspended, fut) = Self::maybe_take_action(
                self.action_at_height.clone(),
                action,
                self.shutdown.subscribe(),
            );
            self.suspended = suspended;
            fut.unwrap_or_else(|| self.forward_request(req))
        } else {
            self.forward_request(req)
        }
    }
}
