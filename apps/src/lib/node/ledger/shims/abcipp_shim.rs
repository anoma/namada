use std::convert::TryFrom;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
use namada::proof_of_stake::find_validator_by_raw_hash;
use namada::types::address::Address;
#[cfg(not(feature = "abcipp"))]
use namada::types::hash::Hash;
use namada::types::key::tm_raw_hash_to_string;
#[cfg(not(feature = "abcipp"))]
use namada::types::storage::BlockHash;
use namada::types::storage::BlockHeight;
#[cfg(not(feature = "abcipp"))]
use namada::types::transaction::hash_tx;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedSender;
use tower::Service;

use super::super::Shell;
use super::abcipp_shim_types::shim::request::{FinalizeBlock, ProcessedTx};
#[cfg(not(feature = "abcipp"))]
use super::abcipp_shim_types::shim::TxBytes;
use super::abcipp_shim_types::shim::{Error, Request, Response};
use crate::config;
use crate::config::{Action, ActionAtHeight};
#[cfg(not(feature = "abcipp"))]
use crate::facade::tendermint_proto::abci::RequestBeginBlock;
use crate::facade::tower_abci::{BoxError, Request as Req, Response as Resp};

/// The shim wraps the shell, which implements ABCI++.
/// The shim makes a crude translation between the ABCI interface currently used
/// by tendermint and the shell's interface.
#[derive(Debug)]
pub struct AbcippShim {
    service: Shell,
    #[cfg(not(feature = "abcipp"))]
    begin_block_request: Option<RequestBeginBlock>,
    #[cfg(not(feature = "abcipp"))]
    delivered_txs: Vec<TxBytes>,
    shell_recv: std::sync::mpsc::Receiver<(
        Req,
        tokio::sync::oneshot::Sender<Result<Resp, BoxError>>,
    )>,
}

impl AbcippShim {
    /// Create a shell with a ABCI service that passes messages to and from the
    /// shell.
    pub fn new(
        config: config::Ledger,
        wasm_dir: PathBuf,
        broadcast_sender: UnboundedSender<Vec<u8>>,
        db_cache: &rocksdb::Cache,
        vp_wasm_compilation_cache: u64,
        tx_wasm_compilation_cache: u64,
        native_token: Address,
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
                    Some(db_cache),
                    vp_wasm_compilation_cache,
                    tx_wasm_compilation_cache,
                    native_token,
                ),
                #[cfg(not(feature = "abcipp"))]
                begin_block_request: None,
                #[cfg(not(feature = "abcipp"))]
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

    #[cfg(not(feature = "abcipp"))]
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
                    .and_then(|res| match res {
                        Response::ProcessProposal(resp) => {
                            Ok(Resp::ProcessProposal((&resp).into()))
                        }
                        _ => unreachable!(),
                    }),
                #[cfg(feature = "abcipp")]
                Req::FinalizeBlock(block) => {
                    let block_time =
                        self.service.get_block_timestamp(block.time.clone());
                    let unprocessed_txs = block.txs.clone();
                    let (processing_results, _) =
                        self.service.process_txs(&block.txs, block_time);
                    let mut txs = Vec::with_capacity(unprocessed_txs.len());
                    for (result, tx) in processing_results
                        .into_iter()
                        .zip(unprocessed_txs.into_iter())
                    {
                        txs.push(ProcessedTx { tx, result });
                    }
                    let mut finalize_req: FinalizeBlock = block.into();
                    finalize_req.txs = txs;
                    self.service
                        .call(Request::FinalizeBlock(finalize_req))
                        .map_err(Error::from)
                        .and_then(|res| match res {
                            Response::FinalizeBlock(resp) => {
                                Ok(Resp::FinalizeBlock(resp.into()))
                            }
                            _ => Err(Error::ConvertResp(res)),
                        })
                }
                #[cfg(not(feature = "abcipp"))]
                Req::BeginBlock(block) => {
                    // we save this data to be forwarded to finalize later
                    self.begin_block_request = Some(block);
                    Ok(Resp::BeginBlock(Default::default()))
                }
                #[cfg(not(feature = "abcipp"))]
                Req::DeliverTx(tx) => {
                    self.delivered_txs.push(tx.tx);
                    Ok(Resp::DeliverTx(Default::default()))
                }
                #[cfg(not(feature = "abcipp"))]
                Req::EndBlock(_) => {
                    let begin_block_request =
                        self.begin_block_request.take().unwrap();
                    let block_time = self.service.get_block_timestamp(
                        begin_block_request
                            .header
                            .as_ref()
                            .and_then(|header| header.time.to_owned()),
                    );

                    let block_proposer = begin_block_request
                        .header
                        .as_ref()
                        .and_then(|header| {
                            let tm_raw_hash_string =
                                tm_raw_hash_to_string(&header.proposer_address);
                            find_validator_by_raw_hash(
                                &self.service.wl_storage,
                                tm_raw_hash_string,
                            )
                            .unwrap()
                        });

                    let (processing_results, _) = self.service.process_txs(
                        &self.delivered_txs,
                        block_time,
                        block_proposer.as_ref(),
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
                    end_block_request.hash = BlockHash::from(hash.clone());
                    end_block_request.txs = txs;
                    self.service
                        .call(Request::FinalizeBlock(end_block_request))
                        .map_err(Error::from)
                        .and_then(|res| match res {
                            Response::FinalizeBlock(resp) => {
                                Ok(Resp::EndBlock(resp.into()))
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
        let result = self.shell_send.send((req, resp_send));

        async move {
            if let Err(err) = result {
                // The shell has shut-down
                return Err(err.into());
            }
            match recv.await {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::info!("ABCI response channel didn't respond");
                    Err(err.into())
                }
            }
        }
        .boxed()
    }

    /// Given the type of request, determine if we need to check
    /// to possibly take an action.
    fn get_action(&self, req: &Req) -> Option<CheckAction> {
        match req {
            Req::PrepareProposal(req) => Some(CheckAction::Check(req.height)),
            Req::ProcessProposal(req) => Some(CheckAction::Check(req.height)),
            Req::EndBlock(req) => Some(CheckAction::Check(req.height)),
            Req::BeginBlock(_)
            | Req::DeliverTx(_)
            | Req::InitChain(_)
            | Req::CheckTx(_)
            | Req::Commit(_) => {
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
