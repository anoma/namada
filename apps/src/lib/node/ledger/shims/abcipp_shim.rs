use std::convert::TryFrom;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
use namada::types::ethereum_events::EthereumEvent;
use tendermint_proto::abci::ResponseFinalizeBlock;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tower::Service;
use tower_abci::{BoxError, Request as Req, Response as Resp};

use super::super::Shell;
use super::abcipp_shim_types::shim::request::{FinalizeBlock, ProcessedTx};
use super::abcipp_shim_types::shim::response::TxResult;
use super::abcipp_shim_types::shim::{Error, Request, Response};
use crate::config;

/// The shim wraps the shell, which implements ABCI++.
/// The shim makes a crude translation between the ABCI interface currently used
/// by tendermint and the shell's interface.
#[derive(Debug)]
pub struct AbcippShim {
    service: Shell,
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
        eth_receiver: Option<UnboundedReceiver<EthereumEvent>>,
        db_cache: &rocksdb::Cache,
        vp_wasm_compilation_cache: u64,
        tx_wasm_compilation_cache: u64,
    ) -> (Self, AbciService) {
        // We can use an unbounded channel here, because tower-abci limits the
        // the number of requests that can come in
        let (shell_send, shell_recv) = std::sync::mpsc::channel();
        (
            Self {
                service: Shell::new(
                    config,
                    wasm_dir,
                    broadcast_sender,
                    eth_receiver,
                    Some(db_cache),
                    vp_wasm_compilation_cache,
                    tx_wasm_compilation_cache,
                ),
                shell_recv,
            },
            AbciService { shell_send },
        )
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
                            Ok(Resp::ProcessProposal(resp))
                        }
                        _ => unreachable!(),
                    }),
                Req::FinalizeBlock(block) => {
                    // Process transactions first in the same way as
                    // `ProcessProposal`.
                    let unprocessed_txs = block.txs.clone();
                    let processing_results =
                        self.service.process_txs(&block.txs);
                    let mut txs = Vec::with_capacity(unprocessed_txs.len());
                    for (result, tx) in processing_results
                        .iter()
                        .map(TxResult::from)
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
                                let mut resp: ResponseFinalizeBlock =
                                    resp.into();

                                // Add processing results
                                for (tx_result, processing_result) in resp
                                    .tx_results
                                    .iter_mut()
                                    .zip(processing_results)
                                {
                                    tx_result
                                        .events
                                        .extend(processing_result.events);
                                }

                                Ok(Resp::FinalizeBlock(resp))
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

#[derive(Debug)]
pub struct AbciService {
    shell_send: std::sync::mpsc::Sender<(
        Req,
        tokio::sync::oneshot::Sender<Result<Resp, BoxError>>,
    )>,
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
        let (resp_send, recv) = tokio::sync::oneshot::channel();
        let result = self.shell_send.send((req, resp_send));
        Box::pin(
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
            .boxed(),
        )
    }
}
