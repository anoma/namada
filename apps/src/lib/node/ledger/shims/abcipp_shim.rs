use std::convert::TryFrom;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
use namada::proof_of_stake::{
    find_validator_by_raw_hash, write_current_block_proposer_address,
};
use namada::types::address::Address;
#[cfg(not(feature = "abcipp"))]
use namada::types::hash::Hash;
#[cfg(not(feature = "abcipp"))]
use namada::types::key::tm_raw_hash_to_string;
#[cfg(not(feature = "abcipp"))]
use namada::types::storage::BlockHash;
#[cfg(not(feature = "abcipp"))]
use namada::types::transaction::hash_tx;
use tokio::sync::mpsc::UnboundedSender;
use tower::Service;

use super::super::Shell;
use super::abcipp_shim_types::shim::request::{FinalizeBlock, ProcessedTx};
#[cfg(not(feature = "abcipp"))]
use super::abcipp_shim_types::shim::TxBytes;
use super::abcipp_shim_types::shim::{Error, Request, Response};
use crate::config;
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
            AbciService { shell_send },
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
                Req::ProcessProposal(proposal) => {
                    println!("\nRECEIVED REQUEST PROCESSPROPOSAL");
                    self.service
                        .call(Request::ProcessProposal(proposal))
                        .map_err(Error::from)
                        .and_then(|res| match res {
                            Response::ProcessProposal(resp) => {
                                Ok(Resp::ProcessProposal((&resp).into()))
                            }
                            _ => unreachable!(),
                        })
                }
                #[cfg(feature = "abcipp")]
                Req::FinalizeBlock(block) => {
                    println!("RECEIVED REQUEST FINALIZEBLOCK");
                    let unprocessed_txs = block.txs.clone();
                    let processing_results =
                        self.service.process_txs(&block.txs);
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
                    println!("RECEIVED REQUEST BEGINBLOCK");
                    if let Some(header) = block.header.clone() {
                        if !header.proposer_address.is_empty() {
                            let tm_raw_hash_string = tm_raw_hash_to_string(
                                header.proposer_address.clone(),
                            );
                            let native_proposer_address =
                                find_validator_by_raw_hash(
                                    &self.service.wl_storage,
                                    tm_raw_hash_string,
                                )
                                .unwrap()
                                .expect(
                                    "Unable to find native validator address \
                                     of block proposer from tendermint raw \
                                     hash",
                                );
                            println!(
                                "BLOCK PROPOSER (BEGINBLOCK): {}",
                                native_proposer_address
                            );
                            write_current_block_proposer_address(
                                &mut self.service.wl_storage,
                                native_proposer_address,
                            )
                            .unwrap();
                        }
                    }
                    // we save this data to be forwarded to finalize later
                    self.begin_block_request = Some(block);
                    Ok(Resp::BeginBlock(Default::default()))
                }
                #[cfg(not(feature = "abcipp"))]
                Req::DeliverTx(tx) => {
                    println!("RECEIVED REQUEST DELIVERTX");
                    self.delivered_txs.push(tx.tx);
                    Ok(Resp::DeliverTx(Default::default()))
                }
                #[cfg(not(feature = "abcipp"))]
                Req::EndBlock(_) => {
                    println!("RECEIVED REQUEST ENDBLOCK");
                    let processing_results =
                        self.service.process_txs(&self.delivered_txs);
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
                        self.begin_block_request.take().unwrap().into();
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
