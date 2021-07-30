use std::convert::{TryFrom, TryInto};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anoma_shared::types::storage::{BlockHash, BlockHeight};
use futures::future::FutureExt;
use tower::{Service, ServiceBuilder};
use tower_abci::{response, split, BoxError, Request as Req, Response as Resp, Server};

use super::abcipp_shim_types::shim::{Error, Response, Request, TxBytes};

/// The shim wraps the shell, which implements ABCI++
/// The shim makes a crude translation between the ABCI
/// interface currently used by tendermint and the shell's
/// interface
pub struct AbcippShim<S: Service<Request>> {
    service: S,
    block_txs: Vec<TxBytes>,
}

/// This is the actual tower service that we run for now.
/// It provides the translation between tendermints interface
/// and the interface of the shell service.
impl<S> Service<Req> for AbcippShim<S>
    where S: Service<Request>
{
    type Error = BoxError;
    type Future = Pin<
        Box<dyn Future<Output = Result<Resp, BoxError>> + Send + 'static>,
    >;
    type Response = Resp;

    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Req) -> Self::Future {
        tracing::debug!(?req);
        let rsp: Result<Resp, Error> = match req {
            Req::BeginBlock(block) => {
                // we simply forward BeginBlock request to the PrepareProposal request
                self.service
                    .call(Request::PrepareProposal(block.into()))
                    .await
                    .map(Resp::BeginBlock)
                    .map_err(Error::from)
            }
            Req::DeliverTx(deliver_tx) => {
                // We store all the transactions to be applied in
                // bulk at a later step
                self.block_txs.push(deliver_tx.tx);
                Ok(Resp::DeliverTx(Default::default()))
            }
            Req::EndBlock(end) => {
                self.service.call(Request::FinalizeBlock(self.block_txs.into())).await;
                self.block_txs = vec!();
                if BlockHeight::try_from(end.height).is_err() {
                    // TODO: Should we panic?
                    tracing::error!("Unexpected block height {}", end.height);
                };
                Ok(Resp::EndBlock(Default::default()))
            },
            _ => {
                request = Request::try_from(req.clone())?;
                let response = self.service.call(request).await;
                match response {
                    resp @ Ok(_) => Resp::try_from(resp),
                    Err(err) => Err(Error::Shell(err))
                }
            }
        };
        tracing::debug!(?rsp);
        Box::pin(async move { rsp.map_err(|e| e.into()) }.boxed())
    }
}