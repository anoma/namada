use std::convert::{TryFrom, TryInto};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anoma_shared::types::storage::{BlockHash, BlockHeight};
use futures::future::FutureExt;
use tower::{Service, ServiceBuilder};
use tower_abci::{response, split, BoxError, Request as Req, Response as Resp, Server};

use super::abcipp_shim_types::shim::{Response, Request};

pub struct AbcippShim<S: Service<Req>> {
    service: S,
}

impl<S> Service<Req> for AbcippShim<S>
    where S: Service<Req>
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

    fn call(&mut self, req: Requ) -> Self::Future {
        tracing::debug!(?req);
        let rsp = match req {
            Req::BeginBlock(block) => {
               self.service(Request::PrepareProposal(block.into()))
                   .map(|resp| Response::BeginBlock(resp.into()))
            }
            Request::DeliverTx(deliver_tx) => {
                Ok(Response::DeliverTx(self.apply_tx(deliver_tx)))
            }
            Request::EndBlock(end) => match BlockHeight::try_from(end.height) {
                Ok(height) => Ok(Response::EndBlock(self.end_block(height))),
                Err(_) => {
                    tracing::error!("Unexpected block height {}", end.height);
                    Ok(Response::EndBlock(Default::default()))
                }
            },
            _ => self.service.call(req.clone())
        };
        tracing::debug!(?rsp);
        Box::pin(async move { rsp.map_err(|e| e.into()) }.boxed())
    }
}