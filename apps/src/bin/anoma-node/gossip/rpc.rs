use anoma::proto::services::rpc_service_server::{
    RpcService, RpcServiceServer,
};
use anoma::proto::services::{rpc_message, RpcMessage, RpcResponse};
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;
use tonic::transport::Server;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

#[derive(Debug)]
struct Rpc {
    inject_message:
        mpsc::Sender<(rpc_message::Message, oneshot::Sender<RpcResponse>)>,
}

#[tonic::async_trait]
impl RpcService for Rpc {
    async fn send_message(
        &self,
        request: TonicRequest<RpcMessage>,
    ) -> Result<TonicResponse<RpcResponse>, Status> {
        if let RpcMessage { message: Some(msg) } = request.into_inner() {
            let (sender, receiver) = oneshot::channel();
            self.inject_message
                .send((msg, sender))
                .await
                .map_err(|err|
                         Status::cancelled(format!{"failed to send message to gossip app: {:?}",err})
                )?
                ;
            let response = receiver.await.map_err(|err|
                Status::data_loss(format!{"failed to receive response from gossip app: {:?}", err}))?;
            Ok(TonicResponse::new(response))
        } else {
            tracing::error!("Received empty rpc message, nothing can be done");
            Ok(TonicResponse::new(RpcResponse::default()))
        }
    }
}

#[tokio::main]
pub async fn rpc_server(
    inject_message: Sender<(
        rpc_message::Message,
        oneshot::Sender<RpcResponse>,
    )>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:39111".parse().unwrap();

    let rpc = Rpc { inject_message };

    let svc = RpcServiceServer::new(rpc);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}
