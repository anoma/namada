use anoma::protobuf::services::rpc_service_server::{
    RpcService, RpcServiceServer,
};
use anoma::protobuf::services::{rpc_message, RpcMessage, RpcResponse};
use tokio::sync::mpsc::{self, Sender};
use tonic::transport::Server;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

#[derive(Debug)]
struct Rpc {
    tx: mpsc::Sender<rpc_message::Message>,
}

#[tonic::async_trait]
impl RpcService for Rpc {
    async fn send_message(
        &self,
        request: TonicRequest<RpcMessage>,
    ) -> Result<TonicResponse<RpcResponse>, Status> {
        if let RpcMessage { message: Some(msg) } = request.into_inner() {
            self.tx.send(msg).await.expect("failed to send message")
        } else {
            log::error!("Received empty rpc message, nothing can be done");
        }
        Ok(TonicResponse::new(RpcResponse::default()))
    }
}

#[tokio::main]
pub async fn rpc_server(
    tx: Sender<rpc_message::Message>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:39111".parse().unwrap();

    let rpc = Rpc { tx };

    let svc = RpcServiceServer::new(rpc);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}
