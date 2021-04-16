use anoma::protobuf::services::rpc_service_server::{
    RpcService, RpcServiceServer,
};
use anoma::protobuf::services::{rpc_message, RpcMessage, RpcResponse};
use anoma::protobuf::types::Intent;
use tokio::sync::mpsc::{self, Sender};
use tonic::transport::Server;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

#[derive(Debug)]
struct Rpc {
    tx: mpsc::Sender<Intent>,
}

#[tonic::async_trait]
impl RpcService for Rpc {
    async fn send_message(
        &self,
        request: TonicRequest<RpcMessage>,
    ) -> Result<TonicResponse<RpcResponse>, Status> {
        if let RpcMessage { message: Some(msg) } = request.into_inner() {
            match msg {
                rpc_message::Message::Intent(intent) => {
                    self.tx.send(intent).await.expect("failed to send intent")
                }
                rpc_message::Message::Dkg(dkg_msg) => println!(
                    "received dkg msg {:?}, not implemented yet",
                    dkg_msg
                ),
            }
        } else {
            log::error!("Received empty rpc message, nothing can be done");
        }
        Ok(TonicResponse::new(RpcResponse::default()))
    }
}

#[tokio::main]
pub async fn rpc_server(
    tx: Sender<Intent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:39111".parse().unwrap();

    let rpc = Rpc { tx };

    let svc = RpcServiceServer::new(rpc);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}
