use anoma::protobuf::services::RpcResponse;
use anoma::protobuf::{
    services::rpc_service_server::{RpcService, RpcServiceServer},
    types::{self, IntentMessage},
};

use tokio::sync::mpsc::{self, Sender};
use tonic::transport::Server;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

#[derive(Debug)]
struct Rpc {
    tx: mpsc::Sender<IntentMessage>,
}

#[tonic::async_trait]
impl RpcService for Rpc {
    async fn send_message(
        &self,
        request: TonicRequest<types::Message>,
    ) -> Result<TonicResponse<RpcResponse>, Status> {
        let types::Message {
            message: intent_message,
        }: &types::Message = request.get_ref();
        match intent_message {
            Some(types::message::Message::IntentMessage(msg)) => {
                println!("received a intent {:?}", msg);
                self.tx.send(msg.clone()).await.unwrap();
            }
            Some(types::message::Message::DkgMsg(msg)) => {
                println!("received dkg msg {:?}, not implemented yet", msg);
            }
            None => {
                println!("empty rpc message received, nothing done");
            }
        }
        Ok(TonicResponse::new(RpcResponse::default()))
    }
}

#[tokio::main]
pub async fn rpc_server(
    tx: Sender<IntentMessage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:39111".parse().unwrap();

    let rpc = Rpc { tx };

    let svc = RpcServiceServer::new(rpc);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}
