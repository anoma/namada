//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::protobuf::services::rpc_service_client::RpcServiceClient;
use anoma::protobuf::types;

use anoma::cli::{ClientOpts, Gossip, InlinedClientOpts, Transfer};
use anoma::types::{Message, Transaction};
use clap::Clap;
use tendermint_rpc::{Client, HttpClient};

pub async fn main() {
    match ClientOpts::parse() {
        ClientOpts::Inlined(ops) => exec_inlined(ops).await,
    }
}

async fn exec_inlined(ops: InlinedClientOpts) {
    match ops {
        InlinedClientOpts::Transfer(transaction) => transfer(transaction).await,
        InlinedClientOpts::Gossip(Gossip { orderbook, data }) => {
            gossip(orderbook, data).await.unwrap();
        }
    }
}

async fn transfer(Transfer { src, dest, amount }: Transfer) {
    // TODO add a counter
    let tx = Transaction { src, dest, amount };
    let mut tx_bytes = vec![];
    tx.encode(&mut tx_bytes).unwrap();
    let client =
        HttpClient::new("tcp://127.0.0.1:26657".parse().unwrap()).unwrap();
    // TODO broadcast_tx_commit shouldn't be used live
    let response = client.broadcast_tx_commit(tx_bytes.into()).await;
    println!("{:#?}", response);
}

async fn gossip(
    _orderbook_addr: String,
    data: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = RpcServiceClient::connect("http://[::1]:39111").await?;
    let intent = Some(types::Intent { data });
    let intent_message = types::IntentMessage { intent };
    let message = types::Message {
        message: Some(types::message::Message::IntentMessage(intent_message)),
    };
    let _response = client.send_message(message).await?;
    Ok(())
}
