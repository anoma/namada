//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::protobuf::services::rpc_service_client::RpcServiceClient;
use anoma::protobuf::types;
use anoma::{cli::CliBuilder, protobuf::types::Tx};
use color_eyre::eyre::Result;
use prost::Message;
use tendermint_rpc::{Client, HttpClient};

pub async fn main() -> Result<()> {
    let matches = CliBuilder::new().anoma_client_cli();

    match matches.subcommand() {
        Some((CliBuilder::TX_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let path = args.value_of("path").unwrap().to_string();
            let data = args.value_of("data");
            Ok(exec_tx(path, data).await)
        }
        Some((CliBuilder::INTENT_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let orderbook = args.value_of("orderbook").unwrap().to_string();
            let data = args.value_of("data").unwrap().to_string();
            Ok(gossip_intent(orderbook, data).await)
        }
        _ => Ok(()),
    }
}

async fn exec_tx(code_path: String, data_hex: Option<&str>) {
    // TODO tendermint cache blocks the same transaction sent more than once,
    // add a counter or timestamp?

    let code = std::fs::read(code_path).unwrap();
    let data = data_hex.map(|hex| hex::decode(hex).unwrap());
    let tx = Tx { code, data };
    let mut tx_bytes = vec![];
    tx.encode(&mut tx_bytes).unwrap();
    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    let client =
        HttpClient::new("tcp://127.0.0.1:26657".parse().unwrap()).unwrap();
    // TODO broadcast_tx_commit shouldn't be used live
    let response = client.broadcast_tx_commit(tx_bytes.into()).await.unwrap();
    println!("{:#?}", response);
}

async fn gossip_intent(orderbook_addr: String, data_path: String) {
    println!("address : {:?}", orderbook_addr);
    let mut client = RpcServiceClient::connect(orderbook_addr).await.unwrap();
    let data = std::fs::read(data_path).expect("data file IO error");
    let intent = types::Intent {
        data,
        timestamp: Some(std::time::SystemTime::now().into()),
    };
    let intent_message = types::IntentMessage {
        intent: Some(intent),
    };
    let message = types::Message {
        message: Some(types::message::Message::IntentMessage(intent_message)),
    };
    let _response = client.send_message(message).await.unwrap();
}
