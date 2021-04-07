//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use std::fs::File;
use std::io::prelude::*;

use anoma::{cli, protobuf::services::rpc_service_client::RpcServiceClient};
use anoma::protobuf::types;
use anoma::protobuf::types::Tx;
use anoma_data_template;
use borsh::BorshSerialize;
use clap::Clap;
use color_eyre::eyre::Result;
use prost::Message;
use tendermint_rpc::{Client, HttpClient};
use eyre::Context;

pub async fn main() -> Result<()> {
    let mut app = cli::anoma_client_cli();

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some((cli::TX_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let path = args.value_of(cli::PATH_TX_ARG).unwrap().to_string();
            let data = args.value_of(cli::DATA_TX_ARG);
            exec_tx(path, data).await;
            Ok(())
        }
        Some((cli::INTENT_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let orderbook =
                args.value_of(cli::ORDERBOOK_ARG).unwrap().to_string();
            let data = args.value_of(cli::DATA_INTENT_ARG).unwrap().to_string();
            gossip_intent(orderbook, data).await;
            Ok(())
        }
        Some((cli::CRAFT_INTENT_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let addr = args.value_of(cli::ADDRESS_ARG).unwrap().to_string();
            let token_sell = args.value_of(cli::TOKEN_SELL_ARG).unwrap().to_string();
            let amount_sell = cli::parse_u64(args,cli::AMOUNT_SELL_ARG).expect("not a valid amount");
            let token_buy = args.value_of(cli::TOKEN_BUY_ARG).unwrap().to_string();
            let amount_buy = cli::parse_u64(args,cli::AMOUNT_BUY_ARG).expect("not a valid amount");
            let file = args.value_of(cli::FILE_ARG).unwrap().to_string();
            craft_intent(
                addr,
                token_sell,
                amount_sell,
                token_buy,
                amount_buy,
                file,
            );
            Ok(())
        },
        Some((cli::CRAFT_DATA_TX_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let source = args.value_of(cli::SOURCE_ARG).unwrap().to_string();
            let target = args.value_of(cli::TARGET_ARG).unwrap().to_string();
            let token = args.value_of(cli::TOKEN_ARG).unwrap().to_string();
            let amount = cli::parse_u64(args,cli::AMOUNT_ARG).expect("not a valid amount");
            let file = args.value_of(cli::FILE_ARG).unwrap().to_string();
            craft_tx_data(source, target, token, amount, file);
            Ok(())
        }
        _ => app.print_help().wrap_err("Can't display help.")
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

fn craft_intent(
    addr: String,
    token_sell: String,
    amount_sell: u64,
    token_buy: String,
    amount_buy: u64,
    file: String,
) {
    let data = anoma_data_template::Intent {
        addr,
        token_sell,
        amount_sell,
        token_buy,
        amount_buy,
    };
    let data_bytes = data.try_to_vec().unwrap();
    let mut file = File::create(file).unwrap();
    file.write_all(&data_bytes).unwrap();
}

fn craft_tx_data(
    source: String,
    target: String,
    token: String,
    amount: u64,
    file: String,
) {
    use anoma_data_template::*;
    let data = TxData {
        transfers:vec![Transfer{
            source,target,
            token,
            amount,
        }]};
    let data_bytes = data.try_to_vec().unwrap();
    let mut file = File::create(file).unwrap();
    file.write_all(&data_bytes).unwrap();
}
