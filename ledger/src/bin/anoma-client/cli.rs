//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use std::fs::File;
use std::io::Write;

use anoma::cli;
use anoma::protobuf::services::rpc_service_client::RpcServiceClient;
use anoma::protobuf::services::{rpc_message, RpcMessage};
use anoma::protobuf::types;
use anoma::protobuf::types::Tx;
use anoma_data_template;
use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use eyre::Context;
use prost::Message;
use tendermint_rpc::{Client, HttpClient};

pub async fn main() -> Result<()> {
    let mut app = cli::anoma_client_cli();

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some((cli::TX_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let path = cli::parse_string_req(args, cli::PATH_TX_ARG);
            let data = args.value_of(cli::DATA_TX_ARG);
            let dry = args.is_present(cli::DRY_RUN_TX_ARG);
            exec_tx(path, data, dry).await;
            Ok(())
        }
        Some((cli::INTENT_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let node = cli::parse_string_req(args, cli::NODE_INTENT_ARG);
            let data = cli::parse_string_req(args, cli::DATA_INTENT_ARG);
            gossip_intent(node, data).await;
            Ok(())
        }
        Some((cli::CRAFT_INTENT_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let addr = cli::parse_string_req(args, cli::ADDRESS_ARG);
            let token_sell = cli::parse_string_req(args, cli::TOKEN_SELL_ARG);
            let amount_sell = cli::parse_req(args, cli::AMOUNT_SELL_ARG);
            let token_buy = cli::parse_string_req(args, cli::TOKEN_BUY_ARG);
            let amount_buy = cli::parse_req(args, cli::AMOUNT_BUY_ARG);
            let file = cli::parse_string_req(args, cli::FILE_ARG);
            craft_intent(
                addr,
                token_sell,
                amount_sell,
                token_buy,
                amount_buy,
                file,
            );
            Ok(())
        }
        Some((cli::CRAFT_DATA_TX_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let source = cli::parse_string_req(args, cli::SOURCE_ARG);
            let target = cli::parse_string_req(args, cli::TARGET_ARG);
            let token = cli::parse_string_req(args, cli::TOKEN_ARG);
            let amount = cli::parse_req(args, cli::AMOUNT_ARG);
            let file = cli::parse_string_req(args, cli::FILE_ARG);
            craft_tx_data(source, target, token, amount, file);
            Ok(())
        }
        _ => app.print_help().wrap_err("Can't display help."),
    }
}

async fn exec_tx(code_path: String, data_path: Option<&str>, dry: bool) {
    // TODO tendermint cache blocks the same transaction sent more than once,
    // add a counter or timestamp?

    let code = std::fs::read(code_path).unwrap();
    let data = data_path.map(|data_path| std::fs::read(data_path).unwrap());
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
    // TODO broadcast_tx_commit shouldn't be used live;
    if dry {
        let path = std::str::FromStr::from_str("dry_run_tx").unwrap();

        let response = client
            .abci_query(Some(path), tx_bytes, None, false)
            .await
            .unwrap();
        println!("{:#?}", response);
    } else {
        let response =
            client.broadcast_tx_commit(tx_bytes.into()).await.unwrap();
        println!("{:#?}", response);
    }
}

async fn gossip_intent(node_addr: String, data_path: String) {
    let mut client = RpcServiceClient::connect(node_addr).await.unwrap();
    let data = std::fs::read(data_path).expect("data file IO error");
    let intent = types::Intent {
        data,
        timestamp: Some(std::time::SystemTime::now().into()),
    };
    let message = RpcMessage {
        message: Some(rpc_message::Message::Intent(intent)),
    };
    let _response = client
        .send_message(message)
        .await
        .expect("failed to send message and/or receive rpc response");
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
        transfers: vec![Transfer {
            source,
            target,
            token,
            amount,
        }],
    };
    let data_bytes = data.try_to_vec().unwrap();
    let mut file = File::create(file).unwrap();
    file.write_all(&data_bytes).unwrap();
}
