use std::fs::File;
use std::io::Write;

use anoma::cli;
use anoma::protobuf::services::rpc_service_client::RpcServiceClient;
use anoma::protobuf::services::{rpc_message, RpcMessage};
use anoma::protobuf::{services, types};
use anoma_shared::types::intent::Intent;
use anoma_shared::types::{token, Address};
// use anoma_data_template;
use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use eyre::Context;

use crate::tx;

pub async fn main() -> Result<()> {
    let mut app = cli::anoma_client_cli();

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some((cli::TX_COMMAND, args)) => {
            let code = cli::parse_string_req(args, cli::CODE_ARG);
            let data = args.value_of(cli::DATA_ARG);
            let dry_run = args.is_present(cli::DRY_RUN_TX_ARG);
            tx::submit_custom(code, data, dry_run).await;
            Ok(())
        }
        Some((cli::TX_TRANSFER_COMMAND, args)) => {
            let source = cli::parse_string_req(args, cli::SOURCE_ARG);
            let target = cli::parse_string_req(args, cli::TARGET_ARG);
            let token = cli::parse_string_req(args, cli::TOKEN_ARG);
            let amount: f64 = cli::parse_req(args, cli::AMOUNT_ARG);
            let code = cli::parse_string_req(args, cli::CODE_ARG);
            let dry_run = args.is_present(cli::DRY_RUN_TX_ARG);
            tx::submit_transfer(source, target, token, amount, code, dry_run)
                .await;
            Ok(())
        }
        Some((cli::INTENT_COMMAND, args)) => {
            let node = cli::parse_string_req(args, cli::NODE_INTENT_ARG);
            let data = cli::parse_string_req(args, cli::DATA_INTENT_ARG);
            let topic = cli::parse_string_req(args, cli::TOPIC_ARG);
            gossip_intent(node, data, topic).await;
            Ok(())
        }
        Some((cli::SUBSCRIBE_TOPIC_COMMAND, args)) => {
            // here unwrap is safe as the arguments are required
            let node = cli::parse_string_req(args, cli::NODE_INTENT_ARG);
            let topic = cli::parse_string_req(args, cli::TOPIC_ARG);
            subscribe_topic(node, topic).await;
            Ok(())
        }
        Some((cli::CRAFT_INTENT_COMMAND, args)) => {
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
        _ => app.print_help().wrap_err("Can't display help."),
    }
}

async fn gossip_intent(node_addr: String, data_path: String, topic: String) {
    let mut client = RpcServiceClient::connect(node_addr).await.unwrap();
    let data = std::fs::read(data_path).expect("data file IO error");
    let intent = types::Intent {
        data,
        timestamp: Some(std::time::SystemTime::now().into()),
    };
    let message = RpcMessage {
        message: Some(rpc_message::Message::Intent(services::IntentMesage {
            intent: Some(intent),
            topic,
        })),
    };
    let response = client
        .send_message(message)
        .await
        .expect("failed to send message and/or receive rpc response");
    println!("{:#?}", response);
}

async fn subscribe_topic(node_addr: String, topic: String) {
    let mut client = RpcServiceClient::connect(node_addr).await.unwrap();
    let message = RpcMessage {
        message: Some(rpc_message::Message::Topic(
            services::SubscribeTopicMessage { topic },
        )),
    };
    let response = client
        .send_message(message)
        .await
        .expect("failed to send message and/or receive rpc response");
    println!("{:#?}", response);
}

fn craft_intent(
    addr: String,
    token_sell: String,
    amount_sell: u64,
    token_buy: String,
    amount_buy: u64,
    file: String,
) {
    let addr = Address::from_raw(addr);
    let token_sell = Address::from_raw(token_sell);
    let amount_sell = token::Amount::from(amount_sell);
    let token_buy = Address::from_raw(token_buy);
    let amount_buy = token::Amount::from(amount_buy);

    let data = Intent {
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
