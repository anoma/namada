use std::fs::File;
use std::io::Write;

use anoma::client::tx;
use anoma::proto::services::rpc_service_client::RpcServiceClient;
use anoma::proto::services::{rpc_message, RpcMessage};
use anoma::proto::{services, types};
use anoma::{cli, wallet};
use anoma_shared::types::intent::Intent;
use anoma_shared::types::key::ed25519::Signed;
use anoma_shared::types::{token, Address};
use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use eyre::Context;

pub async fn main() -> Result<()> {
    let mut app = cli::anoma_client_cli();

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some((cli::TX_COMMAND, args)) => {
            let tx_code_path = cli::parse_string_req(args, cli::CODE_ARG);
            let data = args.value_of(cli::DATA_ARG);
            let dry_run = args.is_present(cli::DRY_RUN_TX_ARG);
            let ledger_address =
                cli::parse_string_req(args, cli::LEDGER_ADDRESS_ARG);
            tx::submit_custom(tx_code_path, data, dry_run, ledger_address)
                .await;
            Ok(())
        }
        Some((cli::TX_TRANSFER_COMMAND, args)) => {
            let source = cli::parse_string_req(args, cli::SOURCE_ARG);
            let target = cli::parse_string_req(args, cli::TARGET_ARG);
            let token = cli::parse_string_req(args, cli::TOKEN_ARG);
            let amount: f64 = cli::parse_req(args, cli::AMOUNT_ARG);
            let tx_code_path = cli::parse_string_req(args, cli::CODE_ARG);
            let dry_run = args.is_present(cli::DRY_RUN_TX_ARG);
            let ledger_address =
                cli::parse_string_req(args, cli::LEDGER_ADDRESS_ARG);
            tx::submit_transfer(
                source,
                target,
                token,
                amount,
                tx_code_path,
                dry_run,
                ledger_address,
            )
            .await;
            Ok(())
        }
        Some((cli::TX_UPDATE_COMMAND, args)) => {
            let addr = cli::parse_string_req(args, cli::ADDRESS_ARG);
            let vp_code_path = cli::parse_string_req(args, cli::CODE_ARG);
            let dry_run = args.is_present(cli::DRY_RUN_TX_ARG);
            let ledger_address =
                cli::parse_string_req(args, cli::LEDGER_ADDRESS_ARG);
            tx::submit_update_vp(addr, vp_code_path, dry_run, ledger_address)
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
    amount_sell: f64,
    token_buy: String,
    amount_buy: f64,
    file: String,
) {
    let source_keypair = wallet::key_of(&addr);
    let addr = Address::decode(addr).expect("Source address is not valid");
    let token_sell = Address::decode(token_sell)
        .expect("Token to sell address is not valid");
    let amount_sell = token::Amount::from(amount_sell);
    let token_buy =
        Address::decode(token_buy).expect("Token to buy address is not valid");
    let amount_buy = token::Amount::from(amount_buy);

    let intent = Intent {
        addr,
        token_sell,
        amount_sell,
        token_buy,
        amount_buy,
    };
    let signed: Signed<Intent> = Signed::new(&source_keypair, intent);
    let data_bytes = signed.try_to_vec().unwrap();

    let mut file = File::create(file).unwrap();
    file.write_all(&data_bytes).unwrap();
}
