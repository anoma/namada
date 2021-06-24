use std::fs::File;
use std::io::Write;

use anoma::cli::{
    ArgMatchesExt, CraftIntentArgs, IntentArgs, SubscribeTopicArgs,
};
use anoma::client::tx;
use anoma::proto::services::rpc_service_client::RpcServiceClient;
use anoma::proto::{services, RpcMessage};
use anoma::{cli, wallet};
use anoma_shared::types::address::Address;
use anoma_shared::types::intent::Intent;
use anoma_shared::types::key::ed25519::Signed;
use anoma_shared::types::token;
use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use eyre::Context;

pub async fn main() -> Result<()> {
    let mut app = cli::anoma_client_cli();

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some((cli::TX_CUSTOM_CMD, args)) => {
            let args = args.tx_custom();
            tx::submit_custom(args).await;
        }
        Some((cli::TX_TRANSFER_CMD, args)) => {
            let args = args.tx_transfer();
            tx::submit_transfer(args).await;
        }
        Some((cli::TX_UPDATE_CMD, args)) => {
            let args = args.tx_update_vp();
            tx::submit_update_vp(args).await;
        }
        Some((cli::INTENT_CMD, args)) => {
            let args = args.intent();
            gossip_intent(args).await;
        }
        Some((cli::CRAFT_INTENT_CMD, args)) => {
            let args = args.craft_intent();
            craft_intent(args);
        }
        Some((cli::SUBSCRIBE_TOPIC_CMD, args)) => {
            let args = args.subscribe_topic();
            subscribe_topic(args).await;
        }
        _ => app.print_help().wrap_err("Can't display help.")?,
    }
    Ok(())
}

async fn gossip_intent(
    IntentArgs {
        node_addr,
        data_path,
        topic,
    }: IntentArgs,
) {
    let mut client = RpcServiceClient::connect(node_addr).await.unwrap();
    let data = std::fs::read(data_path).expect("data file IO error");
    let intent = anoma_shared::proto::Intent::new(data);
    let message: services::RpcMessage =
        RpcMessage::new_intent(intent, topic).into();
    let response = client
        .send_message(message)
        .await
        .expect("failed to send message and/or receive rpc response");
    println!("{:#?}", response);
}

async fn subscribe_topic(
    SubscribeTopicArgs { node_addr, topic }: SubscribeTopicArgs,
) {
    let mut client = RpcServiceClient::connect(node_addr).await.unwrap();
    let message: services::RpcMessage = RpcMessage::new_topic(topic).into();
    let response = client
        .send_message(message)
        .await
        .expect("failed to send message and/or receive rpc response");
    println!("{:#?}", response);
}

fn craft_intent(
    CraftIntentArgs {
        addr,
        token_sell,
        amount_sell,
        token_buy,
        amount_buy,
        file,
    }: CraftIntentArgs,
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
