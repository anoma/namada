use std::str::FromStr;

use anoma_shared::proto::Tx;
use anoma_shared::types::address::Address;
use anoma_shared::types::key::ed25519::Keypair;
use anoma_shared::types::token;
use anoma_shared::types::transaction::UpdateVp;
use borsh::BorshSerialize;
use tendermint_rpc::{Client, HttpClient};

use crate::cli::{TxArgs, TxCustomArgs, TxTransferArgs, TxUpdateVpArgs};
use crate::wallet;

const TX_UPDATE_VP: &str = "wasm/txs/tx_update_vp/tx.wasm";

pub async fn submit_custom(args: TxCustomArgs) {
    let tx_code = std::fs::read(args.code_path)
        .expect("Expected a file at given code path");
    let data = args.data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });
    let tx = Tx::new(tx_code, data);

    submit_tx(args.tx, tx).await
}

pub async fn submit_update_vp(args: TxUpdateVpArgs) {
    let source_key: Keypair = wallet::key_of(&args.addr);
    let addr = Address::decode(&args.addr).expect("The address is not valid");
    let vp_code = std::fs::read(args.vp_code_path)
        .expect("Expected a file at given code path");
    let tx_code = std::fs::read(TX_UPDATE_VP)
        .expect("Expected a file at given code path");

    let update_vp = UpdateVp { addr, vp_code };
    let data = update_vp.try_to_vec().expect(
        "Encoding transfer data to update a validity predicate shouldn't  fail",
    );
    let tx = Tx::new(tx_code, Some(data)).sign(&source_key);

    submit_tx(args.tx, tx).await
}

pub async fn submit_transfer(args: TxTransferArgs) {
    let source_key: Keypair = wallet::key_of(&args.source);
    let source =
        Address::decode(&args.source).expect("Source address is not valid");
    let target =
        Address::decode(&args.target).expect("Target address is not valid");
    let token =
        Address::decode(&args.token).expect("Token address is not valid");
    let amount = token::Amount::from(args.amount);
    let tx_code = std::fs::read(&args.code_path).unwrap();

    let transfer = token::Transfer {
        source,
        target,
        token,
        amount,
    };
    let data = transfer
        .try_to_vec()
        .expect("Encoding unsigned transfer shouldn't fail");
    let tx = Tx::new(tx_code, Some(data)).sign(&source_key);

    submit_tx(args.tx, tx).await
}

async fn submit_tx(args: TxArgs, tx: Tx) {
    let tx_bytes = tx.to_bytes();

    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    let address: tendermint::net::Address =
        FromStr::from_str(&format!("tcp://{}", args.ledger_address)).unwrap();
    let client = HttpClient::new(address).unwrap();
    // TODO broadcast_tx_commit shouldn't be used live;
    if args.dry_run {
        let path = FromStr::from_str("dry_run_tx").unwrap();

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
