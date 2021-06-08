use std::str::FromStr;

use anoma_shared::types::key::ed25519::Keypair;
use anoma_shared::types::{token, Address, UpdateVp};
use borsh::BorshSerialize;
use tendermint_rpc::{Client, HttpClient};

use crate::proto::Tx;
use crate::wallet;

const TX_UPDATE_VP: &str = "wasm/txs/tx_update_vp/tx.wasm";

pub async fn submit_custom(
    tx_code_path: String,
    data_path: Option<&str>,
    dry_run: bool,
    ledger_address: String,
) {
    let tx_code = std::fs::read(tx_code_path)
        .expect("Expected a file at given code path");
    let data = data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });

    submit_tx(tx_code, data, dry_run, ledger_address).await
}

pub async fn submit_update_vp(
    addr: String,
    vp_code_path: String,
    dry_run: bool,
    ledger_address: String,
) {
    let source_key: Keypair = wallet::key_of(&addr);
    let addr = Address::decode(addr).expect("The address is not valid");
    let vp_code = std::fs::read(vp_code_path)
        .expect("Expected a file at given code path");
    let tx_code = std::fs::read(TX_UPDATE_VP)
        .expect("Expected a file at given code path");

    let update_vp = UpdateVp { addr, vp_code };
    let signed = update_vp.sign(&tx_code, &source_key);
    let data = Some(
        signed
            .try_to_vec()
            .expect("Encoding transaction data shouldn't fail"),
    );

    submit_tx(tx_code, data, dry_run, ledger_address).await
}

pub async fn submit_transfer(
    source: String,
    target: String,
    token: String,
    amount: f64,
    tx_code_path: String,
    dry_run: bool,
    ledger_address: String,
) {
    let source_key: Keypair = wallet::key_of(&source);
    let source = Address::decode(source).expect("Source address is not valid");
    let target = Address::decode(target).expect("Target address is not valid");
    let token = Address::decode(token).expect("Token address is not valid");
    let amount = token::Amount::from(amount);
    let tx_code = std::fs::read(tx_code_path).unwrap();

    let transfer = token::Transfer {
        source,
        target,
        token,
        amount,
    };
    let signed = transfer.sign(&tx_code, &source_key);
    let data = Some(
        signed
            .try_to_vec()
            .expect("Encoding transaction data shouldn't fail"),
    );

    submit_tx(tx_code, data, dry_run, ledger_address).await
}

async fn submit_tx(
    code: Vec<u8>,
    data: Option<Vec<u8>>,
    dry_run: bool,
    ledger_address: String,
) {
    let tx = Tx::new(code, data);
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
        FromStr::from_str(&format!("tcp://{}", ledger_address)).unwrap();
    let client = HttpClient::new(address).unwrap();
    // TODO broadcast_tx_commit shouldn't be used live;
    if dry_run {
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
