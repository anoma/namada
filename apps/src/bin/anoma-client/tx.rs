use anoma::protobuf::types::Tx;
use anoma::wallet;
use anoma_shared::types::key::ed25519::Keypair;
use anoma_shared::types::{token, Address};
use borsh::BorshSerialize;
use prost::Message;
use tendermint_rpc::{Client, HttpClient};

pub async fn submit_custom(
    code_path: String,
    data_path: Option<&str>,
    dry_run: bool,
) {
    let code =
        std::fs::read(code_path).expect("Expected a file at given code path");
    let data = data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });

    submit_tx(code, data, dry_run).await
}

pub async fn submit_transfer(
    source: String,
    target: String,
    token: String,
    amount: f64,
    code_path: String,
    dry_run: bool,
) {
    let source_key: Keypair = wallet::key_of(&source);
    let source = Address::from_raw(source);
    let target = Address::from_raw(target);
    let token = Address::from_raw(token);
    let amount = token::Amount::from(amount);
    let code = std::fs::read(code_path).unwrap();

    let transfer = token::Transfer {
        source,
        target,
        token,
        amount,
    };
    let signed = transfer.sign(&code, &source_key);
    let data = Some(
        signed
            .try_to_vec()
            .expect("Encoding transaction data shouldn't fail"),
    );

    submit_tx(code, data, dry_run).await
}

async fn submit_tx(code: Vec<u8>, data: Option<Vec<u8>>, dry_run: bool) {
    // TODO tendermint cache blocks the same transaction sent more than once,
    // add a counter or timestamp?

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
    if dry_run {
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
