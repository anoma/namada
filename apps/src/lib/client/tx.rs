use std::convert::TryFrom;

use anoma::proto::Tx;
use anoma::types::address::Address;
use anoma::types::key::ed25519::Keypair;
use anoma::types::token;
use anoma::types::transaction::{pos, InitAccount, UpdateVp};
use async_std::io::{self, WriteExt};
use borsh::BorshSerialize;
use jsonpath_lib as jsonpath;
use serde::Serialize;
use tendermint_rpc::query::{EventType, Query};
use tendermint_rpc::Client;

use super::{rpc, signing};
use crate::cli::{args, safe_exit, Context};
use crate::client::tendermint_websocket_client::{
    hash_tx, Error, TendermintWebsocketClient, WebSocketAddress,
};

const TX_INIT_ACCOUNT_WASM: &str = "wasm/tx_init_account.wasm";
const TX_UPDATE_VP_WASM: &str = "wasm/tx_update_vp.wasm";
const TX_TRANSFER_WASM: &str = "wasm/tx_transfer.wasm";
const VP_USER_WASM: &str = "wasm/vp_user.wasm";
const TX_BOND_WASM: &str = "wasm/tx_bond.wasm";
const TX_UNBOND_WASM: &str = "wasm/tx_unbond.wasm";
const TX_WITHDRAW_WASM: &str = "wasm/tx_withdraw.wasm";

pub async fn submit_custom(ctx: Context, args: args::TxCustom) {
    let tx_code = std::fs::read(args.code_path)
        .expect("Expected a file at given code path");
    let data = args.data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });
    let tx = Tx::new(tx_code, data);
    let tx = if let Some(signing_key) = args.signing_key {
        let signing_key = signing_key.get(&ctx);
        signing_key.sign_tx(tx)
    } else if let Some(signer) = args.signer {
        let signing_key = signing::find_keypair(
            &ctx.wallet,
            &signer,
            args.tx.ledger_address.clone(),
        )
        .await;
        signing_key.sign_tx(tx)
    } else {
        // Unsigned tx
        tx
    };

    submit_tx(ctx, args.tx, tx).await
}

pub async fn submit_update_vp(ctx: Context, args: args::TxUpdateVp) {
    let source = args.addr;
    let keypair = signing::find_keypair(
        &ctx.wallet,
        &source,
        args.tx.ledger_address.clone(),
    )
    .await;

    let vp_code = std::fs::read(args.vp_code_path)
        .expect("Expected a file at given code path");
    let tx_code = std::fs::read(TX_UPDATE_VP_WASM)
        .expect("Expected a file at given code path");

    let update_vp = UpdateVp {
        addr: source,
        vp_code,
    };
    let data = update_vp.try_to_vec().expect(
        "Encoding transfer data to update a validity predicate shouldn't fail",
    );
    let tx = keypair.sign_tx(Tx::new(tx_code, Some(data)));

    submit_tx(ctx, args.tx, tx).await
}

pub async fn submit_init_account(ctx: Context, args: args::TxInitAccount) {
    let source = args.source;
    let keypair = signing::find_keypair(
        &ctx.wallet,
        &source,
        args.tx.ledger_address.clone(),
    )
    .await;
    let public_key = args.public_key.get(&ctx).clone();
    let vp_code = args
        .vp_code_path
        .map(|path| {
            std::fs::read(path).expect("Expected a file at given code path")
        })
        .unwrap_or_else(|| {
            std::fs::read(VP_USER_WASM)
                .expect("Expected a file at given code path")
        });
    let tx_code = std::fs::read(TX_INIT_ACCOUNT_WASM)
        .expect("Expected a file at given code path");

    let data = InitAccount {
        public_key,
        vp_code,
    };
    let data = data.try_to_vec().expect(
        "Encoding transfer data to initialize a new account shouldn't fail",
    );
    let tx = keypair.sign_tx(Tx::new(tx_code, Some(data)));

    submit_tx(ctx, args.tx, tx).await
}

pub async fn submit_transfer(ctx: Context, args: args::TxTransfer) {
    let source = args.source;
    let keypair = signing::find_keypair(
        &ctx.wallet,
        &source,
        args.tx.ledger_address.clone(),
    )
    .await;

    let tx_code = std::fs::read(TX_TRANSFER_WASM).unwrap();
    let transfer = token::Transfer {
        source,
        target: args.target,
        token: args.token,
        amount: args.amount,
    };
    tracing::debug!("Transfer data {:?}", transfer);
    let data = transfer
        .try_to_vec()
        .expect("Encoding unsigned transfer shouldn't fail");
    let tx = keypair.sign_tx(Tx::new(tx_code, Some(data)));

    submit_tx(ctx, args.tx, tx).await
}

pub async fn submit_bond(args: args::Bond) {
    let source = args.source.as_ref().unwrap_or(&args.validator);
    let source_key: Keypair = wallet::key_of(source.encode());
    let tx_code = std::fs::read(TX_BOND_WASM).unwrap();

    let bond = pos::Bond {
        validator: args.validator,
        amount: args.amount,
        source: args.source,
    };
    tracing::debug!("Bond data {:?}", bond);
    let data = bond.try_to_vec().expect("Encoding tx data shouldn't fail");
    let tx = Tx::new(tx_code, Some(data)).sign(&source_key);

    submit_tx(args.tx, tx).await
}

pub async fn submit_unbond(args: args::Unbond) {
    let source = args.source.as_ref().unwrap_or(&args.validator);
    let source_key: Keypair = wallet::key_of(source.encode());
    let tx_code = std::fs::read(TX_UNBOND_WASM).unwrap();

    let unbond = pos::Unbond {
        validator: args.validator,
        amount: args.amount,
        source: args.source,
    };
    tracing::debug!("Unbond data {:?}", unbond);
    let data = unbond
        .try_to_vec()
        .expect("Encoding tx data shouldn't fail");
    let tx = Tx::new(tx_code, Some(data)).sign(&source_key);

    submit_tx(args.tx, tx).await
}

pub async fn submit_withdraw(args: args::Withdraw) {
    let source = args.source.as_ref().unwrap_or(&args.validator);
    let source_key: Keypair = wallet::key_of(source.encode());
    let tx_code = std::fs::read(TX_WITHDRAW_WASM).unwrap();

    let withdraw = pos::Withdraw {
        validator: args.validator,
        source: args.source,
    };
    tracing::debug!("Withdraw data {:?}", withdraw);
    let data = withdraw
        .try_to_vec()
        .expect("Encoding tx data shouldn't fail");
    let tx = Tx::new(tx_code, Some(data)).sign(&source_key);

    submit_tx(args.tx, tx).await
}

async fn submit_tx(ctx: Context, args: args::Tx, tx: Tx) {
    let tx_bytes = tx.to_bytes();

    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    if args.dry_run {
        rpc::dry_run_tx(&args.ledger_address, tx_bytes).await
    } else {
        match broadcast_tx(args.ledger_address, tx_bytes).await {
            Ok(result) => {
                let len = result.initialized_accounts.len();
                if len != 0 {
                    // Store newly initialized account addresses in the wallet
                    println!(
                        "The transaction initialized {} new account{}",
                        len,
                        if len == 1 { "" } else { "s" }
                    );
                    let mut wallet = ctx.wallet;
                    for address in result.initialized_accounts {
                        let encoded = address.encode();
                        print!("Choose an alias for {}: ", encoded);
                        io::stdout().flush().await.unwrap();
                        let mut alias = String::new();
                        io::stdin().read_line(&mut alias).await.unwrap();
                        if alias.is_empty() {
                            println!(
                                "Empty alias given, using {} as the alias",
                                encoded
                            );
                            wallet.add_address(encoded, address);
                        } else {
                            wallet.add_address(alias, address);
                        }
                    }
                    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
                }
            }
            Err(err) => {
                eprintln!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
                safe_exit(1)
            }
        }
    }
}

pub async fn broadcast_tx(
    address: tendermint::net::Address,
    tx_bytes: Vec<u8>,
) -> Result<TxResponse, Error> {
    let mut client =
        TendermintWebsocketClient::open(WebSocketAddress::try_from(address)?)?;
    // It is better to subscribe to the transaction before it is broadcast
    //
    // Note that the `applied.hash` key comes from a custom event
    // created by the shell
    let query = Query::from(EventType::NewBlock)
        .and_eq("applied.hash", hash_tx(&tx_bytes).to_string());
    client.subscribe(query)?;
    println!(
        "Transaction added to mempool: {:?}",
        client
            .broadcast_tx_sync(tx_bytes.into())
            .await
            .map_err(|err| Error::Response(format!("{:?}", err)))?
    );
    let parsed = TxResponse::from(client.receive_response()?);
    println!(
        "Transaction applied with result: {}",
        serde_json::to_string_pretty(&parsed).unwrap()
    );
    client.unsubscribe()?;
    client.close();
    Ok(parsed)
}

#[derive(Debug, Serialize)]
pub struct TxResponse {
    info: String,
    height: String,
    hash: String,
    code: String,
    gas_used: String,
    initialized_accounts: Vec<Address>,
}

impl From<serde_json::Value> for TxResponse {
    fn from(json: serde_json::Value) -> Self {
        let mut selector = jsonpath::selector(&json);
        let info = selector("$.events.['applied.info'][0]").unwrap();
        let height = selector("$.events.['applied.height'][0]").unwrap();
        let hash = selector("$.events.['applied.hash'][0]").unwrap();
        let code = selector("$.events.['applied.code'][0]").unwrap();
        let gas_used = selector("$.events.['applied.gas_used'][0]").unwrap();
        let initialized_accounts =
            selector("$.events.['applied.initialized_accounts'][0]");
        let initialized_accounts = match initialized_accounts {
            Ok(values) if !values.is_empty() => {
                // In a response, the initialized accounts are encoded as e.g.:
                // ```
                // "applied.initialized_accounts": Array([
                //   String(
                //     "[\"a1qq5qqqqq8qerqv3sxyuyz3zzxgcyxvecgerry333xce5z3fkg4pnj3zxgfqnzd69gsu5gwzr9wpjpe\"]",
                //   ),
                // ]),
                // ...
                // So we need to decode the inner string first ...
                let raw: String =
                    serde_json::from_value(values[0].clone()).unwrap();
                // ... and then decode the vec from the array inside the string
                serde_json::from_str(&raw).unwrap()
            }
            _ => vec![],
        };
        TxResponse {
            info: serde_json::from_value(info[0].clone()).unwrap(),
            height: serde_json::from_value(height[0].clone()).unwrap(),
            hash: serde_json::from_value(hash[0].clone()).unwrap(),
            code: serde_json::from_value(code[0].clone()).unwrap(),
            gas_used: serde_json::from_value(gas_used[0].clone()).unwrap(),
            initialized_accounts,
        }
    }
}
