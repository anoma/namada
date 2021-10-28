use std::borrow::Cow;
use std::convert::TryFrom;

use anoma::proto::Tx;
use anoma::types::address::Address;
use anoma::types::key::ed25519::Keypair;
use anoma::types::token;
use anoma::types::transaction::{
    pos, Fee, InitAccount, InitValidator, UpdateVp, WrapperTx,
};
use async_std::io::{self, WriteExt};
use borsh::BorshSerialize;
use jsonpath_lib as jsonpath;
use serde::Serialize;
use tendermint_rpc::query::{EventType, Query};
use tendermint_rpc::Client;

use super::{rpc, signing};
use crate::cli::context::WalletAddress;
use crate::cli::{args, safe_exit, Context};
use crate::client::tendermint_websocket_client::{
    hash_tx, Error, TendermintWebsocketClient, WebSocketAddress,
};
use crate::node::ledger::events::{Attributes, EventType as TmEventType};
use crate::node::ledger::tendermint_node;

const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";
const TX_UPDATE_VP_WASM: &str = "tx_update_vp.wasm";
const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
const VP_USER_WASM: &str = "vp_user.wasm";
const TX_BOND_WASM: &str = "tx_bond.wasm";
const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";

pub async fn submit_custom(ctx: Context, args: args::TxCustom) {
    let tx_code = ctx.read_wasm(args.code_path);
    let data = args.data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });
    let tx = Tx::new(tx_code, data);
    let (ctx, tx, keypair) = sign_tx(ctx, tx, &args.tx, None).await;
    let (ctx, initialized_accounts) =
        submit_tx(ctx, &args.tx, tx, &keypair).await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
}

pub async fn submit_update_vp(ctx: Context, args: args::TxUpdateVp) {
    let addr = ctx.get(&args.addr);
    let vp_code = ctx.read_wasm(args.vp_code_path);
    let tx_code = ctx.read_wasm(TX_UPDATE_VP_WASM);
    let data = UpdateVp { addr, vp_code };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) = sign_tx(ctx, tx, &args.tx, Some(&args.addr)).await;
    submit_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_init_account(mut ctx: Context, args: args::TxInitAccount) {
    let public_key = ctx.get_cached(&args.public_key);
    let vp_code = args
        .vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    let tx_code = ctx.read_wasm(TX_INIT_ACCOUNT_WASM);
    let data = InitAccount {
        public_key,
        vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(&args.source)).await;
    let (ctx, initialized_accounts) =
        submit_tx(ctx, &args.tx, tx, &keypair).await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
}

pub async fn submit_init_validator(
    mut ctx: Context,
    args::TxInitValidator {
        tx: tx_args,
        source,
        account_key,
        consensus_key,
        rewards_account_key,
        validator_vp_code_path,
        rewards_vp_code_path,
        unsafe_dont_encrypt,
    }: args::TxInitValidator,
) {
    let alias = tx_args
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = format!("{}-consensus-key", alias);
    let rewards_key_alias = format!("{}-rewards-key", alias);
    let account_key = ctx.get_opt_cached(&account_key).unwrap_or_else(|| {
        println!("Generating validator account key...");
        ctx.wallet
            .gen_key(Some(validator_key_alias.clone()), unsafe_dont_encrypt)
            .1
            .public
            .clone()
    });

    let consensus_key =
        ctx.get_opt_cached(&consensus_key).unwrap_or_else(|| {
            println!("Generating consensus key...");
            ctx.wallet
                .gen_key(Some(consensus_key_alias.clone()), unsafe_dont_encrypt)
                .1
        });

    let rewards_account_key =
        ctx.get_opt_cached(&rewards_account_key).unwrap_or_else(|| {
            println!("Generating staking reward account key...");
            ctx.wallet
                .gen_key(Some(rewards_key_alias.clone()), unsafe_dont_encrypt)
                .1
                .public
                .clone()
        });

    ctx.wallet.save().unwrap_or_else(|err| eprintln!("{}", err));

    let validator_vp_code = validator_vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    let rewards_vp_code = rewards_vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    let tx_code = ctx.read_wasm(TX_INIT_VALIDATOR_WASM);

    let data = InitValidator {
        account_key,
        consensus_key: consensus_key.public.clone(),
        rewards_account_key,
        validator_vp_code,
        rewards_vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");
    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) = sign_tx(ctx, tx, &tx_args, Some(&source)).await;

    let (mut ctx, initialized_accounts) =
        submit_tx(ctx, &tx_args, tx, &keypair).await;
    if !tx_args.dry_run {
        let (validator_address_alias, validator_address, rewards_address_alias) =
            match &initialized_accounts[..] {
                // There should be 2 accounts, one for the validator itself, one
                // for its staking reward address.
                [account_1, account_2] => {
                    // We need to find out which address is which
                    let (validator_address, rewards_address) =
                        if rpc::is_validator(account_1, tx_args.ledger_address)
                            .await
                        {
                            (account_1, account_2)
                        } else {
                            (account_2, account_1)
                        };

                    let validator_address_alias = match tx_args
                        .initialized_account_alias
                    {
                        Some(alias) => alias,
                        None => {
                            print!(
                                "Choose an alias for the validator address: "
                            );
                            io::stdout().flush().await.unwrap();
                            let mut alias = String::new();
                            io::stdin().read_line(&mut alias).await.unwrap();
                            alias.trim().to_owned()
                        }
                    };
                    let validator_address_alias =
                        if validator_address_alias.is_empty() {
                            println!(
                                "Empty alias given, using {} as the alias.",
                                validator_address.encode()
                            );
                            validator_address.encode()
                        } else {
                            validator_address_alias
                        };
                    if ctx.wallet.add_address(
                        validator_address_alias.clone(),
                        validator_address.clone(),
                    ) {
                        println!(
                            "Added alias {} for address {}.",
                            validator_address_alias,
                            validator_address.encode()
                        );
                    }
                    let rewards_address_alias =
                        format!("{}-rewards", validator_address_alias);
                    if ctx.wallet.add_address(
                        rewards_address_alias.clone(),
                        rewards_address.clone(),
                    ) {
                        println!(
                            "Added alias {} for address {}.",
                            rewards_address_alias,
                            rewards_address.encode()
                        );
                    }
                    (
                        validator_address_alias,
                        validator_address.clone(),
                        rewards_address_alias,
                    )
                }
                _ => {
                    eprintln!("Expected two accounts to be created");
                    safe_exit(1)
                }
            };

        ctx.wallet.save().unwrap_or_else(|err| eprintln!("{}", err));

        let tendermint_home = ctx.config.ledger.tendermint_dir();
        tendermint_node::write_validator_key(
            &tendermint_home,
            &validator_address,
            &consensus_key,
        );
        tendermint_node::write_validator_state(tendermint_home);

        println!();
        println!(
            "The validator's addresses and keys were stored in the wallet:"
        );
        println!("  Validator address \"{}\"", validator_address_alias);
        println!("  Staking reward address \"{}\"", rewards_address_alias);
        println!("  Validator account key \"{}\"", validator_key_alias);
        println!("  Consensus key \"{}\"", consensus_key_alias);
        println!("  Staking reward key \"{}\"", rewards_key_alias);
        println!(
            "The ledger node has been setup to use this validator's address \
             and consensus key."
        );
    } else {
        println!("Transaction dry run. No addresses have been saved.")
    }
}

pub async fn submit_transfer(ctx: Context, args: args::TxTransfer) {
    let source = ctx.get(&args.source);
    let target = ctx.get(&args.target);
    let token = ctx.get(&args.token);
    let tx_code = ctx.read_wasm(TX_TRANSFER_WASM);
    let transfer = token::Transfer {
        source,
        target,
        token,
        amount: args.amount,
    };
    tracing::debug!("Transfer data {:?}", transfer);
    let data = transfer
        .try_to_vec()
        .expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(&args.source)).await;
    submit_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_bond(ctx: Context, args: args::Bond) {
    let validator = ctx.get(&args.validator);
    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_BOND_WASM);
    let bond = pos::Bond {
        validator,
        amount: args.amount,
        source,
    };
    let data = bond.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.as_ref().unwrap_or(&args.validator);
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(default_signer)).await;
    submit_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_unbond(ctx: Context, args: args::Unbond) {
    let validator = ctx.get(&args.validator);
    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_UNBOND_WASM);

    let data = pos::Unbond {
        validator,
        amount: args.amount,
        source,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.as_ref().unwrap_or(&args.validator);
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(default_signer)).await;
    submit_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_withdraw(ctx: Context, args: args::Withdraw) {
    let validator = ctx.get(&args.validator);
    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_WITHDRAW_WASM);
    let data = pos::Withdraw { validator, source };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.as_ref().unwrap_or(&args.validator);
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(default_signer)).await;
    submit_tx(ctx, &args.tx, tx, &keypair).await;
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// returns unsigned transaction.
async fn sign_tx(
    mut ctx: Context,
    tx: Tx,
    args: &args::Tx,
    default: Option<&WalletAddress>,
) -> (Context, Tx, std::rc::Rc<Keypair>) {
    let (tx, keypair) = if let Some(signing_key) = &args.signing_key {
        let signing_key = ctx.get_cached(signing_key);
        (tx.sign(&signing_key), signing_key)
    } else if let Some(signer) = args.signer.as_ref().or(default) {
        let signer = ctx.get(signer);
        let signing_key = signing::find_keypair(
            &mut ctx.wallet,
            &signer,
            args.ledger_address.clone(),
        )
        .await;
        (tx.sign(&signing_key), signing_key)
    } else {
        panic!(
            "All transactions must be signed; please either specify the key \
             or the address from which to look up the signing key."
        );
    };

    (ctx, tx, keypair)
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
async fn submit_tx(
    ctx: Context,
    args: &args::Tx,
    tx: Tx,
    keypair: &Keypair,
) -> (Context, Vec<Address>) {
    // NOTE: use this to print the request JSON body:
    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    if args.dry_run {
        rpc::dry_run_tx(&args.ledger_address, tx.to_bytes()).await;
        (ctx, vec![])
    } else {
        let epoch = rpc::query_epoch(args::Query {
            ledger_address: args.ledger_address.clone(),
        })
        .await;
        let tx = WrapperTx::new(
            Fee {
                amount: args.fee_amount,
                token: ctx.get(&args.fee_token),
            },
            keypair,
            epoch.expect(
                "Getting the epoch of the last committed block should not fail",
            ),
            args.gas_limit.clone(),
            tx,
        );
        match broadcast_tx(args.ledger_address.clone(), tx, keypair).await {
            Ok(result) => (ctx, result.initialized_accounts),
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

/// Save accounts initialized from a tx into the wallet, if any.
async fn save_initialized_accounts(
    mut ctx: Context,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    let len = initialized_accounts.len();
    if len != 0 {
        // Store newly initialized account addresses in the wallet
        println!(
            "The transaction initialized {} new account{}",
            len,
            if len == 1 { "" } else { "s" }
        );
        // Store newly initialized account addresses in the wallet
        let wallet = &mut ctx.wallet;
        for (ix, address) in initialized_accounts.iter().enumerate() {
            let encoded = address.encode();
            let mut added = false;
            while !added {
                let alias: Cow<str> = match &args.initialized_account_alias {
                    Some(initialized_account_alias) => {
                        if len == 1 {
                            // If there's only one account, use the
                            // alias as is
                            initialized_account_alias.into()
                        } else {
                            // If there're multiple accounts, use
                            // the alias as prefix, followed by
                            // index number
                            format!("{}{}", initialized_account_alias, ix)
                                .into()
                        }
                    }
                    None => {
                        print!("Choose an alias for {}: ", encoded);
                        io::stdout().flush().await.unwrap();
                        let mut alias = String::new();
                        io::stdin().read_line(&mut alias).await.unwrap();
                        alias.trim().to_owned().into()
                    }
                };
                added = if alias.is_empty() {
                    println!(
                        "Empty alias given, using {} as the alias.",
                        encoded
                    );
                    wallet.add_address(encoded.clone(), address.clone())
                } else {
                    let alias = alias.into_owned();
                    let added =
                        wallet.add_address(alias.clone(), address.clone());
                    if added {
                        println!(
                            "Added alias {} for address {}.",
                            alias, encoded
                        );
                    }
                    added
                }
            }
        }
        if !args.dry_run {
            wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
        } else {
            println!("Transaction dry run. No addresses have been saved.")
        }
    }
}

/// Broadcast a transaction to be included in the blockchain.
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx with encrypted payload has been included on the blockchain
/// 3. The decrypted payload of the tx has been included on the blockchain.
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx(
    address: tendermint::net::Address,
    tx: WrapperTx,
    keypair: &Keypair,
) -> Result<TxResponse, Error> {
    // We use this to determine when the wrapper tx makes it on-chain
    let wrapper_tx_hash = hash_tx(&tx.try_to_vec().unwrap()).to_string();
    // We use this to determine when the decrypted inner tx makes it on-chain
    let decrypted_tx_hash = tx.tx_hash.to_string();
    // we sign all txs
    let tx = tx
        .sign(keypair)
        .expect("Signing of the wrapper transaction should not fail");
    let tx_bytes = tx.to_bytes();

    let mut wrapper_tx_subscription = TendermintWebsocketClient::open(
        WebSocketAddress::try_from(address.clone())?,
    )?;
    let mut decrypted_tx_subscription =
        TendermintWebsocketClient::open(WebSocketAddress::try_from(address)?)?;
    // It is better to subscribe to the transaction before it is broadcast
    //
    // Note that the `applied.hash` key comes from a custom event
    // created by the shell
    let query = Query::from(EventType::NewBlock)
        .and_eq("accepted.hash", wrapper_tx_hash.as_str());
    wrapper_tx_subscription.subscribe(query)?;
    let query = Query::from(EventType::NewBlock)
        .and_eq("applied.hash", decrypted_tx_hash.as_str());
    decrypted_tx_subscription.subscribe(query)?;

    let response = wrapper_tx_subscription
        .broadcast_tx_sync(tx_bytes.into())
        .await
        .map_err(|err| Error::Response(format!("{:?}", err)))?;

    let parsed = if response.code == 0.into() {
        println!("Transaction added to mempool: {:?}", response);
        let parsed = parse(
            wrapper_tx_subscription.receive_response()?,
            TmEventType::Accepted,
            &wrapper_tx_hash.to_string(),
        );
        println!(
            "Transaction accepted with result: {}",
            serde_json::to_string_pretty(&parsed).unwrap()
        );

        // The transaction is now on chain. We wait for it to be decrypted and
        // applied
        if parsed.code == 0.to_string() {
            let parsed = parse(
                decrypted_tx_subscription.receive_response()?,
                TmEventType::Applied,
                &decrypted_tx_hash,
            );
            println!(
                "Transaction applied with result: {}",
                serde_json::to_string_pretty(&parsed).unwrap()
            );
            Ok(parsed)
        } else {
            Ok(parsed)
        }
    } else {
        Err(Error::Response(response.log.to_string()))
    };
    wrapper_tx_subscription.unsubscribe()?;
    wrapper_tx_subscription.close();
    decrypted_tx_subscription.unsubscribe()?;
    decrypted_tx_subscription.close();
    parsed
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

/// Parse the JSON payload received from a subscription
///
/// Searches for custom events emitted from the ledger and converts
/// them back to thin wrapper around a hashmap for further parsing.
fn parse(
    json: serde_json::Value,
    event_type: TmEventType,
    tx_hash: &str,
) -> TxResponse {
    let mut selector = jsonpath::selector(&json);
    let mut event = selector(&format!(
        "$.events.[?(@.type=='{}')]",
        event_type.to_string()
    ))
    .unwrap()
    .iter()
    .filter_map(|event| {
        let attrs = Attributes::from(*event);
        match attrs.get("hash") {
            Some(hash) if hash == tx_hash => Some(attrs),
            _ => None,
        }
    })
    .collect::<Vec<Attributes>>()
    .remove(0);

    let info = event.take("info").unwrap();
    let height = event.take("height").unwrap();
    let hash = event.take("hash").unwrap();
    let code = event.take("code").unwrap();
    let gas_used = event.take("gas_used").unwrap_or_else(|| String::from("0"));
    let initialized_accounts = event.take("initialized_accounts");
    let initialized_accounts = match initialized_accounts {
        Some(values) => serde_json::from_str(&values).unwrap(),
        _ => vec![],
    };
    TxResponse {
        info,
        height,
        hash,
        code,
        gas_used,
        initialized_accounts,
    }
}
