use itertools::Either::*;
use crate::ledger::args;
use crate::ledger::wallet::{Wallet, WalletUtils};
use crate::tendermint_rpc::Client;
use crate::proto::Tx;
use namada_core::types::address::Address;
use crate::ledger::signing::sign_tx;
use crate::ledger::signing::TxSigningKey;
use crate::ledger::rpc::{self, TxBroadcastData};
use crate::ledger::signing::find_keypair;
use crate::types::key::*;
use borsh::BorshSerialize;
use crate::tendermint_rpc::error::Error as RpcError;
use crate::ledger::rpc::TxResponse;
use tokio::time::{Duration, Instant};
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;

/// Default timeout in seconds for requests to the `/accepted`
/// and `/applied` ABCI query endpoints.
const DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: u64 = 60;

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
pub async fn process_tx<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    args: &args::Tx,
    tx: Tx,
    default_signer: TxSigningKey,
) -> Vec<Address> {
    let to_broadcast = sign_tx::<C, U, P>(client, wallet, tx, args, default_signer).await;
    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    if args.dry_run {
        if let TxBroadcastData::DryRun(tx) = to_broadcast {
            rpc::dry_run_tx(client, tx.to_bytes()).await;
            vec![]
        } else {
            panic!(
                "Expected a dry-run transaction, received a wrapper \
                 transaction instead"
            );
        }
    } else {
        // Either broadcast or submit transaction and collect result into
        // sum type
        let result = if args.broadcast_only {
            Left(broadcast_tx(client, &to_broadcast).await)
        } else {
            Right(submit_tx(client, to_broadcast).await)
        };
        // Return result based on executed operation, otherwise deal with
        // the encountered errors uniformly
        match result {
            Right(Ok(result)) => result.initialized_accounts,
            Left(Ok(_)) => Vec::default(),
            Right(Err(err)) => {
                panic!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
            }
            Left(Err(err)) => {
                panic!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
            }
        }
    }
}

pub async fn submit_reveal_pk<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    args: args::RevealPk,
) {
    let args::RevealPk {
        tx: args,
        public_key,
    } = args;
    let public_key = public_key;
    if !reveal_pk_if_needed::<C, U, P>(client, wallet, &public_key, &args).await {
        let addr: Address = (&public_key).into();
        println!("PK for {addr} is already revealed, nothing to do.");
    }
}

pub async fn reveal_pk_if_needed<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> bool {
    let addr: Address = public_key.into();
    // Check if PK revealed
    if args.force || !has_revealed_pk(client, &addr).await
    {
        // If not, submit it
        submit_reveal_pk_aux::<C, U, P>(client, wallet, public_key, args).await;
        true
    } else {
        false
    }
}

pub async fn has_revealed_pk<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    addr: &Address,
) -> bool {
    rpc::get_public_key(client, addr).await.is_some()
}

pub async fn submit_reveal_pk_aux<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    public_key: &common::PublicKey,
    args: &args::Tx,
) {
    let addr: Address = public_key.into();
    println!("Submitting a tx to reveal the public key for address {addr}...");
    let tx_data = public_key
        .try_to_vec()
        .expect("Encoding a public key shouldn't fail");
    let tx_code = args.tx_code_path.clone();
    let tx = Tx::new(tx_code, Some(tx_data));

    // submit_tx without signing the inner tx
    let keypair = if let Some(signing_key) = &args.signing_key {
        signing_key.clone()
    } else if let Some(signer) = args.signer.as_ref() {
        let signer = signer;
        find_keypair::<C, U, P>(client, wallet, &signer)
            .await
    } else {
        find_keypair::<C, U, P>(client, wallet, &addr).await
    };
    let epoch = rpc::query_epoch(client)
    .await;
    let to_broadcast = if args.dry_run {
        TxBroadcastData::DryRun(tx)
    } else {
        super::signing::sign_wrapper(args, epoch, tx, &keypair).await
    };

    if args.dry_run {
        if let TxBroadcastData::DryRun(tx) = to_broadcast {
            rpc::dry_run_tx(client, tx.to_bytes()).await;
        } else {
            panic!(
                "Expected a dry-run transaction, received a wrapper \
                 transaction instead"
            );
        }
    } else {
        // Either broadcast or submit transaction and collect result into
        // sum type
        let result = if args.broadcast_only {
            Left(broadcast_tx(client, &to_broadcast).await)
        } else {
            Right(submit_tx(client, to_broadcast).await)
        };
        // Return result based on executed operation, otherwise deal with
        // the encountered errors uniformly
        match result {
            Right(Err(err)) => {
                panic!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
            }
            Left(Err(err)) => {
                panic!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
            }
            _ => {}
        }
    }
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx<C: Client + Sync>(
    rpc_cli: &C,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, RpcError> {
    let (tx, wrapper_tx_hash, decrypted_tx_hash) = match to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => (tx, wrapper_hash, decrypted_hash),
        _ => panic!("Cannot broadcast a dry-run transaction"),
    };

    tracing::debug!(
        transaction = ?to_broadcast,
        "Broadcasting transaction",
    );

    // TODO: configure an explicit timeout value? we need to hack away at
    // `tendermint-rs` for this, which is currently using a hard-coded 30s
    // timeout.
    let response = rpc_cli.broadcast_tx_sync(tx.to_bytes().into()).await?;

    if response.code == 0.into() {
        println!("Transaction added to mempool: {:?}", response);
        // Print the transaction identifiers to enable the extraction of
        // acceptance/application results later
        {
            println!("Wrapper transaction hash: {:?}", wrapper_tx_hash);
            println!("Inner transaction hash: {:?}", decrypted_tx_hash);
        }
        Ok(response)
    } else {
        Err(RpcError::server(serde_json::to_string(&response).unwrap()))
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
pub async fn submit_tx<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, RpcError> {
    let (_, wrapper_hash, decrypted_hash) = match &to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => (tx, wrapper_hash, decrypted_hash),
        _ => panic!("Cannot broadcast a dry-run transaction"),
    };

    // Broadcast the supplied transaction
    broadcast_tx(client, &to_broadcast).await?;

    let max_wait_time = Duration::from_secs(
        DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS,
    );
    let deadline = Instant::now() + max_wait_time;

    tracing::debug!(
        transaction = ?to_broadcast,
        ?deadline,
        "Awaiting transaction approval",
    );

    let parsed = {
        let wrapper_query = crate::ledger::rpc::TxEventQuery::Accepted(wrapper_hash.as_str());
        let event =
            rpc::query_tx_status(client, wrapper_query, deadline)
                .await;
        let parsed = TxResponse::from_event(event);

        println!(
            "Transaction accepted with result: {}",
            serde_json::to_string_pretty(&parsed).unwrap()
        );
        // The transaction is now on chain. We wait for it to be decrypted
        // and applied
        if parsed.code == 0.to_string() {
            // We also listen to the event emitted when the encrypted
            // payload makes its way onto the blockchain
            let decrypted_query =
                rpc::TxEventQuery::Applied(decrypted_hash.as_str());
            let event =
                rpc::query_tx_status(client, decrypted_query, deadline).await;
            let parsed = TxResponse::from_event(event);
            println!(
                "Transaction applied with result: {}",
                serde_json::to_string_pretty(&parsed).unwrap()
            );
            Ok(parsed)
        } else {
            Ok(parsed)
        }
    };

    tracing::debug!(
        transaction = ?to_broadcast,
        "Transaction approved",
    );

    parsed
}

