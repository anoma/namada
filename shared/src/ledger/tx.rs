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
use std::borrow::Cow;
use rust_decimal::Decimal;
use crate::ledger::pos::{BondId, Bonds, CommissionRates, Unbonds};
use crate::ledger;
use crate::types::transaction::{pos, InitAccount, InitValidator, UpdateVp};
use crate::types::{storage, token};

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

/// Save accounts initialized from a tx into the wallet, if any.
pub async fn save_initialized_accounts<U: WalletUtils, P>(
    wallet: &mut Wallet<P>,
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
        for (ix, address) in initialized_accounts.iter().enumerate() {
            let encoded = address.encode();
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
                        format!("{}{}", initialized_account_alias, ix).into()
                    }
                }
                None => {
                    U::read_alias(&encoded).into()
                }
            };
            let alias = alias.into_owned();
            let added = wallet.add_address::<U>(alias.clone(), address.clone());
            match added {
                Some(new_alias) if new_alias != encoded => {
                    println!(
                        "Added alias {} for address {}.",
                        new_alias, encoded
                    );
                }
                _ => println!("No alias added for address {}.", encoded),
            };
        }
    }
}

pub async fn submit_validator_commission_change<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    args: args::TxCommissionRateChange,
) {
    let epoch = rpc::query_epoch(client)
    .await;

    let tx_code = args.tx_code_path;

    let validator = args.validator.clone();
    if rpc::is_validator(client, &validator).await {
        if args.rate < Decimal::ZERO || args.rate > Decimal::ONE {
            if args.tx.force {
                eprintln!("Invalid new commission rate, received {}", args.rate);
            } else {
                panic!("Invalid new commission rate, received {}", args.rate);
            }
        }

        let commission_rate_key =
            ledger::pos::validator_commission_rate_key(&validator);
        let max_commission_rate_change_key =
            ledger::pos::validator_max_commission_rate_change_key(&validator);
        let commission_rates = rpc::query_storage_value::<C, CommissionRates>(
            &client,
            &commission_rate_key,
        )
        .await;
        let max_change = rpc::query_storage_value::<C, Decimal>(
            &client,
            &max_commission_rate_change_key,
        )
        .await;

        match (commission_rates, max_change) {
            (Some(rates), Some(max_change)) => {
                // Assuming that pipeline length = 2
                let rate_next_epoch = rates.get(epoch.next()).unwrap();
                if (args.rate - rate_next_epoch).abs() > max_change {
                    if args.tx.force {
                        eprintln!(
                            "New rate is too large of a change with respect to \
                             the predecessor epoch in which the rate will take \
                             effect."
                        );
                    } else {
                        panic!(
                            "New rate is too large of a change with respect to \
                             the predecessor epoch in which the rate will take \
                             effect."
                        );
                    }
                }
            }
            _ => {
                if args.tx.force {
                    eprintln!("Error retrieving from storage");
                } else {
                    panic!("Error retrieving from storage");
                }
            }
        }
    } else {
        if args.tx.force {
            eprintln!("The given address {validator} is not a validator.");
        } else {
            panic!("The given address {validator} is not a validator.");
        }
    }

    let data = pos::CommissionChange {
        validator: args.validator.clone(),
        new_rate: args.rate,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.validator.clone();
    process_tx::<C, U, P>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}

pub async fn submit_withdraw<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    args: args::Withdraw,
) {
    let epoch = rpc::query_epoch(client)
    .await;

    let validator = args.validator.clone();
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(client, &validator).await;
    if !is_validator {
        if args.tx.force {
            eprintln!(
                "The address {} doesn't belong to any known validator account.",
                validator
            );
        } else {
            panic!(
                "The address {} doesn't belong to any known validator account.",
                validator
            );
        }
    }

    let source = args.source.clone();
    let tx_code = args.tx_code_path;

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::unbond_key(&bond_id);
    let unbonds = rpc::query_storage_value::<C, Unbonds>(&client, &bond_key).await;
    match unbonds {
        Some(unbonds) => {
            let mut unbonded_amount: token::Amount = 0.into();
            if let Some(unbond) = unbonds.get(epoch) {
                for delta in unbond.deltas.values() {
                    unbonded_amount += *delta;
                }
            }
            if unbonded_amount == 0.into() {
                if args.tx.force {
                    eprintln!(
                        "There are no unbonded bonds ready to withdraw in the \
                         current epoch {}.",
                        epoch
                    );
                } else {
                    panic!(
                        "There are no unbonded bonds ready to withdraw in the \
                         current epoch {}.",
                        epoch
                    );
                }
            }
        }
        None => {
            if args.tx.force {
                eprintln!("No unbonded bonds found");
            } else {
                panic!("No unbonded bonds found");
            }
        }
    }

    let data = pos::Withdraw { validator, source };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx::<C, U, P>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}

pub async fn submit_unbond<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    args: args::Unbond,
) {
    let validator = args.validator.clone();
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(client, &validator).await;
    if !is_validator {
        if args.tx.force {
            eprintln!(
                "The address {} doesn't belong to any known validator account.",
                validator
            );
        } else {
            panic!(
                "The address {} doesn't belong to any known validator account.",
                validator
            );
        }
    }

    let source = args.source.clone();
    let tx_code = args.tx_code_path;

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::bond_key(&bond_id);
    let bonds = rpc::query_storage_value::<C, Bonds>(&client, &bond_key).await;
    match bonds {
        Some(bonds) => {
            let mut bond_amount: token::Amount = 0.into();
            for bond in bonds.iter() {
                for delta in bond.pos_deltas.values() {
                    bond_amount += *delta;
                }
            }
            if args.amount > bond_amount {
                if args.tx.force {
                    eprintln!(
                        "The total bonds of the source {} is lower than the \
                         amount to be unbonded. Amount to unbond is {} and the \
                         total bonds is {}.",
                        bond_source, args.amount, bond_amount
                    );
                } else {
                    panic!(
                        "The total bonds of the source {} is lower than the \
                         amount to be unbonded. Amount to unbond is {} and the \
                         total bonds is {}.",
                        bond_source, args.amount, bond_amount
                    );
                }
            }
        }
        None => {
            if args.tx.force {
                eprintln!("No bonds found");
            } else {
                panic!("No bonds found");
            }
        }
    }

    let data = pos::Unbond {
        validator,
        amount: args.amount,
        source,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx::<C, U, P>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}

pub async fn submit_bond<C: Client + crate::ledger::queries::Client + Sync, U: WalletUtils, P>(
    client: &C,
    wallet: &mut Wallet<P>,
    args: args::Bond,
) {
    let validator = args.validator.clone();
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(client, &validator).await;
    if !is_validator {
        if args.tx.force {
            eprintln!(
                "The address {} doesn't belong to any known validator account.",
                validator
            );
        } else {
            panic!(
                "The address {} doesn't belong to any known validator account.",
                validator
            );
        }
    }
    let source = args.source.clone();
    // Check that the source address exists on chain
    if let Some(source) = &source {
        let source_exists =
            rpc::known_address::<C>(client, source).await;
        if !source_exists {
            if args.tx.force {
                eprintln!("The source address {} doesn't exist on chain.", source);
            } else {
                panic!("The source address {} doesn't exist on chain.", source);
            }
        }
    }
    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let balance_key = token::balance_key(&args.native_token, bond_source);
    match rpc::query_storage_value::<C, token::Amount>(&client, &balance_key).await
    {
        Some(balance) => {
            if balance < args.amount {
                if args.tx.force {
                    eprintln!(
                        "The balance of the source {} is lower than the amount to \
                         be transferred. Amount to transfer is {} and the balance \
                         is {}.",
                        bond_source, args.amount, balance
                    );
                } else {
                    panic!(
                        "The balance of the source {} is lower than the amount to \
                         be transferred. Amount to transfer is {} and the balance \
                         is {}.",
                        bond_source, args.amount, balance
                    );
                }
            }
        }
        None => {
            if args.tx.force {
                eprintln!("No balance found for the source {}", bond_source);
            } else {
                panic!("No balance found for the source {}", bond_source);
            }
        }
    }
    let tx_code = args.tx_code_path;
    let bond = pos::Bond {
        validator,
        amount: args.amount,
        source,
    };
    let data = bond.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx::<C, U, P>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
    )
    .await;
}
