//! SDK functions to construct different types of transactions
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::str::FromStr;

use borsh::BorshSerialize;
use itertools::Either::*;
use masp_primitives::transaction::builder;
use namada_core::types::address::{masp, masp_tx_key, Address};
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::CommissionPair;
use prost::EncodeError;
use rust_decimal::Decimal;
use thiserror::Error;
use tokio::time::Duration;

use super::rpc::query_wasm_code_hash;
use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc::core::ics04_channel::timeout::TimeoutHeight;
use crate::ibc::signer::Signer;
use crate::ibc::timestamp::Timestamp as IbcTimestamp;
use crate::ibc::tx_msg::Msg;
use crate::ibc::Height as IbcHeight;
use crate::ibc_proto::cosmos::base::v1beta1::Coin;
use crate::ledger::args;
use crate::ledger::governance::storage as gov_storage;
use crate::ledger::masp::{ShieldedContext, ShieldedUtils};
use crate::ledger::rpc::{self, TxBroadcastData, TxResponse};
use crate::ledger::signing::{find_keypair, sign_tx, tx_signer, TxSigningKey};
use crate::ledger::wallet::{Wallet, WalletUtils};
use crate::proto::Tx;
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::tendermint_rpc::error::Error as RpcError;
use crate::types::key::*;
use crate::types::masp::TransferTarget;
use crate::types::storage::{Epoch, RESERVED_ADDRESS_PREFIX};
use crate::types::time::DateTimeUtc;
use crate::types::transaction::{pos, InitAccount, UpdateVp};
use crate::types::{storage, token};
use crate::vm;
use crate::vm::WasmValidationError;

/// Default timeout in seconds for requests to the `/accepted`
/// and `/applied` ABCI query endpoints.
const DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: u64 = 60;

/// Errors to do with transaction events.
#[derive(Error, Debug)]
pub enum Error {
    /// Expect a dry running transaction
    #[error(
        "Expected a dry-run transaction, received a wrapper transaction \
         instead: {0:?}"
    )]
    ExpectDryRun(Tx),
    /// Expect a wrapped encrypted running transaction
    #[error("Cannot broadcast a dry-run transaction")]
    ExpectWrappedRun(Tx),
    /// Error during broadcasting a transaction
    #[error("Encountered error while broadcasting transaction: {0}")]
    TxBroadcast(RpcError),
    /// Invalid comission rate set
    #[error("Invalid new commission rate, received {0}")]
    InvalidCommisionRate(Decimal),
    /// Invalid validator address
    #[error("The address {0} doesn't belong to any known validator account.")]
    InvalidValidatorAddress(Address),
    /// Rate of epoch change too large for current epoch
    #[error(
        "New rate, {0}, is too large of a change with respect to the \
         predecessor epoch in which the rate will take effect."
    )]
    TooLargeOfChange(Decimal),
    /// Error retrieving from storage
    #[error("Error retrieving from storage")]
    Retrival,
    /// No unbonded bonds ready to withdraw in the current epoch
    #[error(
        "There are no unbonded bonds ready to withdraw in the current epoch \
         {0}."
    )]
    NoUnbondReady(Epoch),
    /// No unbonded bonds found
    #[error("No unbonded bonds found")]
    NoUnbondFound,
    /// No bonds found
    #[error("No bonds found")]
    NoBondFound,
    /// Lower bond amount than the unbond
    #[error(
        "The total bonds of the source {0} is lower than the amount to be \
         unbonded. Amount to unbond is {1} and the total bonds is {2}."
    )]
    LowerBondThanUnbond(Address, token::Amount, token::Amount),
    /// Balance is too low
    #[error(
        "The balance of the source {0} of token {1} is lower than the amount \
         to be transferred. Amount to transfer is {2} and the balance is {3}."
    )]
    BalanceTooLow(Address, Address, token::Amount, token::Amount),
    /// Token Address does not exist on chain
    #[error("The token address {0} doesn't exist on chain.")]
    TokenDoesNotExist(Address),
    /// Source address does not exist on chain
    #[error("The address {0} doesn't exist on chain.")]
    LocationDoesNotExist(Address),
    /// Target Address does not exist on chain
    #[error("The source address {0} doesn't exist on chain.")]
    SourceDoesNotExist(Address),
    /// Source Address does not exist on chain
    #[error("The target address {0} doesn't exist on chain.")]
    TargetLocationDoesNotExist(Address),
    /// No Balance found for token
    #[error("No balance found for the source {0} of token {1}")]
    NoBalanceForToken(Address, Address),
    /// Negative balance after transfer
    #[error(
        "The balance of the source {0} is lower than the amount to be \
         transferred and fees. Amount to transfer is {1} {2} and fees are {3} \
         {4}."
    )]
    NegativeBalanceAfterTransfer(
        Address,
        token::Amount,
        Address,
        token::Amount,
        Address,
    ),
    /// No Balance found for token
    #[error("{0}")]
    MaspError(builder::Error),
    /// Wasm validation failed
    #[error("Validity predicate code validation failed with {0}")]
    WasmValidationFailure(WasmValidationError),
    /// Encoding transaction failure
    #[error("Encoding tx data, {0}, shouldn't fail")]
    EncodeTxFailure(std::io::Error),
    /// Like EncodeTxFailure but for the encode error type
    #[error("Encoding tx data, {0}, shouldn't fail")]
    EncodeFailure(EncodeError),
    /// Encoding public key failure
    #[error("Encoding a public key, {0}, shouldn't fail")]
    EncodeKeyFailure(std::io::Error),
    /// Updating an VP of an implicit account
    #[error(
        "A validity predicate of an implicit address cannot be directly \
         updated. You can use an established address for this purpose."
    )]
    ImplicitUpdate,
    // This should be removed? or rather refactored as it communicates
    // the same information as the ImplicitUpdate
    /// Updating a VP of an internal implicit address
    #[error(
        "A validity predicate of an internal address cannot be directly \
         updated."
    )]
    ImplicitInternalError,
    /// Unexpected Error
    #[error("Unexpected behavior reading the unbonds data has occurred")]
    UnboundError,
    /// Epoch not in storage
    #[error("Proposal end epoch is not in the storage.")]
    EpochNotInStorage,
    /// Other Errors that may show up when using the interface
    #[error("{0}")]
    Other(String),
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
pub async fn process_tx<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    tx: Tx,
    default_signer: TxSigningKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> Result<Vec<Address>, Error> {
    let to_broadcast = sign_tx::<C, U>(
        client,
        wallet,
        tx,
        args,
        default_signer,
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await?;
    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    if args.dry_run {
        expect_dry_broadcast(to_broadcast, client, vec![]).await
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
            Right(Ok(result)) => Ok(result.initialized_accounts),
            Left(Ok(_)) => Ok(Vec::default()),
            Right(Err(err)) => Err(err),
            Left(Err(err)) => Err(err),
        }
    }
}

/// Submit transaction to reveal public key
pub async fn submit_reveal_pk<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::RevealPk,
) -> Result<(), Error> {
    let args::RevealPk {
        tx: args,
        public_key,
    } = args;
    let public_key = public_key;
    if !reveal_pk_if_needed::<C, U>(client, wallet, &public_key, &args).await? {
        let addr: Address = (&public_key).into();
        println!("PK for {addr} is already revealed, nothing to do.");
        Ok(())
    } else {
        Ok(())
    }
}

/// Submit transaction to rveeal public key if needed
pub async fn reveal_pk_if_needed<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> Result<bool, Error> {
    let addr: Address = public_key.into();
    // Check if PK revealed
    if args.force || !has_revealed_pk(client, &addr).await {
        // If not, submit it
        submit_reveal_pk_aux::<C, U>(client, wallet, public_key, args).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check if the public key for the given address has been revealed
pub async fn has_revealed_pk<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    addr: &Address,
) -> bool {
    rpc::get_public_key(client, addr).await.is_some()
}

/// Submit transaction to reveal the given public key
pub async fn submit_reveal_pk_aux<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    public_key: &common::PublicKey,
    args: &args::Tx,
) -> Result<(), Error> {
    let addr: Address = public_key.into();
    println!("Submitting a tx to reveal the public key for address {addr}...");
    let tx_data = public_key.try_to_vec().map_err(Error::EncodeKeyFailure)?;
    let tx_code = args.tx_code_path.clone();
    let tx = Tx::new(
        tx_code,
        Some(tx_data),
        args.chain_id.clone().expect("value should be there"),
        args.expiration,
    );

    // submit_tx without signing the inner tx
    let keypair = if let Some(signing_key) = &args.signing_key {
        Ok(signing_key.clone())
    } else if let Some(signer) = args.signer.as_ref() {
        let signer = signer;
        find_keypair::<C, U>(client, wallet, signer, args.password.clone())
            .await
    } else {
        find_keypair::<C, U>(client, wallet, &addr, args.password.clone()).await
    }?;
    let epoch = rpc::query_epoch(client).await;
    let to_broadcast = if args.dry_run {
        TxBroadcastData::DryRun(tx)
    } else {
        super::signing::sign_wrapper(
            client,
            args,
            epoch,
            tx,
            &keypair,
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .await
    };

    // Logic is the same as process_tx
    if args.dry_run {
        expect_dry_broadcast(to_broadcast, client, ()).await
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
            Right(Err(err)) => Err(err),
            Left(Err(err)) => Err(err),
            _ => Ok(()),
        }
    }
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx<C: crate::ledger::queries::Client + Sync>(
    rpc_cli: &C,
    to_broadcast: &TxBroadcastData,
) -> Result<Response, Error> {
    let (tx, wrapper_tx_hash, decrypted_tx_hash) = match to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => Ok((tx, wrapper_hash, decrypted_hash)),
        TxBroadcastData::DryRun(tx) => Err(Error::ExpectWrappedRun(tx.clone())),
    }?;

    tracing::debug!(
        transaction = ?to_broadcast,
        "Broadcasting transaction",
    );

    // TODO: configure an explicit timeout value? we need to hack away at
    // `tendermint-rs` for this, which is currently using a hard-coded 30s
    // timeout.
    let response =
        lift_rpc_error(rpc_cli.broadcast_tx_sync(tx.to_bytes().into()).await)?;

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
        Err(Error::TxBroadcast(RpcError::server(
            serde_json::to_string(&response).unwrap(),
        )))
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
pub async fn submit_tx<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse, Error> {
    let (_, wrapper_hash, decrypted_hash) = match &to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => Ok((tx, wrapper_hash, decrypted_hash)),
        TxBroadcastData::DryRun(tx) => Err(Error::ExpectWrappedRun(tx.clone())),
    }?;

    // Broadcast the supplied transaction
    broadcast_tx(client, &to_broadcast).await?;

    let deadline =
        Duration::from_secs(DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS);

    tracing::debug!(
        transaction = ?to_broadcast,
        ?deadline,
        "Awaiting transaction approval",
    );

    let parsed = {
        let wrapper_query =
            crate::ledger::rpc::TxEventQuery::Accepted(wrapper_hash.as_str());
        let event = rpc::query_tx_status(client, wrapper_query, deadline).await;
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
pub async fn save_initialized_accounts<U: WalletUtils>(
    wallet: &mut Wallet<U>,
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
                None => U::read_alias(&encoded).into(),
            };
            let alias = alias.into_owned();
            let added = wallet.add_address(
                alias.clone(),
                address.clone(),
                args.wallet_alias_force,
            );
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

/// Submit validator comission rate change
pub async fn submit_validator_commission_change<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxCommissionRateChange,
) -> Result<(), Error> {
    let epoch = rpc::query_epoch(client).await;

    let tx_code = args.tx_code_path;

    // TODO: put following two let statements in its own function
    let params_key = crate::ledger::pos::params_key();
    let params = rpc::query_storage_value::<C, PosParams>(client, &params_key)
        .await
        .expect("Parameter should be defined.");

    let validator = args.validator.clone();
    if rpc::is_validator(client, &validator).await {
        if args.rate < Decimal::ZERO || args.rate > Decimal::ONE {
            if args.tx.force {
                eprintln!(
                    "Invalid new commission rate, received {}",
                    args.rate
                );
                Ok(())
            } else {
                Err(Error::InvalidCommisionRate(args.rate))
            }
        } else {
            Ok(())
        }?;

        let pipeline_epoch_minus_one = epoch + params.pipeline_len - 1;

        match rpc::query_commission_rate(
            client,
            &validator,
            Some(pipeline_epoch_minus_one),
        )
        .await
        {
            Some(CommissionPair {
                commission_rate,
                max_commission_change_per_epoch,
            }) => {
                if (args.rate - commission_rate).abs()
                    > max_commission_change_per_epoch
                {
                    eprintln!(
                        "New rate is too large of a change with respect to \
                         the predecessor epoch in which the rate will take \
                         effect."
                    );
                    if !args.tx.force {
                        return Err(Error::InvalidCommisionRate(args.rate));
                    }
                }
            }
            None => {
                eprintln!("Error retrieving from storage");
                if !args.tx.force {
                    return Err(Error::Retrival);
                }
            }
        }
    } else {
        eprintln!("The given address {validator} is not a validator.");
        if !args.tx.force {
            return Err(Error::InvalidValidatorAddress(validator));
        }
    }

    let data = pos::CommissionChange {
        validator: args.validator.clone(),
        new_rate: args.rate,
    };
    let data = data.try_to_vec().map_err(Error::EncodeTxFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;

    let tx = Tx::new(tx_code, Some(data), chain_id, expiration);
    let default_signer = args.validator.clone();
    process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;
    Ok(())
}

/// Submit transaction to withdraw an unbond
pub async fn submit_withdraw<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Withdraw,
) -> Result<(), Error> {
    let epoch = rpc::query_epoch(client).await;

    let validator =
        known_validator_or_err(args.validator.clone(), args.tx.force, client)
            .await?;

    let source = args.source.clone();
    let tx_code = args.tx_code_path;

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let tokens = rpc::query_withdrawable_tokens(
        client,
        &bond_source,
        &validator,
        Some(epoch),
    )
    .await;
    if tokens == 0.into() {
        eprintln!(
            "There are no unbonded bonds ready to withdraw in the current \
             epoch {}.",
            epoch
        );
        rpc::query_and_print_unbonds(client, &bond_source, &validator).await;
        if !args.tx.force {
            return Err(Error::NoUnbondReady(epoch));
        }
    } else {
        println!("Found {tokens} tokens that can be withdrawn.");
        println!("Submitting transaction to withdraw them...");
    }

    let data = pos::Withdraw { validator, source };
    let data = data.try_to_vec().map_err(Error::EncodeTxFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;

    let tx = Tx::new(tx_code, Some(data), chain_id, expiration);
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;
    Ok(())
}

/// Submit a transaction to unbond
pub async fn submit_unbond<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Unbond,
) -> Result<(), Error> {
    let validator =
        known_validator_or_err(args.validator.clone(), args.tx.force, client)
            .await?;
    let source = args.source.clone();
    let tx_code = args.tx_code_path;

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_amount =
        rpc::query_bond(client, &bond_source, &validator, None).await;
    println!("Bond amount available for unbonding: {} NAM", bond_amount);

    if args.amount > bond_amount {
        eprintln!(
            "The total bonds of the source {} is lower than the amount to be \
             unbonded. Amount to unbond is {} and the total bonds is {}.",
            bond_source, args.amount, bond_amount
        );
        if !args.tx.force {
            return Err(Error::LowerBondThanUnbond(
                bond_source,
                args.amount,
                bond_amount,
            ));
        }
    }

    // Query the unbonds before submitting the tx
    let unbonds =
        rpc::query_unbond_with_slashing(client, &bond_source, &validator).await;
    let mut withdrawable = BTreeMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        let to_withdraw = withdrawable.entry(withdraw_epoch).or_default();
        *to_withdraw += amount;
    }
    let latest_withdrawal_pre = withdrawable.into_iter().last();

    let data = pos::Unbond {
        validator: validator.clone(),
        amount: args.amount,
        source,
    };
    let data = data.try_to_vec().map_err(Error::EncodeTxFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;

    let tx = Tx::new(tx_code, Some(data), chain_id, expiration);
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;

    // Query the unbonds post-tx
    let unbonds =
        rpc::query_unbond_with_slashing(client, &bond_source, &validator).await;
    let mut withdrawable = BTreeMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        let to_withdraw = withdrawable.entry(withdraw_epoch).or_default();
        *to_withdraw += amount;
    }
    let (latest_withdraw_epoch_post, latest_withdraw_amount_post) =
        withdrawable.into_iter().last().unwrap();

    if let Some((latest_withdraw_epoch_pre, latest_withdraw_amount_pre)) =
        latest_withdrawal_pre
    {
        match latest_withdraw_epoch_post.cmp(&latest_withdraw_epoch_pre) {
            std::cmp::Ordering::Less => {
                if args.tx.force {
                    eprintln!(
                        "Unexpected behavior reading the unbonds data has \
                         occurred"
                    );
                } else {
                    return Err(Error::UnboundError);
                }
            }
            std::cmp::Ordering::Equal => {
                println!(
                    "Amount {} withdrawable starting from epoch {}",
                    latest_withdraw_amount_post - latest_withdraw_amount_pre,
                    latest_withdraw_epoch_post
                );
            }
            std::cmp::Ordering::Greater => {
                println!(
                    "Amount {} withdrawable starting from epoch {}",
                    latest_withdraw_amount_post, latest_withdraw_epoch_post
                );
            }
        }
    } else {
        println!(
            "Amount {} withdrawable starting from epoch {}",
            latest_withdraw_amount_post, latest_withdraw_epoch_post
        );
    }

    Ok(())
}

/// Submit a transaction to bond
pub async fn submit_bond<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::Bond,
) -> Result<(), Error> {
    let validator =
        known_validator_or_err(args.validator.clone(), args.tx.force, client)
            .await?;

    // Check that the source address exists on chain
    let source = args.source.clone();
    let source = match args.source.clone() {
        Some(source) => source_exists_or_err(source, args.tx.force, client)
            .await
            .map(Some),
        None => Ok(source),
    }?;
    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let balance_key = token::balance_key(&args.native_token, bond_source);

    // TODO Should we state the same error message for the native token?
    check_balance_too_low_err(
        &args.native_token,
        bond_source,
        args.amount,
        balance_key,
        args.tx.force,
        client,
    )
    .await?;

    let tx_code = args.tx_code_path;
    let bond = pos::Bond {
        validator,
        amount: args.amount,
        source,
    };
    let data = bond.try_to_vec().map_err(Error::EncodeTxFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;

    let tx = Tx::new(tx_code, Some(data), chain_id, expiration);
    let default_signer = args.source.unwrap_or(args.validator);
    process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(default_signer),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;
    Ok(())
}

/// Check if current epoch is in the last third of the voting period of the
/// proposal. This ensures that it is safe to optimize the vote writing to
/// storage.
pub async fn is_safe_voting_window<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    proposal_id: u64,
    proposal_start_epoch: Epoch,
) -> Result<bool, Error> {
    let current_epoch = rpc::query_epoch(client).await;

    let proposal_end_epoch_key =
        gov_storage::get_voting_end_epoch_key(proposal_id);
    let proposal_end_epoch =
        rpc::query_storage_value::<C, Epoch>(client, &proposal_end_epoch_key)
            .await;

    match proposal_end_epoch {
        Some(proposal_end_epoch) => {
            Ok(!crate::ledger::native_vp::governance::utils::is_valid_validator_voting_period(
                current_epoch,
                proposal_start_epoch,
                proposal_end_epoch,
            ))
        }
        None => {
            Err(Error::EpochNotInStorage)
        }
    }
}

/// Submit an IBC transfer
pub async fn submit_ibc_transfer<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxIbcTransfer,
) -> Result<(), Error> {
    // Check that the source address exists on chain
    let source =
        source_exists_or_err(args.source.clone(), args.tx.force, client)
            .await?;
    // We cannot check the receiver

    let token = token_exists_or_err(args.token, args.tx.force, client).await?;

    // Check source balance
    let (sub_prefix, balance_key) = match args.sub_prefix {
        Some(sub_prefix) => {
            let sub_prefix = storage::Key::parse(sub_prefix).unwrap();
            let prefix = token::multitoken_balance_prefix(&token, &sub_prefix);
            (
                Some(sub_prefix),
                token::multitoken_balance_key(&prefix, &source),
            )
        }
        None => (None, token::balance_key(&token, &source)),
    };

    check_balance_too_low_err(
        &token,
        &source,
        args.amount,
        balance_key,
        args.tx.force,
        client,
    )
    .await?;

    let tx_code = args.tx_code_path;

    let denom = match sub_prefix {
        // To parse IbcToken address, remove the address prefix
        Some(sp) => sp.to_string().replace(RESERVED_ADDRESS_PREFIX, ""),
        None => token.to_string(),
    };
    let token = Coin {
        denom,
        amount: args.amount.to_string(),
    };

    // this height should be that of the destination chain, not this chain
    let timeout_height = match args.timeout_height {
        Some(h) => {
            TimeoutHeight::At(IbcHeight::new(0, h).expect("invalid height"))
        }
        None => TimeoutHeight::Never,
    };

    let now: crate::tendermint::Time = DateTimeUtc::now().try_into().unwrap();
    let now: IbcTimestamp = now.into();
    let timeout_timestamp = if let Some(offset) = args.timeout_sec_offset {
        (now + Duration::new(offset, 0)).unwrap()
    } else if timeout_height == TimeoutHeight::Never {
        // we cannot set 0 to both the height and the timestamp
        (now + Duration::new(3600, 0)).unwrap()
    } else {
        IbcTimestamp::none()
    };

    let msg = MsgTransfer {
        port_id_on_a: args.port_id,
        chan_id_on_a: args.channel_id,
        token,
        sender: Signer::from_str(&source.to_string()).expect("invalid signer"),
        receiver: Signer::from_str(&args.receiver).expect("invalid signer"),
        timeout_height_on_b: timeout_height,
        timeout_timestamp_on_b: timeout_timestamp,
    };
    tracing::debug!("IBC transfer message {:?}", msg);
    let any_msg = msg.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data)
        .map_err(Error::EncodeFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;

    let tx = Tx::new(tx_code, Some(data), chain_id, expiration);
    process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(args.source),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;
    Ok(())
}

/// Submit an ordinary transfer
pub async fn submit_transfer<
    C: crate::ledger::queries::Client + Sync,
    V: WalletUtils,
    U: ShieldedUtils<C = C>,
>(
    client: &C,
    wallet: &mut Wallet<V>,
    shielded: &mut ShieldedContext<U>,
    args: args::TxTransfer,
) -> Result<(), Error> {
    // Check that the source address exists on chain
    let force = args.tx.force;
    let transfer_source = args.source.clone();
    let source = source_exists_or_err(
        transfer_source.effective_address(),
        force,
        client,
    )
    .await?;
    // Check that the target address exists on chain
    let transfer_target = args.target.clone();
    let target = target_exists_or_err(
        transfer_target.effective_address(),
        force,
        client,
    )
    .await?;

    // Check that the token address exists on chain
    let token =
        &(token_exists_or_err(args.token.clone(), force, client).await?);

    // Check source balance
    let (sub_prefix, balance_key) = match &args.sub_prefix {
        Some(sub_prefix) => {
            let sub_prefix = storage::Key::parse(sub_prefix).unwrap();
            let prefix = token::multitoken_balance_prefix(token, &sub_prefix);
            (
                Some(sub_prefix),
                token::multitoken_balance_key(&prefix, &source),
            )
        }
        None => (None, token::balance_key(token, &source)),
    };

    check_balance_too_low_err(
        token,
        &source,
        args.amount,
        balance_key,
        args.tx.force,
        client,
    )
    .await?;

    let tx_code = args.tx_code_path.clone();
    let masp_addr = masp();
    // For MASP sources, use a special sentinel key recognized by VPs as default
    // signer. Also, if the transaction is shielded, redact the amount and token
    // types by setting the transparent value to 0 and token type to a constant.
    // This has no side-effect because transaction is to self.
    let (default_signer, amount, token) =
        if source == masp_addr && target == masp_addr {
            // TODO Refactor me, we shouldn't rely on any specific token here.
            (
                TxSigningKey::SecretKey(masp_tx_key()),
                0.into(),
                args.native_token.clone(),
            )
        } else if source == masp_addr {
            (
                TxSigningKey::SecretKey(masp_tx_key()),
                args.amount,
                token.clone(),
            )
        } else {
            (
                TxSigningKey::WalletAddress(source.clone()),
                args.amount,
                token.clone(),
            )
        };
    // If our chosen signer is the MASP sentinel key, then our shielded inputs
    // will need to cover the gas fees.
    let chosen_signer =
        tx_signer::<C, V>(client, wallet, &args.tx, default_signer.clone())
            .await?
            .ref_to();
    let shielded_gas = masp_tx_key().ref_to() == chosen_signer;
    // Determine whether to pin this transaction to a storage key
    let key = match &args.target {
        TransferTarget::PaymentAddress(pa) if pa.is_pinned() => Some(pa.hash()),
        _ => None,
    };

    let stx_result = shielded
        .gen_shielded_transfer(client, args.clone(), shielded_gas)
        .await;
    let shielded = match stx_result {
        Ok(stx) => Ok(stx.map(|x| x.0)),
        Err(builder::Error::ChangeIsNegative(_)) => {
            Err(Error::NegativeBalanceAfterTransfer(
                source.clone(),
                args.amount,
                token.clone(),
                args.tx.fee_amount,
                args.tx.fee_token.clone(),
            ))
        }
        Err(err) => Err(Error::MaspError(err)),
    }?;

    let transfer = token::Transfer {
        source: source.clone(),
        target,
        token,
        sub_prefix,
        amount,
        key,
        shielded,
    };
    tracing::debug!("Transfer data {:?}", transfer);
    let data = transfer.try_to_vec().map_err(Error::EncodeTxFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;

    #[cfg(not(feature = "mainnet"))]
    let is_source_faucet = rpc::is_faucet_account(client, &source).await;

    let tx = Tx::new(tx_code, Some(data), chain_id, expiration);
    let signing_address = TxSigningKey::WalletAddress(source);
    process_tx::<C, V>(
        client,
        wallet,
        &args.tx,
        tx,
        signing_address,
        #[cfg(not(feature = "mainnet"))]
        is_source_faucet,
    )
    .await?;
    Ok(())
}

/// Submit a transaction to initialize an account
pub async fn submit_init_account<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxInitAccount,
) -> Result<(), Error> {
    let public_key = args.public_key;
    let vp_code = args.vp_code;
    // Validate the VP code
    validate_untrusted_code_err(&vp_code, args.tx.force)?;
    let vp_code_path = String::from_utf8(args.vp_code_path).unwrap();
    let vp_code_hash =
        query_wasm_code_hash(client, vp_code_path).await.unwrap();

    let tx_code = args.tx_code_path;
    let data = InitAccount {
        public_key,
        vp_code_hash,
    };
    let data = data.try_to_vec().map_err(Error::EncodeTxFailure)?;
    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;
    let tx = Tx::new(tx_code, Some(data), chain_id, expiration);
    // TODO Move unwrap to an either
    let initialized_accounts = process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(args.source),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await
    .unwrap();
    save_initialized_accounts::<U>(wallet, &args.tx, initialized_accounts)
        .await;
    Ok(())
}

/// Submit a transaction to update a VP
pub async fn submit_update_vp<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxUpdateVp,
) -> Result<(), Error> {
    let addr = args.addr.clone();

    // Check that the address is established and exists on chain
    match &addr {
        Address::Established(_) => {
            let exists = rpc::known_address::<C>(client, &addr).await;
            if !exists {
                if args.tx.force {
                    eprintln!("The address {} doesn't exist on chain.", addr);
                    Ok(())
                } else {
                    Err(Error::LocationDoesNotExist(addr.clone()))
                }
            } else {
                Ok(())
            }
        }
        Address::Implicit(_) => {
            if args.tx.force {
                eprintln!(
                    "A validity predicate of an implicit address cannot be \
                     directly updated. You can use an established address for \
                     this purpose."
                );
                Ok(())
            } else {
                Err(Error::ImplicitUpdate)
            }
        }
        Address::Internal(_) => {
            if args.tx.force {
                eprintln!(
                    "A validity predicate of an internal address cannot be \
                     directly updated."
                );
                Ok(())
            } else {
                Err(Error::ImplicitInternalError)
            }
        }
    }?;

    let vp_code_path = String::from_utf8(args.vp_code_path).unwrap();
    let vp_code_hash =
        query_wasm_code_hash(client, vp_code_path).await.unwrap();

    let tx_code_path = String::from_utf8(args.tx_code_path).unwrap();
    let tx_code_hash =
        query_wasm_code_hash(client, tx_code_path).await.unwrap();

    let data = UpdateVp { addr, vp_code_hash };
    let data = data.try_to_vec().map_err(Error::EncodeTxFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;

    let tx = Tx::new(tx_code_hash.to_vec(), Some(data), chain_id, expiration);
    process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::WalletAddress(args.addr),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;
    Ok(())
}

/// Submit a custom transaction
pub async fn submit_custom<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    args: args::TxCustom,
) -> Result<(), Error> {
    let tx_code = args.code_path;
    let data = args.data_path;
    let chain_id = args.tx.chain_id.clone().unwrap();
    let expiration = args.tx.expiration;
    let tx = Tx::new(tx_code, data, chain_id, expiration);
    let initialized_accounts = process_tx::<C, U>(
        client,
        wallet,
        &args.tx,
        tx,
        TxSigningKey::None,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;
    save_initialized_accounts::<U>(wallet, &args.tx, initialized_accounts)
        .await;
    Ok(())
}

async fn expect_dry_broadcast<T, C: crate::ledger::queries::Client + Sync>(
    to_broadcast: TxBroadcastData,
    client: &C,
    ret: T,
) -> Result<T, Error> {
    match to_broadcast {
        TxBroadcastData::DryRun(tx) => {
            rpc::dry_run_tx(client, tx.to_bytes()).await;
            Ok(ret)
        }
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash: _,
            decrypted_hash: _,
        } => Err(Error::ExpectDryRun(tx)),
    }
}

fn lift_rpc_error<T>(res: Result<T, RpcError>) -> Result<T, Error> {
    res.map_err(Error::TxBroadcast)
}

/// Returns the given validator if the given address is a validator,
/// otherwise returns an error, force forces the address through even
/// if it isn't a validator
async fn known_validator_or_err<C: crate::ledger::queries::Client + Sync>(
    validator: Address,
    force: bool,
    client: &C,
) -> Result<Address, Error> {
    // Check that the validator address exists on chain
    let is_validator = rpc::is_validator(client, &validator).await;
    if !is_validator {
        if force {
            eprintln!(
                "The address {} doesn't belong to any known validator account.",
                validator
            );
            Ok(validator)
        } else {
            Err(Error::InvalidValidatorAddress(validator))
        }
    } else {
        Ok(validator)
    }
}

/// general pattern for checking if an address exists on the chain, or
/// throwing an error if it's not forced. Takes a generic error
/// message and the error type.
async fn address_exists_or_err<C, F>(
    addr: Address,
    force: bool,
    client: &C,
    message: String,
    err: F,
) -> Result<Address, Error>
where
    C: crate::ledger::queries::Client + Sync,
    F: FnOnce(Address) -> Error,
{
    let addr_exists = rpc::known_address::<C>(client, &addr).await;
    if !addr_exists {
        if force {
            eprintln!("{}", message);
            Ok(addr)
        } else {
            Err(err(addr))
        }
    } else {
        Ok(addr)
    }
}

/// Returns the given token if the given address exists on chain
/// otherwise returns an error, force forces the address through even
/// if it isn't on chain
async fn token_exists_or_err<C: crate::ledger::queries::Client + Sync>(
    token: Address,
    force: bool,
    client: &C,
) -> Result<Address, Error> {
    let message =
        format!("The token address {} doesn't exist on chain.", token);
    address_exists_or_err(
        token,
        force,
        client,
        message,
        Error::TokenDoesNotExist,
    )
    .await
}

/// Returns the given source address if the given address exists on chain
/// otherwise returns an error, force forces the address through even
/// if it isn't on chain
async fn source_exists_or_err<C: crate::ledger::queries::Client + Sync>(
    token: Address,
    force: bool,
    client: &C,
) -> Result<Address, Error> {
    let message =
        format!("The source address {} doesn't exist on chain.", token);
    address_exists_or_err(
        token,
        force,
        client,
        message,
        Error::SourceDoesNotExist,
    )
    .await
}

/// Returns the given target address if the given address exists on chain
/// otherwise returns an error, force forces the address through even
/// if it isn't on chain
async fn target_exists_or_err<C: crate::ledger::queries::Client + Sync>(
    token: Address,
    force: bool,
    client: &C,
) -> Result<Address, Error> {
    let message =
        format!("The target address {} doesn't exist on chain.", token);
    address_exists_or_err(
        token,
        force,
        client,
        message,
        Error::TargetLocationDoesNotExist,
    )
    .await
}

/// checks the balance at the given address is enough to transfer the
/// given amount, along with the balance even existing. force
/// overrides this
async fn check_balance_too_low_err<C: crate::ledger::queries::Client + Sync>(
    token: &Address,
    source: &Address,
    amount: token::Amount,
    balance_key: storage::Key,
    force: bool,
    client: &C,
) -> Result<(), Error> {
    match rpc::query_storage_value::<C, token::Amount>(client, &balance_key)
        .await
    {
        Some(balance) => {
            if balance < amount {
                if force {
                    eprintln!(
                        "The balance of the source {} of token {} is lower \
                         than the amount to be transferred. Amount to \
                         transfer is {} and the balance is {}.",
                        source, token, amount, balance
                    );
                    Ok(())
                } else {
                    Err(Error::BalanceTooLow(
                        source.clone(),
                        token.clone(),
                        amount,
                        balance,
                    ))
                }
            } else {
                Ok(())
            }
        }
        None => {
            if force {
                eprintln!(
                    "No balance found for the source {} of token {}",
                    source, token
                );
                Ok(())
            } else {
                Err(Error::NoBalanceForToken(source.clone(), token.clone()))
            }
        }
    }
}

fn validate_untrusted_code_err(
    vp_code: &Vec<u8>,
    force: bool,
) -> Result<(), Error> {
    if let Err(err) = vm::validate_untrusted_wasm(vp_code) {
        if force {
            eprintln!("Validity predicate code validation failed with {}", err);
            Ok(())
        } else {
            Err(Error::WasmValidationFailure(err))
        }
    } else {
        Ok(())
    }
}
