//! SDK functions to construct different types of transactions
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use borsh::BorshSerialize;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::builder;
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::sapling::fees::{
    ConvertView, InputView as SaplingInputView, OutputView as SaplingOutputView,
};
use masp_primitives::transaction::components::transparent::fees::{
    InputView as TransparentInputView, OutputView as TransparentOutputView,
};
use masp_primitives::transaction::components::Amount;
use namada_core::ledger::governance::cli::onchain::{
    DefaultProposal, OnChainProposal, PgfFundingProposal, PgfStewardProposal,
    ProposalVote,
};
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::ledger::governance::storage::vote::StorageProposalVote;
use namada_core::types::address::{masp, Address};
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::token::MaspDenom;
use namada_core::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::{CommissionPair, ValidatorState};

use super::rpc::query_wasm_code_hash;
use super::signing;
use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc::core::ics04_channel::timeout::TimeoutHeight;
use crate::ibc::signer::Signer;
use crate::ibc::timestamp::Timestamp as IbcTimestamp;
use crate::ibc::tx_msg::Msg;
use crate::ibc::Height as IbcHeight;
use crate::ibc_proto::cosmos::base::v1beta1::Coin;
use crate::ledger::args::{self, InputAmount};
use crate::ledger::masp::{ShieldedContext, ShieldedTransfer, ShieldedUtils};
use crate::ledger::rpc::{
    self, format_denominated_amount, validate_amount, TxBroadcastData,
    TxResponse,
};
use crate::ledger::wallet::{Wallet, WalletUtils};
use crate::proto::{MaspBuilder, Tx};
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::tendermint_rpc::error::Error as RpcError;
use crate::types::control_flow::{time, ProceedOrElse};
use crate::types::error::{EncodingError, Error, QueryError, Result, TxError};
use crate::types::key::*;
use crate::types::masp::TransferTarget;
use crate::types::storage::Epoch;
use crate::types::time::DateTimeUtc;
use crate::types::transaction::account::{InitAccount, UpdateAccount};
use crate::types::transaction::{pos, TxType};
use crate::types::{storage, token};
use crate::vm;

/// Initialize account transaction WASM
pub const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
/// Initialize validator transaction WASM path
pub const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";
/// Initialize proposal transaction WASM path
pub const TX_INIT_PROPOSAL: &str = "tx_init_proposal.wasm";
/// Vote transaction WASM path
pub const TX_VOTE_PROPOSAL: &str = "tx_vote_proposal.wasm";
/// Reveal public key transaction WASM path
pub const TX_REVEAL_PK: &str = "tx_reveal_pk.wasm";
/// Update validity predicate WASM path
pub const TX_UPDATE_ACCOUNT_WASM: &str = "tx_update_account.wasm";
/// Transfer transaction WASM path
pub const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
/// IBC transaction WASM path
pub const TX_IBC_WASM: &str = "tx_ibc.wasm";
/// User validity predicate WASM path
pub const VP_USER_WASM: &str = "vp_user.wasm";
/// Bond WASM path
pub const TX_BOND_WASM: &str = "tx_bond.wasm";
/// Unbond WASM path
pub const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
/// Withdraw WASM path
pub const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";
/// Change commission WASM path
pub const TX_CHANGE_COMMISSION_WASM: &str =
    "tx_change_validator_commission.wasm";

/// Default timeout in seconds for requests to the `/accepted`
/// and `/applied` ABCI query endpoints.
const DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: u64 = 60;

/// Capture the result of running a transaction
pub enum ProcessTxResponse {
    /// Result of submitting a transaction to the blockchain
    Applied(TxResponse),
    /// Result of submitting a transaction to the mempool
    Broadcast(Response),
    /// Result of dry running transaction
    DryRun,
    /// Dump transaction to disk
    Dump,
}

impl ProcessTxResponse {
    /// Get the the accounts that were reported to be initialized
    pub fn initialized_accounts(&self) -> Vec<Address> {
        match self {
            Self::Applied(result) => result.initialized_accounts.clone(),
            _ => vec![],
        }
    }
}

/// Build and dump a transaction either to file or to screen
pub fn dump_tx(args: &args::Tx, tx: Tx) {
    let tx_id = tx.header_hash();
    let serialized_tx = tx.serialize();
    match args.output_folder.to_owned() {
        Some(path) => {
            let tx_filename = format!("{}.tx", tx_id);
            let out = File::create(path.join(tx_filename)).unwrap();
            serde_json::to_writer_pretty(out, &serialized_tx)
                .expect("Should be able to write to file.")
        }
        None => println!("{}", serialized_tx),
    }
}

/// Prepare a transaction for signing and submission by adding a wrapper header
/// to it.
pub async fn prepare_tx<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args: &args::Tx,
    tx: &mut Tx,
    gas_payer: common::PublicKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) {
    if !args.dry_run {
        let epoch = rpc::query_epoch(client).await;
        signing::wrap_tx(
            client,
            tx,
            args,
            epoch,
            gas_payer,
            #[cfg(not(feature = "mainnet"))]
            requires_pow,
        )
        .await
    }
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
) -> Result<ProcessTxResponse> {
    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    if args.dry_run {
        expect_dry_broadcast(TxBroadcastData::DryRun(tx), client).await
    } else {
        // We use this to determine when the wrapper tx makes it on-chain
        let wrapper_hash = tx.header_hash().to_string();
        // We use this to determine when the decrypted inner tx makes it
        // on-chain
        let decrypted_hash = tx
            .clone()
            .update_header(TxType::Raw)
            .header_hash()
            .to_string();
        let to_broadcast = TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        };
        // Either broadcast or submit transaction and collect result into
        // sum type
        if args.broadcast_only {
            broadcast_tx(client, &to_broadcast)
                .await
                .map(ProcessTxResponse::Broadcast)
        } else {
            match submit_tx(client, to_broadcast).await {
                Ok(x) => {
                    save_initialized_accounts::<U>(
                        wallet,
                        args,
                        x.initialized_accounts.clone(),
                    )
                    .await;
                    Ok(ProcessTxResponse::Applied(x))
                }
                Err(x) => Err(x),
            }
        }
    }
}

/// Check if a reveal public key transaction is needed
pub async fn is_reveal_pk_needed<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
    force: bool,
) -> Result<bool>
where
    C: crate::ledger::queries::Client + Sync,
{
    // Check if PK revealed
    Ok(force || !has_revealed_pk(client, address).await)
}

/// Check if the public key for the given address has been revealed
pub async fn has_revealed_pk<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    rpc::is_public_key_revealed(client, address).await
}

/// Submit transaction to reveal the given public key
pub async fn build_reveal_pk<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args: &args::Tx,
    address: &Address,
    public_key: common::PublicKey,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    println!(
        "Submitting a tx to reveal the public key for address {address}..."
    );

    build(
        client,
        args,
        args.tx_reveal_code_path.clone(),
        public_key,
        do_nothing,
        gas_payer,
    )
    .await
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx<C: crate::ledger::queries::Client + Sync>(
    rpc_cli: &C,
    to_broadcast: &TxBroadcastData,
) -> Result<Response> {
    let (tx, wrapper_tx_hash, decrypted_tx_hash) = match to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => Ok((tx, wrapper_hash, decrypted_hash)),
        TxBroadcastData::DryRun(tx) => {
            Err(TxError::ExpectWrappedRun(tx.clone()))
        }
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
        Err(Error::from(TxError::TxBroadcast(RpcError::server(
            serde_json::to_string(&response).map_err(|err| {
                Error::from(EncodingError::Serde(err.to_string()))
            })?,
        ))))
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
pub async fn submit_tx<C>(
    client: &C,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse>
where
    C: crate::ledger::queries::Client + Sync,
{
    let (_, wrapper_hash, decrypted_hash) = match &to_broadcast {
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => Ok((tx, wrapper_hash, decrypted_hash)),
        TxBroadcastData::DryRun(tx) => {
            Err(TxError::ExpectWrappedRun(tx.clone()))
        }
    }?;

    // Broadcast the supplied transaction
    broadcast_tx(client, &to_broadcast).await?;

    let deadline = time::Instant::now()
        + time::Duration::from_secs(
            DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS,
        );

    tracing::debug!(
        transaction = ?to_broadcast,
        ?deadline,
        "Awaiting transaction approval",
    );

    let parsed = {
        let wrapper_query =
            crate::ledger::rpc::TxEventQuery::Accepted(wrapper_hash.as_str());
        let event = rpc::query_tx_status(client, wrapper_query, deadline)
            .await
            .proceed_or(TxError::AcceptTimeout)?;
        let parsed = TxResponse::from_event(event);

        let tx_to_str = |parsed| {
            serde_json::to_string_pretty(parsed).map_err(|err| {
                Error::from(EncodingError::Serde(err.to_string()))
            })
        };
        println!("Transaction accepted with result: {}", tx_to_str(&parsed)?);
        // The transaction is now on chain. We wait for it to be decrypted
        // and applied
        if parsed.code == 0.to_string() {
            // We also listen to the event emitted when the encrypted
            // payload makes its way onto the blockchain
            let decrypted_query =
                rpc::TxEventQuery::Applied(decrypted_hash.as_str());
            let event = rpc::query_tx_status(client, decrypted_query, deadline)
                .await
                .proceed_or(TxError::AppliedTimeout)?;
            let parsed = TxResponse::from_event(event);
            println!(
                "Transaction applied with result: {}",
                tx_to_str(&parsed)?
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

/// decode components of a masp note
pub fn decode_component<K, F>(
    (addr, denom, epoch): (Address, MaspDenom, Epoch),
    val: i128,
    res: &mut HashMap<K, token::Change>,
    mk_key: F,
) where
    F: FnOnce(Address, Epoch) -> K,
    K: Eq + std::hash::Hash,
{
    let decoded_change = token::Change::from_masp_denominated(val, denom)
        .expect("expected this to fit");

    res.entry(mk_key(addr, epoch))
        .and_modify(|val| *val += decoded_change)
        .or_insert(decoded_change);
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
pub async fn build_validator_commission_change<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    args::CommissionRateChange {
        tx: tx_args,
        validator,
        rate,
        tx_code_path,
    }: args::CommissionRateChange,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let epoch = rpc::query_epoch(client).await;

    let params: PosParams = rpc::get_pos_params(client).await;

    let validator = validator.clone();
    if rpc::is_validator(client, &validator).await {
        if rate < Dec::zero() || rate > Dec::one() {
            eprintln!("Invalid new commission rate, received {}", rate);
            return Err(Error::from(TxError::InvalidCommissionRate(rate)));
        }

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
                if rate.abs_diff(&commission_rate)
                    > max_commission_change_per_epoch
                {
                    eprintln!(
                        "New rate is too large of a change with respect to \
                         the predecessor epoch in which the rate will take \
                         effect."
                    );
                    if !tx_args.force {
                        return Err(Error::from(
                            TxError::InvalidCommissionRate(rate),
                        ));
                    }
                }
            }
            None => {
                eprintln!("Error retrieving from storage");
                if !tx_args.force {
                    return Err(Error::from(TxError::Retrieval));
                }
            }
        }
    } else {
        eprintln!("The given address {validator} is not a validator.");
        if !tx_args.force {
            return Err(Error::from(TxError::InvalidValidatorAddress(
                validator,
            )));
        }
    }

    let data = pos::CommissionChange {
        validator: validator.clone(),
        new_rate: rate,
    };

    build(client, &tx_args, tx_code_path, data, do_nothing, gas_payer).await
}

/// Submit transaction to unjail a jailed validator
pub async fn build_unjail_validator<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    args::TxUnjailValidator {
        tx: tx_args,
        validator,
        tx_code_path,
    }: args::TxUnjailValidator,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    if !rpc::is_validator(client, &validator).await {
        eprintln!("The given address {} is not a validator.", &validator);
        if !tx_args.force {
            return Err(Error::from(TxError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(client).await;
    let current_epoch = rpc::query_epoch(client).await;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let validator_state_at_pipeline =
        rpc::get_validator_state(client, &validator, Some(pipeline_epoch))
            .await
            .ok_or_else(|| {
                Error::from(TxError::Other(
                    "Validator state should be defined.".to_string(),
                ))
            })?;
    if validator_state_at_pipeline != ValidatorState::Jailed {
        eprintln!(
            "The given validator address {} is not jailed at the pipeline \
             epoch when it would be restored to one of the validator sets.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxError::ValidatorNotCurrentlyJailed(
                validator.clone(),
            )));
        }
    }

    let last_slash_epoch_key =
        crate::ledger::pos::validator_last_slash_key(&validator);
    let last_slash_epoch =
        rpc::query_storage_value::<C, Epoch>(client, &last_slash_epoch_key)
            .await;
    if let Some(last_slash_epoch) = last_slash_epoch {
        let eligible_epoch =
            last_slash_epoch + params.slash_processing_epoch_offset();
        if current_epoch < eligible_epoch {
            eprintln!(
                "The given validator address {} is currently frozen and not \
                 yet eligible to be unjailed.",
                &validator
            );
            if !tx_args.force {
                return Err(Error::from(TxError::ValidatorNotCurrentlyJailed(
                    validator.clone(),
                )));
            }
        }
    }

    build(
        client,
        &tx_args,
        tx_code_path,
        validator,
        do_nothing,
        gas_payer,
    )
    .await
}

/// Submit transaction to withdraw an unbond
pub async fn build_withdraw<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args::Withdraw {
        tx: tx_args,
        validator,
        source,
        tx_code_path,
    }: args::Withdraw,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let epoch = rpc::query_epoch(client).await;

    let validator =
        known_validator_or_err(validator.clone(), tx_args.force, client)
            .await?;

    let source = source.clone();

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let tokens = rpc::query_withdrawable_tokens(
        client,
        &bond_source,
        &validator,
        Some(epoch),
    )
    .await;

    if tokens.is_zero() {
        eprintln!(
            "There are no unbonded bonds ready to withdraw in the current \
             epoch {}.",
            epoch
        );
        rpc::query_and_print_unbonds(client, &bond_source, &validator).await;
        if !tx_args.force {
            return Err(Error::from(TxError::NoUnbondReady(epoch)));
        }
    } else {
        println!(
            "Found {} tokens that can be withdrawn.",
            tokens.to_string_native()
        );
        println!("Submitting transaction to withdraw them...");
    }

    let data = pos::Withdraw { validator, source };

    build(client, &tx_args, tx_code_path, data, do_nothing, gas_payer).await
}

/// Submit a transaction to unbond
pub async fn build_unbond<
    C: crate::ledger::queries::Client + Sync,
    U: WalletUtils,
>(
    client: &C,
    _wallet: &mut Wallet<U>,
    args::Unbond {
        tx: tx_args,
        validator,
        amount,
        source,
        tx_code_path,
    }: args::Unbond,
    gas_payer: &common::PublicKey,
) -> Result<(Tx, Option<(Epoch, token::Amount)>)> {
    let source = source.clone();
    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());

    if !tx_args.force {
        known_validator_or_err(validator.clone(), tx_args.force, client)
            .await?;

        let bond_amount =
            rpc::query_bond(client, &bond_source, &validator, None).await;
        println!(
            "Bond amount available for unbonding: {} NAM",
            bond_amount.to_string_native()
        );

        if amount > bond_amount {
            eprintln!(
                "The total bonds of the source {} is lower than the amount to \
                 be unbonded. Amount to unbond is {} and the total bonds is \
                 {}.",
                bond_source,
                amount.to_string_native(),
                bond_amount.to_string_native()
            );
            if !tx_args.force {
                return Err(Error::from(TxError::LowerBondThanUnbond(
                    bond_source,
                    amount.to_string_native(),
                    bond_amount.to_string_native(),
                )));
            }
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
        amount,
        source: source.clone(),
    };

    let tx = build(client, &tx_args, tx_code_path, data, do_nothing, gas_payer)
        .await?;
    Ok((tx, latest_withdrawal_pre))
}

/// Query the unbonds post-tx
pub async fn query_unbonds<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args: args::Unbond,
    latest_withdrawal_pre: Option<(Epoch, token::Amount)>,
) -> Result<()> {
    let source = args.source.clone();
    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| args.validator.clone());

    // Query the unbonds post-tx
    let unbonds =
        rpc::query_unbond_with_slashing(client, &bond_source, &args.validator)
            .await;
    let mut withdrawable = BTreeMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        let to_withdraw = withdrawable.entry(withdraw_epoch).or_default();
        *to_withdraw += amount;
    }
    let (latest_withdraw_epoch_post, latest_withdraw_amount_post) =
        withdrawable.into_iter().last().ok_or_else(|| {
            Error::Other("No withdrawable amount".to_string())
        })?;

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
                    return Err(Error::from(TxError::UnboundError));
                }
            }
            std::cmp::Ordering::Equal => {
                println!(
                    "Amount {} withdrawable starting from epoch {}",
                    (latest_withdraw_amount_post - latest_withdraw_amount_pre)
                        .to_string_native(),
                    latest_withdraw_epoch_post
                );
            }
            std::cmp::Ordering::Greater => {
                println!(
                    "Amount {} withdrawable starting from epoch {}",
                    latest_withdraw_amount_post.to_string_native(),
                    latest_withdraw_epoch_post,
                );
            }
        }
    } else {
        println!(
            "Amount {} withdrawable starting from epoch {}",
            latest_withdraw_amount_post.to_string_native(),
            latest_withdraw_epoch_post,
        );
    }
    Ok(())
}

/// Submit a transaction to bond
pub async fn build_bond<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args::Bond {
        tx: tx_args,
        validator,
        amount,
        source,
        native_token,
        tx_code_path,
    }: args::Bond,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let validator =
        known_validator_or_err(validator.clone(), tx_args.force, client)
            .await?;

    // Check that the source address exists on chain
    let source = source.clone();
    let source = match source.clone() {
        Some(source) => source_exists_or_err(source, tx_args.force, client)
            .await
            .map(Some),
        None => Ok(source),
    }?;
    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let balance_key = token::balance_key(&native_token, bond_source);

    // TODO Should we state the same error message for the native token?
    check_balance_too_low_err(
        &native_token,
        bond_source,
        amount,
        balance_key,
        tx_args.force,
        client,
    )
    .await?;

    let data = pos::Bond {
        validator,
        amount,
        source,
    };

    build(client, &tx_args, tx_code_path, data, do_nothing, gas_payer).await
}

/// Build a default proposal governance
pub async fn build_default_proposal<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    args::InitProposal {
        tx,
        proposal_data: _,
        native_token: _,
        is_offline: _,
        is_pgf_stewards: _,
        is_pgf_funding: _,
        tx_code_path,
    }: args::InitProposal,
    proposal: DefaultProposal,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

    let push_data =
        |tx_builder: &mut Tx, init_proposal_data: &mut InitProposalData| {
            let (_, extra_section_hash) = tx_builder
                .add_extra_section(proposal_to_vec(proposal.proposal)?);
            init_proposal_data.content = extra_section_hash;

            if let Some(init_proposal_code) = proposal.data {
                let (_, extra_section_hash) =
                    tx_builder.add_extra_section(init_proposal_code);
                init_proposal_data.r#type =
                    ProposalType::Default(Some(extra_section_hash));
            };
            Ok(())
        };
    build(
        client,
        &tx,
        tx_code_path,
        init_proposal_data,
        push_data,
        gas_payer,
    )
    .await
}

/// Build a proposal vote
pub async fn build_vote_proposal<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args::VoteProposal {
        tx,
        proposal_id,
        vote,
        voter,
        is_offline: _,
        proposal_data: _,
        tx_code_path,
    }: args::VoteProposal,
    epoch: Epoch,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let proposal_vote = ProposalVote::try_from(vote)
        .map_err(|_| TxError::InvalidProposalVote)?;

    let proposal_id = proposal_id.ok_or_else(|| {
        Error::Other("Proposal id must be defined.".to_string())
    })?;
    let proposal = if let Some(proposal) =
        rpc::query_proposal_by_id(client, proposal_id).await
    {
        proposal
    } else {
        return Err(Error::from(TxError::ProposalDoesNotExist(proposal_id)));
    };

    let storage_vote =
        StorageProposalVote::build(&proposal_vote, &proposal.r#type)
            .ok_or_else(|| {
                Error::from(TxError::Other(
                    "Should be able to build the proposal vote".to_string(),
                ))
            })?;

    let is_validator = rpc::is_validator(client, &voter).await;

    if !proposal.can_be_voted(epoch, is_validator) {
        return Err(Error::from(TxError::InvalidProposalVotingPeriod(
            proposal_id,
        )));
    }

    let delegations = rpc::get_delegators_delegation_at(
        client,
        &voter,
        proposal.voting_start_epoch,
    )
    .await
    .keys()
    .cloned()
    .collect::<Vec<Address>>();

    let data = VoteProposalData {
        id: proposal_id,
        vote: storage_vote,
        voter: voter.clone(),
        delegations,
    };

    build(client, &tx, tx_code_path, data, do_nothing, gas_payer).await
}

/// Build a pgf funding proposal governance
pub async fn build_pgf_funding_proposal<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    args::InitProposal {
        tx,
        proposal_data: _,
        native_token: _,
        is_offline: _,
        is_pgf_stewards: _,
        is_pgf_funding: _,
        tx_code_path,
    }: args::InitProposal,
    proposal: PgfFundingProposal,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

    let add_section = |tx: &mut Tx, data: &mut InitProposalData| {
        let (_, extra_section_hash) =
            tx.add_extra_section(proposal_to_vec(proposal.proposal)?);
        data.content = extra_section_hash;
        Ok(())
    };
    build(
        client,
        &tx,
        tx_code_path,
        init_proposal_data,
        add_section,
        gas_payer,
    )
    .await
}

/// Build a pgf funding proposal governance
pub async fn build_pgf_stewards_proposal<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    args::InitProposal {
        tx,
        proposal_data: _,
        native_token: _,
        is_offline: _,
        is_pgf_stewards: _,
        is_pgf_funding: _,
        tx_code_path,
    }: args::InitProposal,
    proposal: PgfStewardProposal,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

    let add_section = |tx: &mut Tx, data: &mut InitProposalData| {
        let (_, extra_section_hash) =
            tx.add_extra_section(proposal_to_vec(proposal.proposal)?);
        data.content = extra_section_hash;
        Ok(())
    };

    build(
        client,
        &tx,
        tx_code_path,
        init_proposal_data,
        add_section,
        gas_payer,
    )
    .await
}

/// Submit an IBC transfer
pub async fn build_ibc_transfer<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args::TxIbcTransfer {
        tx: tx_args,
        source,
        receiver,
        token,
        amount,
        port_id,
        channel_id,
        timeout_height,
        timeout_sec_offset,
        tx_code_path,
    }: args::TxIbcTransfer,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    // Check that the source address exists on chain
    let source =
        source_exists_or_err(source.clone(), tx_args.force, client).await?;
    // We cannot check the receiver

    // Check source balance
    let balance_key = token::balance_key(&token, &source);

    check_balance_too_low_err(
        &token,
        &source,
        amount,
        balance_key,
        tx_args.force,
        client,
    )
    .await?;

    let tx_code_hash =
        query_wasm_code_hash(client, tx_code_path.to_string_lossy())
            .await
            .map_err(|e| Error::from(QueryError::Wasm(e.to_string())))?;

    let amount = amount
        .to_string_native()
        .split('.')
        .next()
        .ok_or_else(|| Error::Other("Invalid amount".to_string()))?
        .to_string();
    let token = Coin {
        denom: token.to_string(),
        amount,
    };

    // this height should be that of the destination chain, not this chain
    let timeout_height = match timeout_height {
        Some(h) => {
            TimeoutHeight::At(IbcHeight::new(0, h).map_err(|err| {
                Error::Other(format!("Invalid height: {err}"))
            })?)
        }
        None => TimeoutHeight::Never,
    };

    let now: std::result::Result<
        crate::tendermint::Time,
        namada_core::tendermint::Error,
    > = DateTimeUtc::now().try_into();
    let now = now.map_err(|e| Error::Other(e.to_string()))?;
    let now: IbcTimestamp = now.into();
    let timeout_timestamp = if let Some(offset) = timeout_sec_offset {
        (now + Duration::new(offset, 0))
            .map_err(|e| Error::Other(e.to_string()))?
    } else if timeout_height == TimeoutHeight::Never {
        // we cannot set 0 to both the height and the timestamp
        (now + Duration::new(3600, 0))
            .map_err(|e| Error::Other(e.to_string()))?
    } else {
        IbcTimestamp::none()
    };

    let msg = MsgTransfer {
        port_id_on_a: port_id,
        chan_id_on_a: channel_id,
        token,
        sender: Signer::from_str(&source.to_string()).map_err(|err| {
            Error::from(TxError::Other(format!("Invalid signer: {err}")))
        })?,
        receiver: Signer::from_str(&receiver).map_err(|err| {
            Error::from(TxError::Other(format!("Invalid signer: {err}")))
        })?,
        timeout_height_on_b: timeout_height,
        timeout_timestamp_on_b: timeout_timestamp,
    };

    let any_msg = msg.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data)
        .map_err(TxError::EncodeFailure)?;

    let chain_id = tx_args.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, tx_args.expiration);
    tx.add_code_from_hash(tx_code_hash)
        .add_serialized_data(data);

    prepare_tx::<C>(
        client,
        &tx_args,
        &mut tx,
        gas_payer.clone(),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
    Ok(tx)
}

/// Abstraction for helping build transactions
pub async fn build<C: crate::ledger::queries::Client + Sync, F, D>(
    client: &C,
    tx_args: &crate::ledger::args::Tx,
    path: PathBuf,
    data: D,
    on_tx: F,
    gas_payer: &common::PublicKey,
) -> Result<Tx>
where
    F: FnOnce(&mut Tx, &mut D) -> Result<()>,
    D: BorshSerialize,
{
    build_pow_flag(
        client,
        tx_args,
        path,
        data,
        on_tx,
        gas_payer,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await
}

async fn build_pow_flag<C: crate::ledger::queries::Client + Sync, F, D>(
    client: &C,
    tx_args: &crate::ledger::args::Tx,
    path: PathBuf,
    mut data: D,
    on_tx: F,
    gas_payer: &common::PublicKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> Result<Tx>
where
    F: FnOnce(&mut Tx, &mut D) -> Result<()>,
    D: BorshSerialize,
{
    let chain_id = tx_args.chain_id.clone().unwrap();

    let mut tx_builder = Tx::new(chain_id, tx_args.expiration);

    let tx_code_hash = query_wasm_code_hash(client, path.to_string_lossy())
        .await
        .map_err(|e| Error::from(QueryError::Wasm(e.to_string())))?;

    on_tx(&mut tx_builder, &mut data)?;

    tx_builder.add_code_from_hash(tx_code_hash).add_data(data);

    prepare_tx::<C>(
        client,
        tx_args,
        &mut tx_builder,
        gas_payer.clone(),
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await;
    Ok(tx_builder)
}

/// Try to decode the given asset type and add its decoding to the supplied set.
/// Returns true only if a new decoding has been added to the given set.
async fn add_asset_type<
    C: crate::ledger::queries::Client + Sync,
    U: ShieldedUtils,
>(
    asset_types: &mut HashSet<(Address, MaspDenom, Epoch)>,
    shielded: &mut ShieldedContext<U>,
    client: &C,
    asset_type: AssetType,
) -> bool {
    if let Some(asset_type) =
        shielded.decode_asset_type(client, asset_type).await
    {
        asset_types.insert(asset_type)
    } else {
        false
    }
}

/// Collect the asset types used in the given Builder and decode them. This
/// function provides the data necessary for offline wallets to present asset
/// type information.
async fn used_asset_types<
    C: crate::ledger::queries::Client + Sync,
    U: ShieldedUtils,
    P,
    R,
    K,
    N,
>(
    shielded: &mut ShieldedContext<U>,
    client: &C,
    builder: &Builder<P, R, K, N>,
) -> std::result::Result<HashSet<(Address, MaspDenom, Epoch)>, RpcError> {
    let mut asset_types = HashSet::new();
    // Collect all the asset types used in the Sapling inputs
    for input in builder.sapling_inputs() {
        add_asset_type(&mut asset_types, shielded, client, input.asset_type())
            .await;
    }
    // Collect all the asset types used in the transparent inputs
    for input in builder.transparent_inputs() {
        add_asset_type(
            &mut asset_types,
            shielded,
            client,
            input.coin().asset_type(),
        )
        .await;
    }
    // Collect all the asset types used in the Sapling outputs
    for output in builder.sapling_outputs() {
        add_asset_type(&mut asset_types, shielded, client, output.asset_type())
            .await;
    }
    // Collect all the asset types used in the transparent outputs
    for output in builder.transparent_outputs() {
        add_asset_type(&mut asset_types, shielded, client, output.asset_type())
            .await;
    }
    // Collect all the asset types used in the Sapling converts
    for output in builder.sapling_converts() {
        for (asset_type, _) in
            Amount::from(output.conversion().clone()).components()
        {
            add_asset_type(&mut asset_types, shielded, client, *asset_type)
                .await;
        }
    }
    Ok(asset_types)
}

/// Submit an ordinary transfer
pub async fn build_transfer<
    C: crate::ledger::queries::Client + Sync,
    U: ShieldedUtils,
>(
    client: &C,
    shielded: &mut ShieldedContext<U>,
    mut args: args::TxTransfer,
    gas_payer: &common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let source = args.source.effective_address();
    let target = args.target.effective_address();
    let token = args.token.clone();

    // Check that the source address exists on chain
    source_exists_or_err(source.clone(), args.tx.force, client).await?;
    // Check that the target address exists on chain
    target_exists_or_err(target.clone(), args.tx.force, client).await?;
    // Check source balance
    let balance_key = token::balance_key(&token, &source);

    // validate the amount given
    let validated_amount =
        validate_amount(client, args.amount, &token, args.tx.force).await?;
    let validate_fee = validate_amount(
        client,
        args.tx.gas_amount,
        &args.tx.gas_token,
        args.tx.force,
    )
    .await?;

    args.amount = InputAmount::Validated(validated_amount);
    args.tx.gas_amount = InputAmount::Validated(validate_fee);
    check_balance_too_low_err::<C>(
        &token,
        &source,
        validated_amount.amount,
        balance_key,
        args.tx.force,
        client,
    )
    .await?;

    let masp_addr = masp();
    // For MASP sources, use a special sentinel key recognized by VPs as default
    // signer. Also, if the transaction is shielded, redact the amount and token
    // types by setting the transparent value to 0 and token type to a constant.
    // This has no side-effect because transaction is to self.
    let (_amount, token, shielded_gas) =
        if source == masp_addr && target == masp_addr {
            // TODO Refactor me, we shouldn't rely on any specific token here.
            (token::Amount::default(), args.native_token.clone(), true)
        } else {
            (validated_amount.amount, token, false)
        };

    // Determine whether to pin this transaction to a storage key
    let key = match &args.target {
        TransferTarget::PaymentAddress(pa) if pa.is_pinned() => Some(pa.hash()),
        _ => None,
    };

    #[cfg(not(feature = "mainnet"))]
    let is_source_faucet = rpc::is_faucet_account(client, &source).await;
    #[cfg(feature = "mainnet")]
    let is_source_faucet = false;

    // Construct the shielded part of the transaction, if any
    let stx_result = shielded
        .gen_shielded_transfer(client, &args, shielded_gas)
        .await;

    let shielded_parts = match stx_result {
        Ok(stx) => Ok(stx),
        Err(builder::Error::InsufficientFunds(_)) => {
            Err(TxError::NegativeBalanceAfterTransfer(
                Box::new(source.clone()),
                validated_amount.amount.to_string_native(),
                Box::new(token.clone()),
                validate_fee.amount.to_string_native(),
                Box::new(args.tx.gas_token.clone()),
            ))
        }
        Err(err) => Err(TxError::MaspError(err.to_string())),
    }?;

    let shielded_tx_epoch = shielded_parts.clone().map(|trans| trans.epoch);

    let asset_types = match shielded_parts.clone() {
        None => None,
        Some(transfer) => {
            // Get the decoded asset types used in the transaction to give
            // offline wallet users more information
            let asset_types =
                used_asset_types(shielded, client, &transfer.builder)
                    .await
                    .unwrap_or_default();
            Some(asset_types)
        }
    };

    // Construct the corresponding transparent Transfer object
    let transfer = token::Transfer {
        source: source.clone(),
        target: target.clone(),
        token: token.clone(),
        amount: validated_amount,
        key: key.clone(),
        // Link the Transfer to the MASP Transaction by hash code
        shielded: None,
    };

    let add_shielded = |tx: &mut Tx, transfer: &mut token::Transfer| {
        // Add the MASP Transaction and its Builder to facilitate validation
        if let Some(ShieldedTransfer {
            builder,
            masp_tx,
            metadata,
            epoch: _,
        }) = shielded_parts
        {
            // Add a MASP Transaction section to the Tx and get the tx hash
            let masp_tx_hash = tx.add_masp_tx_section(masp_tx).1;
            transfer.shielded = Some(masp_tx_hash);

            tracing::debug!("Transfer data {:?}", transfer);

            tx.add_masp_builder(MaspBuilder {
                // Is safe
                asset_types: asset_types.unwrap(),
                // Store how the Info objects map to Descriptors/Outputs
                metadata,
                // Store the data that was used to construct the Transaction
                builder,
                // Link the Builder to the Transaction by hash code
                target: masp_tx_hash,
            });
        };
        Ok(())
    };
    let tx = build_pow_flag(
        client,
        &args.tx,
        args.tx_code_path,
        transfer,
        add_shielded,
        gas_payer,
        #[cfg(not(feature = "mainnet"))]
        is_source_faucet,
    )
    .await?;

    Ok((tx, shielded_tx_epoch))
}

/// Submit a transaction to initialize an account
pub async fn build_init_account<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args::TxInitAccount {
        tx: tx_args,
        vp_code_path,
        tx_code_path,
        public_keys,
        threshold,
    }: args::TxInitAccount,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let vp_code_hash = query_wasm_code_hash_buf(client, &vp_code_path).await?;

    let threshold = match threshold {
        Some(threshold) => threshold,
        None => {
            if public_keys.len() == 1 {
                1u8
            } else {
                return Err(Error::from(TxError::MissingAccountThreshold));
            }
        }
    };

    let data = InitAccount {
        public_keys,
        // We will add the hash inside the add_code_hash function
        vp_code_hash: Hash::zero(),
        threshold,
    };

    let add_code_hash = |tx: &mut Tx, data: &mut InitAccount| {
        let extra_section_hash = tx.add_extra_section_from_hash(vp_code_hash);
        data.vp_code_hash = extra_section_hash;
        Ok(())
    };
    build(
        client,
        &tx_args,
        tx_code_path,
        data,
        add_code_hash,
        gas_payer,
    )
    .await
}

/// Submit a transaction to update a VP
pub async fn build_update_account<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args::TxUpdateAccount {
        tx: tx_args,
        vp_code_path,
        tx_code_path,
        addr,
        public_keys,
        threshold,
    }: args::TxUpdateAccount,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let addr = if let Some(account) = rpc::get_account_info(client, &addr).await
    {
        account.address
    } else if tx_args.force {
        addr
    } else {
        return Err(Error::from(TxError::LocationDoesNotExist(addr)));
    };

    let vp_code_hash = match vp_code_path {
        Some(code_path) => {
            let vp_hash = query_wasm_code_hash_buf(client, &code_path).await?;
            Some(vp_hash)
        }
        None => None,
    };

    let chain_id = tx_args.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, tx_args.expiration);
    let extra_section_hash = vp_code_hash
        .map(|vp_code_hash| tx.add_extra_section_from_hash(vp_code_hash));

    let data = UpdateAccount {
        addr,
        vp_code_hash: extra_section_hash,
        public_keys,
        threshold,
    };

    let add_code_hash = |tx: &mut Tx, data: &mut UpdateAccount| {
        let extra_section_hash = vp_code_hash
            .map(|vp_code_hash| tx.add_extra_section_from_hash(vp_code_hash));
        data.vp_code_hash = extra_section_hash;
        Ok(())
    };
    build(
        client,
        &tx_args,
        tx_code_path,
        data,
        add_code_hash,
        gas_payer,
    )
    .await
}

/// Submit a custom transaction
pub async fn build_custom<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    args::TxCustom {
        tx: tx_args,
        code_path,
        data_path,
        serialized_tx,
        owner: _,
    }: args::TxCustom,
    gas_payer: &common::PublicKey,
) -> Result<Tx> {
    let mut tx = if let Some(serialized_tx) = serialized_tx {
        Tx::deserialize(serialized_tx.as_ref()).map_err(|_| {
            Error::Other("Invalid tx deserialization.".to_string())
        })?
    } else {
        let tx_code_hash = query_wasm_code_hash_buf(
            client,
            &code_path
                .ok_or(Error::Other("No code path supplied".to_string()))?,
        )
        .await?;
        let chain_id = tx_args.chain_id.clone().unwrap();
        let mut tx = Tx::new(chain_id, tx_args.expiration);
        tx.add_code_from_hash(tx_code_hash);
        data_path.map(|data| tx.add_serialized_data(data));
        tx
    };

    prepare_tx::<C>(
        client,
        &tx_args,
        &mut tx,
        gas_payer.clone(),
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await;
    Ok(tx)
}

async fn expect_dry_broadcast<C: crate::ledger::queries::Client + Sync>(
    to_broadcast: TxBroadcastData,
    client: &C,
) -> Result<ProcessTxResponse> {
    match to_broadcast {
        TxBroadcastData::DryRun(tx) => {
            rpc::dry_run_tx(client, tx.to_bytes()).await;
            Ok(ProcessTxResponse::DryRun)
        }
        TxBroadcastData::Wrapper {
            tx,
            wrapper_hash: _,
            decrypted_hash: _,
        } => Err(Error::from(TxError::ExpectDryRun(tx))),
    }
}

fn lift_rpc_error<T>(res: std::result::Result<T, RpcError>) -> Result<T> {
    res.map_err(|err| Error::from(TxError::TxBroadcast(err)))
}

/// Returns the given validator if the given address is a validator,
/// otherwise returns an error, force forces the address through even
/// if it isn't a validator
async fn known_validator_or_err<C: crate::ledger::queries::Client + Sync>(
    validator: Address,
    force: bool,
    client: &C,
) -> Result<Address> {
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
            Err(Error::from(TxError::InvalidValidatorAddress(validator)))
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
) -> Result<Address>
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

/// Returns the given source address if the given address exists on chain
/// otherwise returns an error, force forces the address through even
/// if it isn't on chain
async fn source_exists_or_err<C: crate::ledger::queries::Client + Sync>(
    token: Address,
    force: bool,
    client: &C,
) -> Result<Address> {
    let message =
        format!("The source address {} doesn't exist on chain.", token);
    address_exists_or_err(token, force, client, message, |err| {
        Error::from(TxError::SourceDoesNotExist(err))
    })
    .await
}

/// Returns the given target address if the given address exists on chain
/// otherwise returns an error, force forces the address through even
/// if it isn't on chain
async fn target_exists_or_err<C: crate::ledger::queries::Client + Sync>(
    token: Address,
    force: bool,
    client: &C,
) -> Result<Address> {
    let message =
        format!("The target address {} doesn't exist on chain.", token);
    address_exists_or_err(token, force, client, message, |err| {
        Error::from(TxError::TargetLocationDoesNotExist(err))
    })
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
) -> Result<()> {
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
                        source,
                        token,
                        format_denominated_amount(client, token, amount).await,
                        format_denominated_amount(client, token, balance).await,
                    );
                    Ok(())
                } else {
                    Err(Error::from(TxError::BalanceTooLow(
                        source.clone(),
                        token.clone(),
                        amount.to_string_native(),
                        balance.to_string_native(),
                    )))
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
                Err(Error::from(TxError::NoBalanceForToken(
                    source.clone(),
                    token.clone(),
                )))
            }
        }
    }
}

#[allow(dead_code)]
fn validate_untrusted_code_err(vp_code: &Vec<u8>, force: bool) -> Result<()> {
    if let Err(err) = vm::validate_untrusted_wasm(vp_code) {
        if force {
            eprintln!("Validity predicate code validation failed with {}", err);
            Ok(())
        } else {
            Err(Error::from(TxError::WasmValidationFailure(err)))
        }
    } else {
        Ok(())
    }
}
async fn query_wasm_code_hash_buf<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    path: &Path,
) -> Result<Hash> {
    query_wasm_code_hash(client, path.to_string_lossy()).await
}

/// A helper for [`fn build`] that can be used for `on_tx` arg that does nothing
fn do_nothing<D>(_tx: &mut Tx, _data: &mut D) -> Result<()>
where
    D: BorshSerialize,
{
    Ok(())
}

fn proposal_to_vec(proposal: OnChainProposal) -> Result<Vec<u8>> {
    proposal
        .content
        .try_to_vec()
        .map_err(|e| Error::from(EncodingError::Conversion(e.to_string())))
}
