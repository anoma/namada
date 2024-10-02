//! SDK functions to construct different types of transactions

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use borsh::BorshSerialize;
use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::sapling::fees::{
    ConvertView, InputView as SaplingInputView, OutputView as SaplingOutputView,
};
use masp_primitives::transaction::components::transparent::fees::{
    InputView as TransparentInputView, OutputView as TransparentOutputView,
};
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::transaction::{builder, Transaction as MaspTransaction};
use namada_account::{InitAccount, UpdateAccount};
use namada_core::address::{Address, IBC, MASP};
use namada_core::arith::checked;
use namada_core::chain::Epoch;
use namada_core::collections::HashSet;
use namada_core::dec::Dec;
use namada_core::hash::Hash;
use namada_core::ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use namada_core::ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use namada_core::ibc::apps::nft_transfer::types::PrefixedClassId;
use namada_core::ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use namada_core::ibc::apps::transfer::types::packet::PacketData;
use namada_core::ibc::apps::transfer::types::PrefixedCoin;
use namada_core::ibc::core::channel::types::timeout::{
    TimeoutHeight, TimeoutTimestamp,
};
use namada_core::ibc::core::client::types::Height as IbcHeight;
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::ibc::primitives::Timestamp as IbcTimestamp;
use namada_core::key::{self, *};
use namada_core::masp::{
    AssetData, ExtendedSpendingKey, MaspEpoch, TransferSource, TransferTarget,
};
use namada_core::storage;
use namada_core::time::DateTimeUtc;
use namada_governance::cli::onchain::{
    DefaultProposal, OnChainProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada_governance::pgf::cli::steward::Commission;
use namada_governance::storage::proposal::{
    InitProposalData, ProposalType, VoteProposalData,
};
use namada_governance::storage::vote::ProposalVote;
use namada_ibc::storage::channel_key;
use namada_ibc::trace::is_nft_trace;
use namada_ibc::{MsgNftTransfer, MsgTransfer};
use namada_io::{display_line, edisplay_line, Client, Io};
use namada_proof_of_stake::parameters::{
    PosParams, MAX_VALIDATOR_METADATA_LEN,
};
use namada_proof_of_stake::types::{CommissionPair, ValidatorState};
use namada_token as token;
use namada_token::masp::shielded_wallet::ShieldedApi;
use namada_token::masp::TransferErr::Build;
use namada_token::masp::{
    MaspDataLog, MaspFeeData, MaspTransferData, ShieldedTransfer,
};
use namada_token::storage_key::balance_key;
use namada_token::DenominatedAmount;
use namada_tx::data::pgf::UpdateStewardCommission;
use namada_tx::data::pos::{BecomeValidator, ConsensusKeyChange};
use namada_tx::data::{
    compute_inner_tx_hash, pos, BatchedTxResult, DryRunResult, ResultCode,
};
pub use namada_tx::{Authorization, *};
use num_traits::Zero;
use rand_core::{OsRng, RngCore};

use crate::args::{
    SdkTypes, TxShieldedTransferData, TxShieldingTransferData,
    TxTransparentTransferData, TxUnshieldingTransferData,
};
use crate::control_flow::time;
use crate::error::{EncodingError, Error, QueryError, Result, TxSubmitError};
use crate::rpc::{
    self, get_validator_stake, query_wasm_code_hash, validate_amount,
    InnerTxResult, TxBroadcastData, TxResponse,
};
use crate::signing::{
    self, validate_fee, validate_transparent_fee, SigningTxData,
};
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::tendermint_rpc::error::Error as RpcError;
use crate::wallet::WalletIo;
use crate::{args, Namada};

/// Initialize account transaction WASM
pub const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
/// Become validator transaction WASM path
pub const TX_BECOME_VALIDATOR_WASM: &str = "tx_become_validator.wasm";
/// Unjail validator transaction WASM path
pub const TX_UNJAIL_VALIDATOR_WASM: &str = "tx_unjail_validator.wasm";
/// Deactivate validator transaction WASM path
pub const TX_DEACTIVATE_VALIDATOR_WASM: &str = "tx_deactivate_validator.wasm";
/// Reactivate validator transaction WASM path
pub const TX_REACTIVATE_VALIDATOR_WASM: &str = "tx_reactivate_validator.wasm";
/// Initialize proposal transaction WASM path
pub const TX_INIT_PROPOSAL: &str = "tx_init_proposal.wasm";
/// Vote transaction WASM path
pub const TX_VOTE_PROPOSAL: &str = "tx_vote_proposal.wasm";
/// Reveal public key transaction WASM path
pub const TX_REVEAL_PK: &str = "tx_reveal_pk.wasm";
/// Update validity predicate WASM path
pub const TX_UPDATE_ACCOUNT_WASM: &str = "tx_update_account.wasm";
/// Transparent transfer transaction WASM path
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
/// Claim-rewards WASM path
pub const TX_CLAIM_REWARDS_WASM: &str = "tx_claim_rewards.wasm";
/// Bridge pool WASM path
pub const TX_BRIDGE_POOL_WASM: &str = "tx_bridge_pool.wasm";
/// Change commission WASM path
pub const TX_CHANGE_COMMISSION_WASM: &str =
    "tx_change_validator_commission.wasm";
/// Change consensus key WASM path
pub const TX_CHANGE_CONSENSUS_KEY_WASM: &str = "tx_change_consensus_key.wasm";
/// Change validator metadata WASM path
pub const TX_CHANGE_METADATA_WASM: &str = "tx_change_validator_metadata.wasm";
/// Resign steward WASM path
pub const TX_RESIGN_STEWARD: &str = "tx_resign_steward.wasm";
/// Update steward commission WASM path
pub const TX_UPDATE_STEWARD_COMMISSION: &str =
    "tx_update_steward_commission.wasm";
/// Redelegate transaction WASM path
pub const TX_REDELEGATE_WASM: &str = "tx_redelegate.wasm";

/// Refund target alias prefix for IBC shielded transfers
const IBC_REFUND_ALIAS_PREFIX: &str = "ibc-refund-target";

/// Default timeout in seconds for requests to the `/accepted`
/// and `/applied` ABCI query endpoints.
const DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS: u64 = 60;

/// Capture the result of running a transaction
#[derive(Debug)]
pub enum ProcessTxResponse {
    /// Result of submitting a transaction to the blockchain
    Applied(TxResponse),
    /// Result of submitting a transaction to the mempool
    Broadcast(Response),
    /// Result of dry running transaction
    DryRun(DryRunResult),
}

impl ProcessTxResponse {
    /// Returns a `TxResult` if the transaction applied and was it accepted by
    /// all VPs. Note that this always returns false for dry-run transactions.
    pub fn is_applied_and_valid(
        &self,
        wrapper_hash: Option<&Hash>,
        cmt: &TxCommitments,
    ) -> Option<&BatchedTxResult> {
        match self {
            ProcessTxResponse::Applied(resp) => {
                if resp.code == ResultCode::Ok {
                    if let Some(InnerTxResult::Success(result)) =
                        resp.batch_result().get(&compute_inner_tx_hash(
                            wrapper_hash,
                            either::Right(cmt),
                        ))
                    {
                        return Some(result);
                    }
                }
                None
            }
            ProcessTxResponse::DryRun(_) | ProcessTxResponse::Broadcast(_) => {
                None
            }
        }
    }
}

/// Build and dump a transaction either to file or to screen
pub fn dump_tx<IO: Io>(io: &IO, args: &args::Tx, tx: Tx) {
    match args.output_folder.clone() {
        Some(path) => {
            let tx_path = path.join(format!(
                "{}.tx",
                tx.header_hash().to_string().to_lowercase()
            ));
            let out = File::create(&tx_path)
                .expect("Should be able to create a file to dump tx");
            tx.to_writer_json(out)
                .expect("Should be able to write to file.");
            display_line!(
                io,
                "Transaction serialized to {}.",
                tx_path.to_string_lossy()
            );
        }
        None => {
            let serialized_tx = serde_json::to_string_pretty(&tx)
                .expect("Should be able to json encode the tx.");
            display_line!(io, "Below the serialized transaction: \n");
            display_line!(io, "{}", serialized_tx)
        }
    }
}

/// Prepare a transaction for signing and submission by adding a wrapper header
/// to it.
pub async fn prepare_tx(
    args: &args::Tx,
    tx: &mut Tx,
    fee_amount: DenominatedAmount,
    fee_payer: common::PublicKey,
) -> Result<()> {
    if !args.dry_run {
        signing::wrap_tx(tx, args, fee_amount, fee_payer).await
    } else {
        Ok(())
    }
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
pub async fn process_tx(
    context: &impl Namada,
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

    if args.dry_run || args.dry_run_wrapper {
        expect_dry_broadcast(TxBroadcastData::DryRun(tx), context).await
    } else {
        // We use this to determine when the wrapper tx makes it on-chain
        let tx_hash = tx.header_hash().to_string();
        let cmts = tx.commitments().clone();
        let wrapper_hash = tx.wrapper_hash();
        // We use this to determine when the decrypted inner tx makes it
        // on-chain
        let to_broadcast = TxBroadcastData::Live { tx, tx_hash };
        if args.broadcast_only {
            broadcast_tx(context, &to_broadcast)
                .await
                .map(ProcessTxResponse::Broadcast)
        } else {
            match submit_tx(context, to_broadcast).await {
                Ok(resp) => {
                    for cmt in cmts {
                        if let Some(InnerTxResult::Success(result)) =
                            resp.batch_result().get(&compute_inner_tx_hash(
                                wrapper_hash.as_ref(),
                                either::Right(&cmt),
                            ))
                        {
                            save_initialized_accounts(
                                context,
                                args,
                                result.initialized_accounts.clone(),
                            )
                            .await;
                        }
                    }
                    Ok(ProcessTxResponse::Applied(resp))
                }
                Err(x) => Err(x),
            }
        }
    }
}

/// Check if a reveal public key transaction is needed
pub async fn is_reveal_pk_needed<C: Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool> {
    // Check if PK revealed
    Ok(!has_revealed_pk(client, address).await?)
}

/// Check if the public key for the given address has been revealed
pub async fn has_revealed_pk<C: Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool> {
    rpc::is_public_key_revealed(client, address).await
}

/// Submit transaction to reveal the given public key
pub async fn build_reveal_pk(
    context: &impl Namada,
    args: &args::Tx,
    public_key: &common::PublicKey,
) -> Result<(Tx, SigningTxData)> {
    let signing_data = signing::aux_signing_data(
        context,
        args,
        None,
        Some(public_key.into()),
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, args, &signing_data.fee_payer)
            .await?;

    build(
        context,
        args,
        args.tx_reveal_code_path.clone(),
        public_key,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a node
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx(
    context: &impl Namada,
    to_broadcast: &TxBroadcastData,
) -> Result<Response> {
    let (tx, tx_hash) = match to_broadcast {
        TxBroadcastData::Live { tx, tx_hash } => Ok((tx, tx_hash)),
        TxBroadcastData::DryRun(tx) => {
            Err(TxSubmitError::ExpectLiveRun(tx.clone()))
        }
    }?;

    tracing::debug!(
        transaction = ?to_broadcast,
        "Broadcasting transaction",
    );

    let response = lift_rpc_error(
        context.client().broadcast_tx_sync(tx.to_bytes()).await,
    )?;

    if response.code == 0.into() {
        display_line!(context.io(), "Transaction added to mempool.");
        tracing::debug!("Transaction mempool response: {response:#?}");
        // Print the transaction identifiers to enable the extraction of
        // acceptance/application results later
        {
            display_line!(context.io(), "Transaction hash: {tx_hash}",);
        }
        Ok(response)
    } else {
        Err(Error::from(TxSubmitError::TxBroadcast(RpcError::server(
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
pub async fn submit_tx(
    context: &impl Namada,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse> {
    let (_, tx_hash) = match &to_broadcast {
        TxBroadcastData::Live { tx, tx_hash } => Ok((tx, tx_hash)),
        TxBroadcastData::DryRun(tx) => {
            Err(TxSubmitError::ExpectLiveRun(tx.clone()))
        }
    }?;

    // Broadcast the supplied transaction
    broadcast_tx(context, &to_broadcast).await?;

    #[allow(clippy::disallowed_methods)]
    let deadline = time::Instant::now()
        + time::Duration::from_secs(
            DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS,
        );

    tracing::debug!(
        transaction = ?to_broadcast,
        ?deadline,
        "Awaiting transaction approval",
    );

    // The transaction is now on chain. We wait for it to be applied
    let tx_query = rpc::TxEventQuery::Applied(tx_hash.as_str());
    let event = rpc::query_tx_status(context, tx_query, deadline).await?;
    let response = TxResponse::from_event(event);
    display_batch_resp(context, &response);
    Ok(response)
}

/// Display a result of a tx batch.
pub fn display_batch_resp(context: &impl Namada, resp: &TxResponse) {
    for (inner_hash, result) in resp.batch_result() {
        match result {
            InnerTxResult::Success(_) => {
                display_line!(
                    context.io(),
                    "Transaction {} was successfully applied at height {}, \
                     consuming {} gas units.",
                    inner_hash,
                    resp.height,
                    resp.gas_used
                );
            }
            InnerTxResult::VpsRejected(inner) => {
                let changed_keys: Vec<_> = inner
                    .changed_keys
                    .iter()
                    .map(storage::Key::to_string)
                    .collect();
                edisplay_line!(
                    context.io(),
                    "Transaction {} was rejected by VPs: {}\nErrors: \
                     {}\nChanged keys: {}",
                    inner_hash,
                    serde_json::to_string_pretty(
                        &inner.vps_result.rejected_vps
                    )
                    .unwrap(),
                    serde_json::to_string_pretty(&inner.vps_result.errors)
                        .unwrap(),
                    serde_json::to_string_pretty(&changed_keys).unwrap(),
                );
            }
            InnerTxResult::OtherFailure => {
                edisplay_line!(
                    context.io(),
                    "Transaction {} failed.\nDetails: {}",
                    inner_hash,
                    serde_json::to_string_pretty(&resp).unwrap()
                );
            }
        }
    }

    tracing::debug!(
        "Full result: {}",
        serde_json::to_string_pretty(&resp).unwrap()
    );
}

/// Save accounts initialized from a tx into the wallet, if any.
pub async fn save_initialized_accounts<N: Namada>(
    context: &N,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    let len = initialized_accounts.len();
    if len != 0 {
        // Store newly initialized account addresses in the wallet
        display_line!(
            context.io(),
            "The transaction initialized {} new account{}",
            len,
            if len == 1 { "" } else { "s" }
        );
        // Store newly initialized account addresses in the wallet
        for (ix, address) in initialized_accounts.iter().enumerate() {
            let encoded = address.encode();
            let alias: Cow<'_, str> = match &args.initialized_account_alias {
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
                None => N::WalletUtils::read_alias(&encoded).into(),
            };
            let alias = alias.into_owned();
            let added = context.wallet_mut().await.insert_address(
                alias.clone(),
                address.clone(),
                args.wallet_alias_force,
            );
            match added {
                Some(new_alias) if new_alias != encoded => {
                    display_line!(
                        context.io(),
                        "Added alias {} for address {}.",
                        new_alias,
                        encoded
                    );
                }
                _ => {
                    display_line!(
                        context.io(),
                        "No alias added for address {}.",
                        encoded
                    )
                }
            };
        }
    }
}

/// Submit validator commission rate change
pub async fn build_change_consensus_key(
    context: &impl Namada,
    args::ConsensusKeyChange {
        tx: tx_args,
        validator,
        consensus_key,
        tx_code_path,
        unsafe_dont_encrypt: _,
    }: &args::ConsensusKeyChange,
) -> Result<(Tx, SigningTxData)> {
    let consensus_key = if let Some(consensus_key) = consensus_key {
        consensus_key
    } else {
        edisplay_line!(context.io(), "Consensus key must must be present.");
        return Err(Error::from(TxSubmitError::Other(
            "Consensus key must must be present.".to_string(),
        )));
    };

    // Check that the new consensus key is unique
    let consensus_keys = rpc::get_consensus_keys(context.client()).await?;

    if consensus_keys.contains(consensus_key) {
        edisplay_line!(
            context.io(),
            "The consensus key is already being used."
        );
        return Err(Error::from(TxSubmitError::ConsensusKeyNotUnique));
    }

    let data = ConsensusKeyChange {
        validator: validator.clone(),
        consensus_key: consensus_key.clone(),
    };

    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        None,
        None,
        vec![consensus_key.clone()],
        false,
    )
    .await?;

    let (fee_amount, _updated_balance) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit validator commission rate change
pub async fn build_validator_commission_change(
    context: &impl Namada,
    args::CommissionRateChange {
        tx: tx_args,
        validator,
        rate,
        tx_code_path,
    }: &args::CommissionRateChange,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(validator.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(validator.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    let epoch = rpc::query_epoch(context.client()).await?;

    let params: PosParams = rpc::get_pos_params(context.client()).await?;

    let validator = validator.clone();
    if rpc::is_validator(context.client(), &validator).await? {
        if *rate < Dec::zero() || *rate > Dec::one() {
            edisplay_line!(
                context.io(),
                "Invalid new commission rate, received {}",
                rate
            );
            return Err(Error::from(TxSubmitError::InvalidCommissionRate(
                *rate,
            )));
        }

        let pipeline_epoch_minus_one =
            epoch.unchecked_add(params.pipeline_len - 1);

        let CommissionPair {
            commission_rate,
            max_commission_change_per_epoch,
            epoch: _,
        } = rpc::query_commission_rate(
            context.client(),
            &validator,
            Some(pipeline_epoch_minus_one),
        )
        .await?;

        match (commission_rate, max_commission_change_per_epoch) {
            (Some(commission_rate), Some(max_commission_change_per_epoch)) => {
                if rate.is_negative() || *rate > Dec::one() {
                    edisplay_line!(
                        context.io(),
                        "New rate is outside of the allowed range of values \
                         between 0.0 and 1.0."
                    );
                    if !tx_args.force {
                        return Err(Error::from(
                            TxSubmitError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
                if rate.abs_diff(commission_rate)?
                    > max_commission_change_per_epoch
                {
                    edisplay_line!(
                        context.io(),
                        "New rate is too large of a change with respect to \
                         the predecessor epoch in which the rate will take \
                         effect."
                    );
                    if !tx_args.force {
                        return Err(Error::from(
                            TxSubmitError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
            }
            (None, None) => {
                edisplay_line!(
                    context.io(),
                    "Error retrieving commission data from validator storage. \
                     This address may not yet be a validator."
                );
                if !tx_args.force {
                    return Err(Error::from(TxSubmitError::Retrieval));
                }
            }
            _ => {
                edisplay_line!(
                    context.io(),
                    "Error retrieving some of the commission data from \
                     validator storage, while other data was found. This is a \
                     bug and should be reported."
                );
                if !tx_args.force {
                    return Err(Error::from(TxSubmitError::Retrieval));
                }
            }
        }
    } else {
        edisplay_line!(
            context.io(),
            "The given address {validator} is not a validator."
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidValidatorAddress(
                validator,
            )));
        }
    }

    let data = pos::CommissionChange {
        validator: validator.clone(),
        new_rate: *rate,
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit validator metadata change
pub async fn build_validator_metadata_change(
    context: &impl Namada,
    args::MetaDataChange {
        tx: tx_args,
        validator,
        email,
        description,
        website,
        discord_handle,
        avatar,
        name,
        commission_rate,
        tx_code_path,
    }: &args::MetaDataChange,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(validator.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(validator.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    let epoch = rpc::query_epoch(context.client()).await?;

    let params: PosParams = rpc::get_pos_params(context.client()).await?;

    // The validator must actually be a validator
    let validator =
        known_validator_or_err(validator.clone(), tx_args.force, context)
            .await?;

    // If there is a new email, it cannot be an empty string that indicates to
    // remove the data (email data cannot be removed)
    if let Some(email) = email.as_ref() {
        if email.is_empty() {
            edisplay_line!(
                context.io(),
                "Cannot remove a validator's email, which was implied by the \
                 empty string"
            );
            return Err(Error::from(TxSubmitError::InvalidEmail));
        }
        // Check that the email is within MAX_VALIDATOR_METADATA_LEN characters
        if email.len() as u64 > MAX_VALIDATOR_METADATA_LEN {
            edisplay_line!(
                context.io(),
                "Email provided is too long, must be within \
                 {MAX_VALIDATOR_METADATA_LEN} characters"
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::MetadataTooLong));
            }
        }
    }

    // Check that any new metadata provided is within MAX_VALIDATOR_METADATA_LEN
    // characters
    if let Some(description) = description.as_ref() {
        if description.len() as u64 > MAX_VALIDATOR_METADATA_LEN {
            edisplay_line!(
                context.io(),
                "Description provided is too long, must be within \
                 {MAX_VALIDATOR_METADATA_LEN} characters"
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::MetadataTooLong));
            }
        }
    }
    if let Some(website) = website.as_ref() {
        if website.len() as u64 > MAX_VALIDATOR_METADATA_LEN {
            edisplay_line!(
                context.io(),
                "Website provided is too long, must be within \
                 {MAX_VALIDATOR_METADATA_LEN} characters"
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::MetadataTooLong));
            }
        }
    }
    if let Some(discord_handle) = discord_handle.as_ref() {
        if discord_handle.len() as u64 > MAX_VALIDATOR_METADATA_LEN {
            edisplay_line!(
                context.io(),
                "Discord handle provided is too long, must be within \
                 {MAX_VALIDATOR_METADATA_LEN} characters"
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::MetadataTooLong));
            }
        }
    }
    if let Some(avatar) = avatar.as_ref() {
        if avatar.len() as u64 > MAX_VALIDATOR_METADATA_LEN {
            edisplay_line!(
                context.io(),
                "Avatar provided is too long, must be within \
                 {MAX_VALIDATOR_METADATA_LEN} characters"
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::MetadataTooLong));
            }
        }
    }
    if let Some(name) = name.as_ref() {
        if name.len() as u64 > MAX_VALIDATOR_METADATA_LEN {
            edisplay_line!(
                context.io(),
                "Name provided is too long, must be within \
                 {MAX_VALIDATOR_METADATA_LEN} characters"
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::MetadataTooLong));
            }
        }
    }

    // If there's a new commission rate, it must be valid
    if let Some(rate) = commission_rate.as_ref() {
        if *rate < Dec::zero() || *rate > Dec::one() {
            edisplay_line!(
                context.io(),
                "Invalid new commission rate, received {}",
                rate
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::InvalidCommissionRate(
                    *rate,
                )));
            }
        }
        let pipeline_epoch_minus_one =
            epoch.unchecked_add(params.pipeline_len - 1);

        let CommissionPair {
            commission_rate,
            max_commission_change_per_epoch,
            epoch: _,
        } = rpc::query_commission_rate(
            context.client(),
            &validator,
            Some(pipeline_epoch_minus_one),
        )
        .await?;

        match (commission_rate, max_commission_change_per_epoch) {
            (Some(commission_rate), Some(max_commission_change_per_epoch)) => {
                if rate.is_negative() || *rate > Dec::one() {
                    edisplay_line!(
                        context.io(),
                        "New rate is outside of the allowed range of values \
                         between 0.0 and 1.0."
                    );
                    if !tx_args.force {
                        return Err(Error::from(
                            TxSubmitError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
                if rate.abs_diff(commission_rate)?
                    > max_commission_change_per_epoch
                {
                    edisplay_line!(
                        context.io(),
                        "New rate is too large of a change with respect to \
                         the predecessor epoch in which the rate will take \
                         effect."
                    );
                    if !tx_args.force {
                        return Err(Error::from(
                            TxSubmitError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
            }
            (None, None) => {
                edisplay_line!(
                    context.io(),
                    "Error retrieving commission data from validator storage. \
                     This address may not yet be a validator."
                );
                if !tx_args.force {
                    return Err(Error::from(TxSubmitError::Retrieval));
                }
            }
            _ => {
                edisplay_line!(
                    context.io(),
                    "Error retrieving some of the commission data from \
                     validator storage, while other data was found. This is a \
                     bug and should be reported."
                );
                if !tx_args.force {
                    return Err(Error::from(TxSubmitError::Retrieval));
                }
            }
        }
    }

    let data = pos::MetaDataChange {
        validator: validator.clone(),
        email: email.clone(),
        website: website.clone(),
        description: description.clone(),
        discord_handle: discord_handle.clone(),
        avatar: avatar.clone(),
        name: name.clone(),
        commission_rate: *commission_rate,
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Craft transaction to update a steward commission
pub async fn build_update_steward_commission(
    context: &impl Namada,
    args::UpdateStewardCommission {
        tx: tx_args,
        steward,
        commission,
        tx_code_path,
    }: &args::UpdateStewardCommission,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(steward.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(steward.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    if !rpc::is_steward(context.client(), steward).await {
        edisplay_line!(
            context.io(),
            "The given address {} is not a steward.",
            &steward
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidSteward(
                steward.clone(),
            )));
        }
    };

    let commission = Commission::try_from(commission.as_ref())
        .map_err(|e| TxSubmitError::InvalidStewardCommission(e.to_string()))?;

    if !commission.is_valid() {
        edisplay_line!(
            context.io(),
            "The sum of all percentage must not be greater than 1."
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidStewardCommission(
                "Commission sum is greater than 1.".to_string(),
            )));
        }
    }

    let data = UpdateStewardCommission {
        steward: steward.clone(),
        commission: commission.reward_distribution,
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Craft transaction to resign as a steward
pub async fn build_resign_steward(
    context: &impl Namada,
    args::ResignSteward {
        tx: tx_args,
        steward,
        tx_code_path,
    }: &args::ResignSteward,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(steward.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(steward.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    if !rpc::is_steward(context.client(), steward).await {
        edisplay_line!(
            context.io(),
            "The given address {} is not a steward.",
            &steward
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidSteward(
                steward.clone(),
            )));
        }
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        steward.clone(),
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit transaction to unjail a jailed validator
pub async fn build_unjail_validator(
    context: &impl Namada,
    args::TxUnjailValidator {
        tx: tx_args,
        validator,
        tx_code_path,
    }: &args::TxUnjailValidator,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(validator.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(validator.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    if !rpc::is_validator(context.client(), validator).await? {
        edisplay_line!(
            context.io(),
            "The given address {} is not a validator.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch.unchecked_add(params.pipeline_len);

    let (validator_state_at_pipeline, _) = rpc::get_validator_state(
        context.client(),
        validator,
        Some(pipeline_epoch),
    )
    .await?;
    if validator_state_at_pipeline != Some(ValidatorState::Jailed) {
        edisplay_line!(
            context.io(),
            "The given validator address {} is not jailed at the pipeline \
             epoch when it would be restored to one of the validator sets.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(
                TxSubmitError::ValidatorNotCurrentlyJailed(validator.clone()),
            ));
        }
    }

    let last_slash_epoch =
        rpc::query_last_infraction_epoch(context.client(), validator).await;
    match last_slash_epoch {
        Ok(Some(last_slash_epoch)) => {
            // Jailed due to slashing
            let eligible_epoch = last_slash_epoch
                .unchecked_add(params.slash_processing_epoch_offset());
            if current_epoch < eligible_epoch {
                edisplay_line!(
                    context.io(),
                    "The given validator address {} is currently frozen and \
                     will be eligible to be unjailed starting at epoch {}.",
                    &validator,
                    eligible_epoch
                );
                if !tx_args.force {
                    return Err(Error::from(TxSubmitError::ValidatorFrozen(
                        validator.clone(),
                    )));
                }
            }
        }
        Ok(None) => {
            // Jailed due to liveness only. No checks needed.
        }
        Err(err) => {
            if !tx_args.force {
                return Err(err);
            }
        }
    }

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        validator.clone(),
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit transaction to deactivate a validator
pub async fn build_deactivate_validator(
    context: &impl Namada,
    args::TxDeactivateValidator {
        tx: tx_args,
        validator,
        tx_code_path,
    }: &args::TxDeactivateValidator,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(validator.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(validator.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    // Check if the validator address is actually a validator
    if !rpc::is_validator(context.client(), validator).await? {
        edisplay_line!(
            context.io(),
            "The given address {} is not a validator.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch.unchecked_add(params.pipeline_len);

    let (validator_state_at_pipeline, _) = rpc::get_validator_state(
        context.client(),
        validator,
        Some(pipeline_epoch),
    )
    .await?;
    if validator_state_at_pipeline == Some(ValidatorState::Inactive) {
        edisplay_line!(
            context.io(),
            "The given validator address {} is already inactive at the \
             pipeline epoch {}.",
            &validator,
            &pipeline_epoch
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::ValidatorInactive(
                validator.clone(),
                pipeline_epoch,
            )));
        }
    }

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        validator.clone(),
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit transaction to deactivate a validator
pub async fn build_reactivate_validator(
    context: &impl Namada,
    args::TxReactivateValidator {
        tx: tx_args,
        validator,
        tx_code_path,
    }: &args::TxReactivateValidator,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(validator.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(validator.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    // Check if the validator address is actually a validator
    if !rpc::is_validator(context.client(), validator).await? {
        edisplay_line!(
            context.io(),
            "The given address {} is not a validator.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch.unchecked_add(params.pipeline_len);

    for epoch in Epoch::iter_bounds_inclusive(current_epoch, pipeline_epoch) {
        let (validator_state, _) =
            rpc::get_validator_state(context.client(), validator, Some(epoch))
                .await?;

        if validator_state != Some(ValidatorState::Inactive) {
            edisplay_line!(
                context.io(),
                "The given validator address {} is not inactive at epoch {}.",
                &validator,
                &epoch
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::ValidatorNotInactive(
                    validator.clone(),
                    epoch,
                )));
            }
        }
    }

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        validator.clone(),
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Redelegate bonded tokens from one validator to another
pub async fn build_redelegation(
    context: &impl Namada,
    args::Redelegate {
        tx: tx_args,
        src_validator,
        dest_validator,
        owner,
        amount: redel_amount,
        tx_code_path,
    }: &args::Redelegate,
) -> Result<(Tx, SigningTxData)> {
    // Require a positive amount of tokens to be redelegated
    if redel_amount.is_zero() {
        edisplay_line!(
            context.io(),
            "The requested redelegation amount is 0. A positive amount must \
             be requested."
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::RedelegationIsZero));
        }
    }

    // The src and dest validators must actually be validators
    let src_validator =
        known_validator_or_err(src_validator.clone(), tx_args.force, context)
            .await?;
    let dest_validator =
        known_validator_or_err(dest_validator.clone(), tx_args.force, context)
            .await?;

    // The delegator (owner) must exist on-chain and must not be a validator
    let owner =
        source_exists_or_err(owner.clone(), tx_args.force, context).await?;
    if rpc::is_validator(context.client(), &owner).await? {
        edisplay_line!(
            context.io(),
            "The given address {} is a validator. A validator is prohibited \
             from redelegating its own bonds.",
            &owner
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::RedelegatorIsValidator(
                owner.clone(),
            )));
        }
    }

    // Prohibit redelegation to the same validator
    if src_validator == dest_validator {
        edisplay_line!(
            context.io(),
            "The provided source and destination validators are the same. \
             Redelegation is not allowed to the same validator."
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::RedelegationSrcEqDest));
        }
    }

    // Prohibit chained redelegations
    let params = rpc::get_pos_params(context.client()).await?;
    let incoming_redel_epoch = rpc::query_incoming_redelegations(
        context.client(),
        &src_validator,
        &owner,
    )
    .await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let is_not_chained = if let Some(redel_end_epoch) = incoming_redel_epoch {
        let last_contrib_epoch =
            redel_end_epoch.prev().expect("End epoch must have a prev");
        last_contrib_epoch.unchecked_add(params.slash_processing_epoch_offset())
            <= current_epoch
    } else {
        true
    };
    if !is_not_chained {
        edisplay_line!(
            context.io(),
            "The source validator {} has an incoming redelegation from the \
             delegator {} that may still be subject to future slashing. \
             Redelegation is not allowed until this is no longer the case.",
            &src_validator,
            &owner
        );
        if !tx_args.force {
            return Err(Error::from(
                TxSubmitError::IncomingRedelIsStillSlashable(
                    src_validator.clone(),
                    owner.clone(),
                ),
            ));
        }
    }

    // Give a redelegation warning based on the pipeline state of the dest
    // validator
    let pipeline_epoch = current_epoch.unchecked_add(params.pipeline_len);
    let (dest_validator_state_at_pipeline, _) = rpc::get_validator_state(
        context.client(),
        &dest_validator,
        Some(pipeline_epoch),
    )
    .await?;
    if dest_validator_state_at_pipeline == Some(ValidatorState::Inactive) {
        edisplay_line!(
            context.io(),
            "WARNING: the given destination validator address {} is inactive \
             at the pipeline epoch {}. If you would still like to redelegate \
             to the inactive validator, use the --force option.",
            &dest_validator,
            &pipeline_epoch
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::ValidatorInactive(
                dest_validator.clone(),
                pipeline_epoch,
            )));
        }
    }

    // There must be at least as many tokens in the bond as the requested
    // redelegation amount
    let bond_amount =
        rpc::query_bond(context.client(), &owner, &src_validator, None).await?;
    if *redel_amount > bond_amount {
        edisplay_line!(
            context.io(),
            "There are not enough tokens available for the desired \
             redelegation at the current epoch {}. Requested to redelegate {} \
             tokens but only {} tokens are available.",
            current_epoch,
            redel_amount.to_string_native(),
            bond_amount.to_string_native()
        );
        if !tx_args.force {
            return Err(Error::from(
                TxSubmitError::RedelegationAmountTooLarge(
                    redel_amount.to_string_native(),
                    bond_amount.to_string_native(),
                ),
            ));
        }
    } else {
        display_line!(
            context.io(),
            "{} NAM tokens available for redelegation. Submitting \
             redelegation transaction for {} tokens...",
            bond_amount.to_string_native(),
            redel_amount.to_string_native()
        );
    }

    let default_address = owner.clone();
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(default_address),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    let data = pos::Redelegation {
        src_validator,
        dest_validator,
        owner,
        amount: *redel_amount,
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit transaction to withdraw an unbond
pub async fn build_withdraw(
    context: &impl Namada,
    args::Withdraw {
        tx: tx_args,
        validator,
        source,
        tx_code_path,
    }: &args::Withdraw,
) -> Result<(Tx, SigningTxData)> {
    let default_address = source.clone().unwrap_or(validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(default_address),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    let epoch = rpc::query_epoch(context.client()).await?;

    // Check that the validator address is actually a validator
    let validator =
        known_validator_or_err(validator.clone(), tx_args.force, context)
            .await?;

    // Check that the source address exists on chain
    let source = match source.clone() {
        Some(source) => source_exists_or_err(source, tx_args.force, context)
            .await
            .map(Some),
        None => Ok(source.clone()),
    }?;

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let tokens = rpc::query_withdrawable_tokens(
        context.client(),
        &bond_source,
        &validator,
        Some(epoch),
    )
    .await?;

    if tokens.is_zero() {
        edisplay_line!(
            context.io(),
            "There are no unbonded bonds ready to withdraw in the current \
             epoch {}.",
            epoch
        );
        rpc::query_and_print_unbonds(context, &bond_source, &validator).await?;
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::NoUnbondReady(epoch)));
        }
    } else {
        display_line!(
            context.io(),
            "Found {} tokens that can be withdrawn.",
            tokens.to_string_native()
        );
        display_line!(
            context.io(),
            "Submitting transaction to withdraw them..."
        );
    }

    let data = pos::Withdraw { validator, source };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit transaction to withdraw an unbond
pub async fn build_claim_rewards(
    context: &impl Namada,
    args::ClaimRewards {
        tx: tx_args,
        validator,
        source,
        tx_code_path,
    }: &args::ClaimRewards,
) -> Result<(Tx, SigningTxData)> {
    let default_address = source.clone().unwrap_or(validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(default_address),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    // Check that the validator address is actually a validator
    let validator =
        known_validator_or_err(validator.clone(), tx_args.force, context)
            .await?;

    // Check that the source address exists on chain
    let source = match source.clone() {
        Some(source) => source_exists_or_err(source, tx_args.force, context)
            .await
            .map(Some),
        None => Ok(source.clone()),
    }?;

    let data = pos::ClaimRewards { validator, source };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit a transaction to unbond
pub async fn build_unbond(
    context: &impl Namada,
    args::Unbond {
        tx: tx_args,
        validator,
        amount,
        source,
        tx_code_path,
    }: &args::Unbond,
) -> Result<(Tx, SigningTxData, Option<(Epoch, token::Amount)>)> {
    // Require a positive amount of tokens to be bonded
    if amount.is_zero() {
        edisplay_line!(
            context.io(),
            "The requested bond amount is 0. A positive amount must be \
             requested."
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::BondIsZero));
        }
    }

    // The validator must actually be a validator
    let validator =
        known_validator_or_err(validator.clone(), tx_args.force, context)
            .await?;

    // Check that the source address exists on chain
    let source = match source.clone() {
        Some(source) => source_exists_or_err(source, tx_args.force, context)
            .await
            .map(Some),
        None => Ok(source.clone()),
    }?;

    // Check that the validator is not frozen due to slashes
    let last_slash_epoch =
        rpc::query_last_infraction_epoch(context.client(), &validator).await?;
    if let Some(infraction_epoch) = last_slash_epoch {
        let params = rpc::get_pos_params(context.client()).await?;
        let current_epoch = rpc::query_epoch(context.client()).await?;

        let eligible_epoch = infraction_epoch
            .unchecked_add(params.slash_processing_epoch_offset());
        if current_epoch < eligible_epoch {
            edisplay_line!(
                context.io(),
                "The validator {} is currently frozen due to an infraction in \
                 epoch {}. Unbonds can be processed starting at epoch {}.",
                &validator,
                infraction_epoch,
                eligible_epoch
            );
            if !tx_args.force {
                return Err(Error::from(TxSubmitError::ValidatorFrozen(
                    validator.clone(),
                )));
            }
        }
    }

    let default_address = source.clone().unwrap_or(validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(default_address),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());

    let bond_amount =
        rpc::query_bond(context.client(), &bond_source, &validator, None)
            .await?;
    display_line!(
        context.io(),
        "Bond amount available for unbonding: {} NAM",
        bond_amount.to_string_native()
    );

    if *amount > bond_amount {
        edisplay_line!(
            context.io(),
            "The total bonds of the source {} is lower than the amount to be \
             unbonded. Amount to unbond is {} and the total bonds is {}.",
            bond_source,
            amount.to_string_native(),
            bond_amount.to_string_native(),
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::LowerBondThanUnbond(
                bond_source,
                amount.to_string_native(),
                bond_amount.to_string_native(),
            )));
        }
    }

    // Query the unbonds before submitting the tx
    let unbonds = rpc::query_unbond_with_slashing(
        context.client(),
        &bond_source,
        &validator,
    )
    .await?;
    let mut withdrawable = BTreeMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        let to_withdraw = withdrawable.entry(withdraw_epoch).or_default();
        *to_withdraw = checked!(to_withdraw + amount)?;
    }
    let latest_withdrawal_pre = withdrawable.into_iter().last();

    let data = pos::Unbond {
        validator: validator.clone(),
        amount: *amount,
        source: source.clone(),
    };

    let tx = build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await?;
    Ok((tx, signing_data, latest_withdrawal_pre))
}

/// Query the unbonds post-tx
pub async fn query_unbonds(
    context: &impl Namada,
    args: args::Unbond,
    latest_withdrawal_pre: Option<(Epoch, token::Amount)>,
) -> Result<()> {
    let source = args.source.clone();
    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| args.validator.clone());

    // Query the unbonds post-tx
    let unbonds = rpc::query_unbond_with_slashing(
        context.client(),
        &bond_source,
        &args.validator,
    )
    .await?;
    let mut withdrawable = BTreeMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        let to_withdraw = withdrawable.entry(withdraw_epoch).or_default();
        *to_withdraw = checked!(to_withdraw + amount)?;
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
                    edisplay_line!(
                        context.io(),
                        "Unexpected behavior reading the unbonds data has \
                         occurred"
                    );
                } else {
                    return Err(Error::from(TxSubmitError::UnbondError));
                }
            }
            std::cmp::Ordering::Equal => {
                display_line!(
                    context.io(),
                    "Amount {} withdrawable starting from epoch {}",
                    checked!(
                        latest_withdraw_amount_post
                            - latest_withdraw_amount_pre
                    )?
                    .to_string_native(),
                    latest_withdraw_epoch_post
                );
            }
            std::cmp::Ordering::Greater => {
                display_line!(
                    context.io(),
                    "Amount {} withdrawable starting from epoch {}",
                    latest_withdraw_amount_post.to_string_native(),
                    latest_withdraw_epoch_post,
                );
            }
        }
    } else {
        display_line!(
            context.io(),
            "Amount {} withdrawable starting from epoch {}",
            latest_withdraw_amount_post.to_string_native(),
            latest_withdraw_epoch_post,
        );
    }
    Ok(())
}

/// Submit a transaction to bond
pub async fn build_bond(
    context: &impl Namada,
    args::Bond {
        tx: tx_args,
        validator,
        amount,
        source,
        tx_code_path,
    }: &args::Bond,
) -> Result<(Tx, SigningTxData)> {
    // Require a positive amount of tokens to be bonded
    if amount.is_zero() {
        edisplay_line!(
            context.io(),
            "The requested bond amount is 0. A positive amount must be \
             requested."
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::BondIsZero));
        }
    }

    // The validator must actually be a validator
    let validator =
        known_validator_or_err(validator.clone(), tx_args.force, context)
            .await?;

    // Check that the source address exists on chain
    let mut is_src_also_val = false;
    let source = match source.clone() {
        Some(source) => {
            is_src_also_val =
                rpc::is_validator(context.client(), &source).await?;
            source_exists_or_err(source, tx_args.force, context)
                .await
                .map(Some)
        }
        None => Ok(source.clone()),
    }?;

    // Check that the source is not a different validator bonding to validator
    if is_src_also_val && source != Some(validator.clone()) {
        edisplay_line!(
            context.io(),
            "The given source address {} is a validator. A validator is \
             prohibited from bonding to another validator.",
            &source.clone().unwrap()
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::InvalidBondPair(
                source.clone().unwrap(),
                validator.clone(),
            )));
        }
    }

    // Give a bonding warning based on the pipeline state
    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch.unchecked_add(params.pipeline_len);
    let (validator_state_at_pipeline, _) = rpc::get_validator_state(
        context.client(),
        &validator,
        Some(pipeline_epoch),
    )
    .await?;
    if validator_state_at_pipeline == Some(ValidatorState::Inactive) {
        edisplay_line!(
            context.io(),
            "WARNING: the given validator address {} is inactive at the \
             pipeline epoch {}. If you would still like to bond to the \
             inactive validator, use the --force option.",
            &validator,
            &pipeline_epoch
        );
        if !tx_args.force {
            return Err(Error::from(TxSubmitError::ValidatorInactive(
                validator.clone(),
                pipeline_epoch,
            )));
        }
    }

    let default_address = source.clone().unwrap_or(validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(default_address.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, updated_balance) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let native_token = context.native_token();
    let check_balance = if &updated_balance.source == bond_source
        && updated_balance.token == native_token
    {
        CheckBalance::Balance(updated_balance.post_balance)
    } else {
        CheckBalance::Query(balance_key(&native_token, bond_source))
    };
    check_balance_too_low_err(
        &native_token,
        bond_source,
        *amount,
        check_balance,
        tx_args.force,
        context,
    )
    .await?;

    let data = pos::Bond {
        validator,
        amount: *amount,
        source,
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Build a default proposal governance
pub async fn build_default_proposal(
    context: &impl Namada,
    args::InitProposal {
        tx,
        proposal_data: _,
        is_pgf_stewards: _,
        is_pgf_funding: _,
        tx_code_path,
    }: &args::InitProposal,
    proposal: DefaultProposal,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(proposal.proposal.author.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx,
        Some(proposal.proposal.author.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _updated_balance) =
        validate_transparent_fee(context, tx, &signing_data.fee_payer).await?;

    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxSubmitError::InvalidProposal(e.to_string()))?;

    let push_data =
        |tx_builder: &mut Tx, init_proposal_data: &mut InitProposalData| {
            let (_, extra_section_hash) = tx_builder
                .add_extra_section(proposal_to_vec(proposal.proposal)?, None);
            init_proposal_data.content = extra_section_hash;

            if let Some(init_proposal_code) = proposal.data {
                let (_, extra_section_hash) =
                    tx_builder.add_extra_section(init_proposal_code, None);
                init_proposal_data.r#type =
                    ProposalType::DefaultWithWasm(extra_section_hash);
            };
            Ok(())
        };
    build(
        context,
        tx,
        tx_code_path.clone(),
        init_proposal_data,
        push_data,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Build a proposal vote
pub async fn build_vote_proposal(
    context: &impl Namada,
    args::VoteProposal {
        tx,
        proposal_id,
        vote,
        voter_address,
        tx_code_path,
    }: &args::VoteProposal,
    current_epoch: Epoch,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(voter_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx,
        default_signer.clone(),
        default_signer.clone(),
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx, &signing_data.fee_payer).await?;

    let proposal_vote = ProposalVote::try_from(vote.clone())
        .map_err(|_| TxSubmitError::InvalidProposalVote)?;

    let proposal = if let Some(proposal) =
        rpc::query_proposal_by_id(context.client(), *proposal_id).await?
    {
        proposal
    } else {
        return Err(Error::from(TxSubmitError::ProposalDoesNotExist(
            *proposal_id,
        )));
    };

    let is_validator =
        rpc::is_validator(context.client(), voter_address).await?;

    // Check if the voting period is still valid for the voter
    if !proposal.can_be_voted(current_epoch, is_validator) {
        edisplay_line!(
            context.io(),
            "Proposal {} cannot be voted on, either the voting period ended \
             or the proposal is still pending.",
            proposal_id
        );
        if is_validator {
            edisplay_line!(
                context.io(),
                "NB: voter address {} is a validator, and validators can only \
                 vote on proposals within the first 2/3 of the voting period. \
                 The voting period specifically for validators has ended.",
                voter_address
            );
        }
        if !tx.force {
            return Err(Error::from(
                TxSubmitError::InvalidProposalVotingPeriod(*proposal_id),
            ));
        }
    }

    if is_validator {
        // Prevent a validator voter from voting if they are jailed or inactive
        // right now
        let state = rpc::get_validator_state(
            context.client(),
            voter_address,
            Some(current_epoch),
        )
        .await?
        .0
        .expect("Expected to find the state of the validator");

        if matches!(state, ValidatorState::Jailed | ValidatorState::Inactive) {
            edisplay_line!(
                context.io(),
                "The voter {} is a validator who is currently jailed or \
                 inactive. Thus, this address is prohibited from voting in \
                 governance right now. Please try again when not jailed or \
                 inactive.",
                voter_address
            );
            if !tx.force {
                return Err(Error::from(
                    TxSubmitError::CannotVoteInGovernance(
                        voter_address.clone(),
                        current_epoch,
                    ),
                ));
            }
        }

        let stake =
            get_validator_stake(context.client(), current_epoch, voter_address)
                .await?;

        if stake.is_zero() {
            edisplay_line!(
                context.io(),
                "Voter address {voter_address} is a validator but has no \
                 stake, so it has no votes.",
            );
            if !tx.force {
                return Err(Error::Other(
                    "Voter address must have delegations".to_string(),
                ));
            }
        }
    } else {
        // Check that there are delegations to vote with
        let delegation_validators = rpc::get_delegation_validators(
            context.client(),
            voter_address,
            current_epoch,
        )
        .await?;

        if delegation_validators.is_empty() {
            edisplay_line!(
                context.io(),
                "Voter address {voter_address} does not have any delegations.",
            );
            if !tx.force {
                return Err(Error::from(TxSubmitError::NoDelegationsFound(
                    voter_address.clone(),
                    current_epoch,
                )));
            }
        }
    };

    let data = VoteProposalData {
        id: *proposal_id,
        vote: proposal_vote,
        voter: voter_address.clone(),
    };

    build(
        context,
        tx,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Build a pgf funding proposal governance
pub async fn build_become_validator(
    context: &impl Namada,
    args::TxBecomeValidator {
        tx: tx_args,
        address,
        scheme: _,
        consensus_key,
        eth_cold_key,
        eth_hot_key,
        protocol_key,
        commission_rate,
        max_commission_rate_change,
        email,
        website,
        description,
        discord_handle,
        avatar,
        name,
        unsafe_dont_encrypt: _,
        tx_code_path,
    }: &args::TxBecomeValidator,
) -> Result<(Tx, SigningTxData)> {
    // Check that the address is established
    if !address.is_established() {
        edisplay_line!(
            context.io(),
            "The given address {address} is not established. Only an \
             established address can become a validator.",
        );
        if !tx_args.force {
            return Err(Error::Other(
                "The given address must be enstablished".to_string(),
            ));
        }
    };

    // Check that the address is not already a validator
    if rpc::is_validator(context.client(), address).await? {
        edisplay_line!(
            context.io(),
            "The given address {address} is already a validator",
        );
        if !tx_args.force {
            return Err(Error::Other(
                "The given address must not be a validator already".to_string(),
            ));
        }
    };

    // If the address is not yet a validator, it cannot have self-bonds, but it
    // may have delegations. It has to unbond those before it can become a
    // validator.
    if rpc::has_bonds(context.client(), address).await? {
        edisplay_line!(
            context.io(),
            "The given address {address} has delegations and therefore cannot \
             become a validator. To become a validator, you have to unbond \
             your delegations first.",
        );
        if !tx_args.force {
            return Err(Error::Other(
                "The given address must not have delegations".to_string(),
            ));
        }
    }

    // Validate the commission rate data
    if *commission_rate > Dec::one() || *commission_rate < Dec::zero() {
        edisplay_line!(
            context.io(),
            "The validator commission rate must not exceed 1.0 or 100%, and \
             it must be 0 or positive."
        );
        if !tx_args.force {
            return Err(Error::Other(
                "Invalid validator commission rate".to_string(),
            ));
        }
    }

    if *max_commission_rate_change > Dec::one()
        || *max_commission_rate_change < Dec::zero()
    {
        edisplay_line!(
            context.io(),
            "The validator maximum change in commission rate per epoch must \
             not exceed 1.0 or 100%, and it must be 0 or positive."
        );
        if !tx_args.force {
            return Err(Error::Other(
                "Invalid validator maximum change".to_string(),
            ));
        }
    }

    // Validate the email
    if email.is_empty() {
        edisplay_line!(
            context.io(),
            "The validator email must not be an empty string."
        );
        if !tx_args.force {
            return Err(Error::Other(
                "Validator email must not be empty".to_string(),
            ));
        }
    }

    // check that all keys have been supplied correctly
    if [
        consensus_key.clone(),
        eth_cold_key.clone(),
        eth_hot_key.clone(),
        protocol_key.clone(),
    ]
    .iter()
    .any(|key| key.is_none())
    {
        edisplay_line!(
            context.io(),
            "All validator keys must be supplied to create a validator."
        );
        return Err(Error::Other("Validator key must be present".to_string()));
    }

    let data = BecomeValidator {
        address: address.clone(),
        consensus_key: consensus_key.clone().unwrap(),
        eth_cold_key: key::secp256k1::PublicKey::try_from_pk(
            &eth_cold_key.clone().unwrap(),
        )
        .unwrap(),
        eth_hot_key: key::secp256k1::PublicKey::try_from_pk(
            &eth_hot_key.clone().unwrap(),
        )
        .unwrap(),
        protocol_key: protocol_key.clone().unwrap(),
        commission_rate: *commission_rate,
        max_commission_rate_change: *max_commission_rate_change,
        email: email.to_owned(),
        description: description.clone(),
        website: website.clone(),
        discord_handle: discord_handle.clone(),
        avatar: avatar.clone(),
        name: name.clone(),
    };

    // Put together all the PKs that we have to sign with to verify ownership
    let account = if let Some(account) =
        rpc::get_account_info(context.client(), address).await?
    {
        account
    } else {
        edisplay_line!(
            context.io(),
            "Unable to query account keys for address {address}."
        );
        return Err(Error::Other("Invalid address".to_string()));
    };

    let mut all_pks = account.get_all_public_keys();
    all_pks.push(consensus_key.clone().unwrap().clone());
    all_pks.push(eth_cold_key.clone().unwrap());
    all_pks.push(eth_hot_key.clone().unwrap());
    all_pks.push(protocol_key.clone().unwrap().clone());

    let signing_data =
        signing::aux_signing_data(context, tx_args, None, None, all_pks, false)
            .await?;

    let (fee_amount, _updated_balance) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Build a pgf funding proposal governance
pub async fn build_pgf_funding_proposal(
    context: &impl Namada,
    args::InitProposal {
        tx,
        proposal_data: _,
        is_pgf_stewards: _,
        is_pgf_funding: _,
        tx_code_path,
    }: &args::InitProposal,
    proposal: PgfFundingProposal,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(proposal.proposal.author.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx,
        Some(proposal.proposal.author.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _updated_balance) =
        validate_transparent_fee(context, tx, &signing_data.fee_payer).await?;

    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxSubmitError::InvalidProposal(e.to_string()))?;

    let add_section = |tx: &mut Tx, data: &mut InitProposalData| {
        let (_, extra_section_hash) =
            tx.add_extra_section(proposal_to_vec(proposal.proposal)?, None);
        data.content = extra_section_hash;
        Ok(())
    };
    build(
        context,
        tx,
        tx_code_path.clone(),
        init_proposal_data,
        add_section,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Build a pgf funding proposal governance
pub async fn build_pgf_stewards_proposal(
    context: &impl Namada,
    args::InitProposal {
        tx,
        proposal_data: _,
        is_pgf_stewards: _,
        is_pgf_funding: _,
        tx_code_path,
    }: &args::InitProposal,
    proposal: PgfStewardProposal,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(proposal.proposal.author.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx,
        Some(proposal.proposal.author.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _updated_balance) =
        validate_transparent_fee(context, tx, &signing_data.fee_payer).await?;

    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxSubmitError::InvalidProposal(e.to_string()))?;

    let add_section = |tx: &mut Tx, data: &mut InitProposalData| {
        let (_, extra_section_hash) =
            tx.add_extra_section(proposal_to_vec(proposal.proposal)?, None);
        data.content = extra_section_hash;
        Ok(())
    };

    build(
        context,
        tx,
        tx_code_path.clone(),
        init_proposal_data,
        add_section,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit an IBC transfer
pub async fn build_ibc_transfer(
    context: &impl Namada,
    args: &args::TxIbcTransfer,
) -> Result<(Tx, SigningTxData, Option<MaspEpoch>)> {
    if args.ibc_shielding_data.is_some() && args.ibc_memo.is_some() {
        return Err(Error::Other(
            "The memo field of the IBC packet can't be used for both \
             shielding transfer and another purpose at the same time"
                .to_string(),
        ));
    }

    let refund_target =
        get_refund_target(context, &args.source, &args.refund_target).await?;

    let source = args.source.effective_address();
    let signing_data = signing::aux_signing_data(
        context,
        &args.tx,
        Some(source.clone()),
        Some(source.clone()),
        vec![],
        args.disposable_signing_key,
    )
    .await?;
    let (fee_per_gas_unit, updated_balance) =
        if let TransferSource::ExtendedSpendingKey(_) = args.source {
            // MASP fee payment
            (validate_fee(context, &args.tx).await?, None)
        } else {
            // Transparent fee payment
            validate_transparent_fee(context, &args.tx, &signing_data.fee_payer)
                .await
                .map(|(fee_amount, updated_balance)| {
                    (fee_amount, Some(updated_balance))
                })?
        };

    // Check that the source address exists on chain
    let source =
        source_exists_or_err(source.clone(), args.tx.force, context).await?;
    // We cannot check the receiver

    // validate the amount given
    let validated_amount =
        validate_amount(context, args.amount, &args.token, args.tx.force)
            .await
            .expect("expected to validate amount");

    // If source is transparent check the balance (MASP balance is checked when
    // constructing the shielded part)
    if let Some(updated_balance) = updated_balance {
        let check_balance = if updated_balance.source == source
            && updated_balance.token == args.token
        {
            CheckBalance::Balance(updated_balance.post_balance)
        } else {
            CheckBalance::Query(balance_key(&args.token, &source))
        };

        check_balance_too_low_err(
            &args.token,
            &source,
            validated_amount.amount(),
            check_balance,
            args.tx.force,
            context,
        )
        .await?;
    }

    let tx_code_hash =
        query_wasm_code_hash(context, args.tx_code_path.to_str().unwrap())
            .await
            .map_err(|e| Error::from(QueryError::Wasm(e.to_string())))?;
    let masp_transfer_data = vec![MaspTransferData {
        source: args.source.clone(),
        // The token will be escrowed to IBC address
        target: TransferTarget::Ibc(args.receiver.clone()),
        token: args.token.clone(),
        amount: validated_amount,
    }];

    let mut transfer = token::Transfer::default();

    // Add masp fee payment if necessary
    let masp_fee_data = get_masp_fee_payment_amount(
        context,
        &args.tx,
        fee_per_gas_unit,
        &signing_data.fee_payer,
        args.gas_spending_keys.clone(),
    )
    .await?;
    if let Some(fee_data) = &masp_fee_data {
        transfer = transfer
            .transfer(
                MASP,
                fee_data.target.to_owned(),
                fee_data.token.to_owned(),
                fee_data.amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))?;
    }

    // For transfer from a spending key
    let shielded_parts = construct_shielded_parts(
        context,
        masp_transfer_data,
        masp_fee_data,
        !(args.tx.dry_run || args.tx.dry_run_wrapper),
        args.tx.expiration.to_datetime(),
    )
    .await?;
    let shielded_tx_epoch = shielded_parts.as_ref().map(|trans| trans.0.epoch);

    // this height should be that of the destination chain, not this chain
    let timeout_height = match args.timeout_height {
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
    > = {
        #[allow(clippy::disallowed_methods)]
        DateTimeUtc::now()
    }
    .try_into();
    let now = now.map_err(|e| Error::Other(e.to_string()))?;
    let now: IbcTimestamp = now.try_into().map_err(|e| {
        Error::Other(format!("Timestamp conversion failed: {e}"))
    })?;
    let timeout_timestamp = if let Some(offset) = args.timeout_sec_offset {
        let timestamp = (now + Duration::new(offset, 0))
            .map_err(|e| Error::Other(e.to_string()))?;
        TimeoutTimestamp::At(timestamp)
    } else if timeout_height == TimeoutHeight::Never {
        // we cannot set 0 to both the height and the timestamp
        let timestamp = (now + Duration::new(3600, 0))
            .map_err(|e| Error::Other(e.to_string()))?;
        TimeoutTimestamp::At(timestamp)
    } else {
        TimeoutTimestamp::Never
    };

    let chain_id = args.tx.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, args.tx.expiration.to_datetime());
    if let Some(memo) = &args.tx.memo {
        tx.add_memo(memo);
    }

    let transfer = shielded_parts
        .map(|(shielded_transfer, asset_types)| {
            let masp_tx_hash =
                tx.add_masp_tx_section(shielded_transfer.masp_tx.clone()).1;
            transfer.shielded_section_hash = Some(masp_tx_hash);
            tx.add_masp_builder(MaspBuilder {
                asset_types,
                metadata: shielded_transfer.metadata,
                builder: shielded_transfer.builder,
                target: masp_tx_hash,
            });
            Result::Ok(transfer)
        })
        .transpose()?;

    // Check the token and make the tx data
    let ibc_denom =
        rpc::query_ibc_denom(context, &args.token.to_string(), Some(&source))
            .await;
    // The refund target should be given or created if the source is shielded.
    // Otherwise, the refund target should be None.
    assert!(
        (args.source.spending_key().is_some() && refund_target.is_some())
            || (args.source.address().is_some() && refund_target.is_none())
    );
    // The memo is either IbcShieldingData or just a memo
    let memo = args
        .ibc_shielding_data
        .as_ref()
        .map_or(args.ibc_memo.clone(), |shielding_data| {
            Some(shielding_data.clone().into())
        });
    // If the refund address is given, set the refund address. It is used only
    // when refunding and won't affect the actual transfer because the actual
    // source will be the MASP address and the MASP transaction is generated by
    // the shielded source address.
    let sender = refund_target
        .map(|t| t.to_string())
        .unwrap_or(source.to_string())
        .into();
    let data = if args.port_id == PortId::transfer() {
        let token = PrefixedCoin {
            denom: ibc_denom
                .parse()
                .map_err(|e| Error::Other(format!("Invalid IBC denom: {e}")))?,
            // Set the IBC amount as an integer
            amount: validated_amount.into(),
        };
        let packet_data = PacketData {
            token,
            sender,
            receiver: args.receiver.clone().into(),
            memo: memo.unwrap_or_default().into(),
        };
        let message = IbcMsgTransfer {
            port_id_on_a: args.port_id.clone(),
            chan_id_on_a: args.channel_id.clone(),
            packet_data,
            timeout_height_on_b: timeout_height,
            timeout_timestamp_on_b: timeout_timestamp,
        };
        MsgTransfer { message, transfer }.serialize_to_vec()
    } else if let Some((trace_path, base_class_id, token_id)) =
        is_nft_trace(&ibc_denom)
    {
        let class_id = PrefixedClassId {
            trace_path,
            base_class_id: base_class_id.parse().map_err(|_| {
                Error::Other(format!("Invalid class ID: {base_class_id}"))
            })?,
        };
        let token_ids = vec![token_id.clone()].try_into().map_err(|_| {
            Error::Other(format!("Invalid token ID: {token_id}"))
        })?;
        let packet_data = NftPacketData {
            class_id,
            class_uri: None,
            class_data: None,
            token_ids,
            token_uris: None,
            token_data: None,
            sender,
            receiver: args.receiver.clone().into(),
            memo: memo.map(|s| s.into()),
        };
        let message = IbcMsgNftTransfer {
            port_id_on_a: args.port_id.clone(),
            chan_id_on_a: args.channel_id.clone(),
            packet_data,
            timeout_height_on_b: timeout_height,
            timeout_timestamp_on_b: timeout_timestamp,
        };
        MsgNftTransfer { message, transfer }.serialize_to_vec()
    } else {
        return Err(Error::Other(format!("Invalid IBC denom: {ibc_denom}")));
    };

    tx.add_code_from_hash(
        tx_code_hash,
        Some(args.tx_code_path.to_string_lossy().into_owned()),
    )
    .add_serialized_data(data);

    prepare_tx(
        &args.tx,
        &mut tx,
        fee_per_gas_unit,
        signing_data.fee_payer.clone(),
    )
    .await?;

    Ok((tx, signing_data, shielded_tx_epoch))
}

/// Abstraction for helping build transactions
#[allow(clippy::too_many_arguments)]
async fn build<F, D>(
    context: &impl Namada,
    tx_args: &crate::args::Tx,
    path: PathBuf,
    mut data: D,
    on_tx: F,
    fee_amount: DenominatedAmount,
    gas_payer: &common::PublicKey,
) -> Result<Tx>
where
    F: FnOnce(&mut Tx, &mut D) -> Result<()>,
    D: BorshSerialize,
{
    let chain_id = tx_args.chain_id.clone().unwrap();

    let mut tx_builder = Tx::new(chain_id, tx_args.expiration.to_datetime());
    if let Some(memo) = &tx_args.memo {
        tx_builder.add_memo(memo);
    }

    let tx_code_hash = query_wasm_code_hash(context, path.to_string_lossy())
        .await
        .map_err(|e| Error::from(QueryError::Wasm(e.to_string())))?;

    on_tx(&mut tx_builder, &mut data)?;

    tx_builder
        .add_code_from_hash(
            tx_code_hash,
            Some(path.to_string_lossy().into_owned()),
        )
        .add_data(data);

    prepare_tx(tx_args, &mut tx_builder, fee_amount, gas_payer.clone()).await?;
    Ok(tx_builder)
}

/// Try to decode the given asset type and add its decoding to the supplied set.
/// Returns true only if a new decoding has been added to the given set.
async fn add_asset_type(
    asset_types: &mut HashSet<AssetData>,
    context: &impl Namada,
    asset_type: AssetType,
) -> bool {
    if let Some(asset_type) = context
        .shielded_mut()
        .await
        .decode_asset_type(context.client(), asset_type)
        .await
    {
        asset_types.insert(asset_type)
    } else {
        false
    }
}

/// Collect the asset types used in the given Builder and decode them. This
/// function provides the data necessary for offline wallets to present asset
/// type information.
async fn used_asset_types<P, K, N>(
    context: &impl Namada,
    builder: &Builder<P, K, N>,
) -> std::result::Result<HashSet<AssetData>, RpcError> {
    let mut asset_types = HashSet::new();
    // Collect all the asset types used in the Sapling inputs
    for input in builder.sapling_inputs() {
        add_asset_type(&mut asset_types, context, input.asset_type()).await;
    }
    // Collect all the asset types used in the transparent inputs
    for input in builder.transparent_inputs() {
        add_asset_type(&mut asset_types, context, input.coin().asset_type())
            .await;
    }
    // Collect all the asset types used in the Sapling outputs
    for output in builder.sapling_outputs() {
        add_asset_type(&mut asset_types, context, output.asset_type()).await;
    }
    // Collect all the asset types used in the transparent outputs
    for output in builder.transparent_outputs() {
        add_asset_type(&mut asset_types, context, output.asset_type()).await;
    }
    // Collect all the asset types used in the Sapling converts
    for output in builder.sapling_converts() {
        for (asset_type, _) in
            I128Sum::from(output.conversion().clone()).components()
        {
            add_asset_type(&mut asset_types, context, *asset_type).await;
        }
    }
    Ok(asset_types)
}

/// Constructs the batched tx from the provided list. Returns also the data for
/// signing
pub fn build_batch(
    mut txs: Vec<(Tx, SigningTxData)>,
) -> Result<(Tx, Vec<SigningTxData>)> {
    if txs.is_empty() {
        return Err(Error::Other(
            "No transactions provided for the batch".to_string(),
        ));
    }
    let (mut batched_tx, sig_data) = txs.remove(0);
    let mut signing_data = vec![sig_data];

    for (tx, sig_data) in txs {
        if tx.commitments().len() != 1 {
            return Err(Error::Other(format!(
                "Inner tx did not contain exactly one transaction, \
                 transaction length: {}",
                tx.commitments().len()
            )));
        }

        let cmt = tx.first_commitments().unwrap().to_owned();
        if !batched_tx.add_inner_tx(tx, cmt.clone()) {
            return Err(Error::Other(format!(
                "The transaction batch already contains inner tx: {}",
                cmt.get_hash()
            )));
        }
        // Avoid redundant signing data
        if !signing_data.iter().any(|sig| sig == &sig_data) {
            signing_data.push(sig_data);
        }
    }

    Ok((batched_tx, signing_data))
}

/// Build a transparent transfer
pub async fn build_transparent_transfer<N: Namada>(
    context: &N,
    args: &mut args::TxTransparentTransfer,
) -> Result<(Tx, SigningTxData)> {
    let mut transfers = token::Transfer::default();

    // Evaluate signer and fees
    let (signing_data, fee_amount, updated_balance) = {
        let source = if args.data.len() == 1 {
            // If only one transfer take its source as the signer
            args.data
                .first()
                .map(|transfer_data| transfer_data.source.clone())
        } else {
            // Otherwise the caller is required to pass the public keys in the
            // argument
            None
        };

        let signing_data = signing::aux_signing_data(
            context,
            &args.tx,
            source.clone(),
            source,
            vec![],
            false,
        )
        .await?;

        // Transparent fee payment
        let (fee_amount, updated_balance) = validate_transparent_fee(
            context,
            &args.tx,
            &signing_data.fee_payer,
        )
        .await
        .map(|(fee_amount, updated_balance)| {
            (fee_amount, Some(updated_balance))
        })?;

        (signing_data, fee_amount, updated_balance)
    };

    for TxTransparentTransferData {
        source,
        target,
        token,
        amount,
    } in &args.data
    {
        // Check that the source address exists on chain
        source_exists_or_err(source.clone(), args.tx.force, context).await?;
        // Check that the target address exists on chain
        target_exists_or_err(target.clone(), args.tx.force, context).await?;

        // Validate the amount given
        let validated_amount =
            validate_amount(context, amount.to_owned(), token, args.tx.force)
                .await?;

        // Check the balance of the source
        if let Some(updated_balance) = &updated_balance {
            let check_balance = if &updated_balance.source == source
                && &updated_balance.token == token
            {
                CheckBalance::Balance(updated_balance.post_balance)
            } else {
                CheckBalance::Query(balance_key(token, source))
            };

            check_balance_too_low_err(
                token,
                source,
                validated_amount.amount(),
                check_balance,
                args.tx.force,
                context,
            )
            .await?;
        }

        // Construct the corresponding transparent Transfer object
        transfers = transfers
            .transfer(
                source.to_owned(),
                target.to_owned(),
                token.to_owned(),
                validated_amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))?;
    }

    let tx = build(
        context,
        &args.tx,
        args.tx_code_path.clone(),
        transfers,
        do_nothing,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await?;
    Ok((tx, signing_data))
}

/// Build a shielded transfer
pub async fn build_shielded_transfer<N: Namada>(
    context: &N,
    args: &mut args::TxShieldedTransfer,
) -> Result<(Tx, SigningTxData)> {
    let signing_data = signing::aux_signing_data(
        context,
        &args.tx,
        Some(MASP),
        Some(MASP),
        vec![],
        args.disposable_signing_key,
    )
    .await?;

    // Shielded fee payment
    let fee_per_gas_unit = validate_fee(context, &args.tx).await?;

    let mut transfer_data = vec![];
    for TxShieldedTransferData {
        source,
        target,
        token,
        amount,
    } in &args.data
    {
        // Validate the amount given
        let validated_amount =
            validate_amount(context, amount.to_owned(), token, args.tx.force)
                .await?;

        transfer_data.push(MaspTransferData {
            source: TransferSource::ExtendedSpendingKey(source.to_owned()),
            target: TransferTarget::PaymentAddress(target.to_owned()),
            token: token.to_owned(),
            amount: validated_amount,
        });
    }

    // Construct the tx data with a placeholder shielded section hash
    let mut data = token::Transfer::default();

    // Add masp fee payment if necessary
    let masp_fee_data = get_masp_fee_payment_amount(
        context,
        &args.tx,
        fee_per_gas_unit,
        &signing_data.fee_payer,
        args.gas_spending_keys.clone(),
    )
    .await?;
    if let Some(fee_data) = &masp_fee_data {
        data = data
            .transfer(
                MASP,
                fee_data.target.to_owned(),
                fee_data.token.to_owned(),
                fee_data.amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))?;
    }

    let shielded_parts = construct_shielded_parts(
        context,
        transfer_data,
        masp_fee_data,
        !(args.tx.dry_run || args.tx.dry_run_wrapper),
        args.tx.expiration.to_datetime(),
    )
    .await?
    .expect("Shielded transfer must have shielded parts");

    let add_shielded_parts = |tx: &mut Tx, data: &mut token::Transfer| {
        // Add the MASP Transaction and its Builder to facilitate validation
        let (
            ShieldedTransfer {
                builder,
                masp_tx,
                metadata,
                epoch: _,
            },
            asset_types,
        ) = shielded_parts;
        // Add a MASP Transaction section to the Tx and get the tx hash
        let section_hash = tx.add_masp_tx_section(masp_tx).1;

        tx.add_masp_builder(MaspBuilder {
            asset_types,
            // Store how the Info objects map to Descriptors/Outputs
            metadata,
            // Store the data that was used to construct the Transaction
            builder,
            // Link the Builder to the Transaction by hash code
            target: section_hash,
        });

        data.shielded_section_hash = Some(section_hash);
        tracing::debug!("Transfer data {data:?}");
        Ok(())
    };

    let tx = build(
        context,
        &args.tx,
        args.tx_code_path.clone(),
        data,
        add_shielded_parts,
        fee_per_gas_unit,
        &signing_data.fee_payer,
    )
    .await?;
    Ok((tx, signing_data))
}

// Check if the transaction will need to pay fees via the masp and extract the
// right masp data
async fn get_masp_fee_payment_amount<N: Namada>(
    context: &N,
    args: &args::Tx<SdkTypes>,
    fee_amount: DenominatedAmount,
    fee_payer: &common::PublicKey,
    gas_spending_keys: Vec<ExtendedSpendingKey>,
) -> Result<Option<MaspFeeData>> {
    let fee_payer_address = Address::from(fee_payer);
    let balance_key = balance_key(&args.fee_token, &fee_payer_address);
    #[allow(clippy::disallowed_methods)]
    let balance = rpc::query_storage_value::<_, token::Amount>(
        context.client(),
        &balance_key,
    )
    .await
    .unwrap_or_default();
    let total_fee = checked!(fee_amount.amount() * u64::from(args.gas_limit))?;

    Ok(match total_fee.checked_sub(balance) {
        Some(diff) if !diff.is_zero() => Some(MaspFeeData {
            sources: gas_spending_keys,
            target: fee_payer_address,
            token: args.fee_token.clone(),
            amount: DenominatedAmount::new(diff, fee_amount.denom()),
        }),
        _ => None,
    })
}

/// Build a shielding transfer
pub async fn build_shielding_transfer<N: Namada>(
    context: &N,
    args: &mut args::TxShieldingTransfer,
) -> Result<(Tx, SigningTxData, MaspEpoch)> {
    let source = if args.data.len() == 1 {
        // If only one transfer take its source as the signer
        args.data
            .first()
            .map(|transfer_data| transfer_data.source.clone())
    } else {
        // Otherwise the caller is required to pass the public keys in the
        // argument
        None
    };
    let signing_data = signing::aux_signing_data(
        context,
        &args.tx,
        source.clone(),
        source,
        vec![],
        false,
    )
    .await?;

    // Transparent fee payment
    let (fee_amount, updated_balance) =
        validate_transparent_fee(context, &args.tx, &signing_data.fee_payer)
            .await
            .map(|(fee_amount, updated_balance)| {
                (fee_amount, Some(updated_balance))
            })?;

    let mut transfer_data = vec![];
    let mut data = token::Transfer::default();
    for TxShieldingTransferData {
        source,
        token,
        amount,
    } in &args.data
    {
        // Validate the amount given
        let validated_amount =
            validate_amount(context, amount.to_owned(), token, args.tx.force)
                .await?;

        // Check the balance of the source
        if let Some(updated_balance) = &updated_balance {
            let check_balance = if &updated_balance.source == source
                && &updated_balance.token == token
            {
                CheckBalance::Balance(updated_balance.post_balance)
            } else {
                CheckBalance::Query(balance_key(token, source))
            };

            check_balance_too_low_err(
                token,
                source,
                validated_amount.amount(),
                check_balance,
                args.tx.force,
                context,
            )
            .await?;
        }

        transfer_data.push(MaspTransferData {
            source: TransferSource::Address(source.to_owned()),
            target: TransferTarget::PaymentAddress(args.target),
            token: token.to_owned(),
            amount: validated_amount,
        });

        data = data
            .transfer(
                source.to_owned(),
                MASP,
                token.to_owned(),
                validated_amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))?;
    }

    let shielded_parts = construct_shielded_parts(
        context,
        transfer_data,
        None,
        !(args.tx.dry_run || args.tx.dry_run_wrapper),
        args.tx.expiration.to_datetime(),
    )
    .await?
    .expect("Shielding transfer must have shielded parts");
    let shielded_tx_epoch = shielded_parts.0.epoch;

    let add_shielded_parts = |tx: &mut Tx, data: &mut token::Transfer| {
        // Add the MASP Transaction and its Builder to facilitate validation
        let (
            ShieldedTransfer {
                builder,
                masp_tx,
                metadata,
                epoch: _,
            },
            asset_types,
        ) = shielded_parts;
        // Add a MASP Transaction section to the Tx and get the tx hash
        let shielded_section_hash = tx.add_masp_tx_section(masp_tx).1;

        tx.add_masp_builder(MaspBuilder {
            asset_types,
            // Store how the Info objects map to Descriptors/Outputs
            metadata,
            // Store the data that was used to construct the Transaction
            builder,
            // Link the Builder to the Transaction by hash code
            target: shielded_section_hash,
        });

        data.shielded_section_hash = Some(shielded_section_hash);
        tracing::debug!("Transfer data {data:?}");
        Ok(())
    };

    let tx = build(
        context,
        &args.tx,
        args.tx_code_path.clone(),
        data,
        add_shielded_parts,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await?;
    Ok((tx, signing_data, shielded_tx_epoch))
}

/// Build an unshielding transfer
pub async fn build_unshielding_transfer<N: Namada>(
    context: &N,
    args: &mut args::TxUnshieldingTransfer,
) -> Result<(Tx, SigningTxData)> {
    let signing_data = signing::aux_signing_data(
        context,
        &args.tx,
        Some(MASP),
        Some(MASP),
        vec![],
        args.disposable_signing_key,
    )
    .await?;

    // Shielded fee payment
    let fee_per_gas_unit = validate_fee(context, &args.tx).await?;

    let mut transfer_data = vec![];
    let mut data = token::Transfer::default();
    for TxUnshieldingTransferData {
        target,
        token,
        amount,
    } in &args.data
    {
        // Validate the amount given
        let validated_amount =
            validate_amount(context, amount.to_owned(), token, args.tx.force)
                .await?;

        transfer_data.push(MaspTransferData {
            source: TransferSource::ExtendedSpendingKey(args.source),
            target: TransferTarget::Address(target.to_owned()),
            token: token.to_owned(),
            amount: validated_amount,
        });

        data = data
            .transfer(
                MASP,
                target.to_owned(),
                token.to_owned(),
                validated_amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))?;
    }

    // Add masp fee payment if necessary
    let masp_fee_data = get_masp_fee_payment_amount(
        context,
        &args.tx,
        fee_per_gas_unit,
        &signing_data.fee_payer,
        args.gas_spending_keys.clone(),
    )
    .await?;
    if let Some(fee_data) = &masp_fee_data {
        // Add another unshield to the list
        data = data
            .transfer(
                MASP,
                fee_data.target.to_owned(),
                fee_data.token.to_owned(),
                fee_data.amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))?;
    }

    let shielded_parts = construct_shielded_parts(
        context,
        transfer_data,
        masp_fee_data,
        !(args.tx.dry_run || args.tx.dry_run_wrapper),
        args.tx.expiration.to_datetime(),
    )
    .await?
    .expect("Shielding transfer must have shielded parts");

    let add_shielded_parts = |tx: &mut Tx, data: &mut token::Transfer| {
        // Add the MASP Transaction and its Builder to facilitate validation
        let (
            ShieldedTransfer {
                builder,
                masp_tx,
                metadata,
                epoch: _,
            },
            asset_types,
        ) = shielded_parts;
        // Add a MASP Transaction section to the Tx and get the tx hash
        let shielded_section_hash = tx.add_masp_tx_section(masp_tx).1;

        tx.add_masp_builder(MaspBuilder {
            asset_types,
            // Store how the Info objects map to Descriptors/Outputs
            metadata,
            // Store the data that was used to construct the Transaction
            builder,
            // Link the Builder to the Transaction by hash code
            target: shielded_section_hash,
        });

        data.shielded_section_hash = Some(shielded_section_hash);
        tracing::debug!("Transfer data {data:?}");
        Ok(())
    };

    let tx = build(
        context,
        &args.tx,
        args.tx_code_path.clone(),
        data,
        add_shielded_parts,
        fee_per_gas_unit,
        &signing_data.fee_payer,
    )
    .await?;
    Ok((tx, signing_data))
}

// Construct the shielded part of the transaction, if any
async fn construct_shielded_parts<N: Namada>(
    context: &N,
    data: Vec<MaspTransferData>,
    fee_data: Option<MaspFeeData>,
    update_ctx: bool,
    expiration: Option<DateTimeUtc>,
) -> Result<Option<(ShieldedTransfer, HashSet<AssetData>)>> {
    // Precompute asset types to increase chances of success in decoding
    let token_map = context.wallet().await.get_addresses();
    let tokens = token_map.values().collect();

    let stx_result = {
        let mut shielded = context.shielded_mut().await;
        _ = shielded
            .precompute_asset_types(context.client(), tokens)
            .await;

        shielded
            .gen_shielded_transfer(
                context, data, fee_data, expiration, update_ctx,
            )
            .await
    };

    let shielded_parts = match stx_result {
        Ok(Some(stx)) => stx,
        Ok(None) => return Ok(None),
        Err(Build {
            error: builder::Error::InsufficientFunds(_),
            data,
        }) => {
            if let Some(MaspDataLog {
                source,
                token,
                amount,
            }) = data
            {
                if let Some(source) = source {
                    return Err(TxSubmitError::NegativeBalanceAfterTransfer(
                        Box::new(source.effective_address()),
                        amount.to_string(),
                        Box::new(token.clone()),
                    )
                    .into());
                }
                return Err(TxSubmitError::MaspError(format!(
                    "Insufficient funds: Could not collect enough funds to \
                     pay for fees: token {token}, amount: {amount}"
                ))
                .into());
            }
            return Err(TxSubmitError::MaspError(
                "Insufficient funds".to_string(),
            )
            .into());
        }
        Err(err) => {
            return Err(TxSubmitError::MaspError(err.to_string()).into());
        }
    };

    // Get the decoded asset types used in the transaction to give offline
    // wallet users more information
    #[allow(clippy::disallowed_methods)]
    let asset_types = used_asset_types(context, &shielded_parts.builder)
        .await
        .unwrap_or_default();

    Ok(Some((shielded_parts, asset_types)))
}

/// Submit a transaction to initialize an account
pub async fn build_init_account(
    context: &impl Namada,
    args::TxInitAccount {
        tx: tx_args,
        vp_code_path,
        tx_code_path,
        public_keys,
        threshold,
    }: &args::TxInitAccount,
) -> Result<(Tx, SigningTxData)> {
    let signing_data =
        signing::aux_signing_data(context, tx_args, None, None, vec![], false)
            .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    let vp_code_hash = query_wasm_code_hash_buf(context, vp_code_path).await?;

    let threshold = match threshold {
        Some(threshold) => {
            let threshold = *threshold;
            if (threshold > 0 && public_keys.len() as u8 >= threshold)
                || tx_args.force
            {
                threshold
            } else {
                edisplay_line!(
                    context.io(),
                    "Invalid account threshold: either the provided threshold \
                     is zero or the number of public keys is less than the \
                     threshold."
                );
                if !tx_args.force {
                    return Err(Error::from(
                        TxSubmitError::InvalidAccountThreshold,
                    ));
                }
                threshold
            }
        }
        None => {
            if public_keys.len() == 1 {
                1u8
            } else {
                return Err(Error::from(
                    TxSubmitError::MissingAccountThreshold,
                ));
            }
        }
    };

    let data = InitAccount {
        public_keys: public_keys.clone(),
        // We will add the hash inside the add_code_hash function
        vp_code_hash: Hash::zero(),
        threshold,
    };

    let add_code_hash = |tx: &mut Tx, data: &mut InitAccount| {
        let extra_section_hash = tx.add_extra_section_from_hash(
            vp_code_hash,
            Some(vp_code_path.to_string_lossy().into_owned()),
        );
        data.vp_code_hash = extra_section_hash;
        Ok(())
    };
    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        add_code_hash,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit a transaction to update a VP
pub async fn build_update_account(
    context: &impl Namada,
    args::TxUpdateAccount {
        tx: tx_args,
        vp_code_path,
        tx_code_path,
        addr,
        public_keys,
        threshold,
    }: &args::TxUpdateAccount,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(addr.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(addr.clone()),
        default_signer,
        vec![],
        false,
    )
    .await?;
    let (fee_amount, _) =
        validate_transparent_fee(context, tx_args, &signing_data.fee_payer)
            .await?;

    let account = if let Some(account) =
        rpc::get_account_info(context.client(), addr).await?
    {
        account
    } else {
        return Err(Error::from(TxSubmitError::LocationDoesNotExist(
            addr.clone(),
        )));
    };

    let threshold = if let Some(threshold) = threshold {
        let threshold = *threshold;

        let invalid_threshold = threshold.is_zero();
        let invalid_threshold_updated =
            !public_keys.is_empty() && public_keys.len() < threshold as usize;
        let invalid_threshold_current = public_keys.is_empty()
            && account.get_all_public_keys().len() < threshold as usize;

        if invalid_threshold
            || invalid_threshold_updated
            || invalid_threshold_current
        {
            edisplay_line!(
                context.io(),
                "Invalid account threshold: either the provided threshold is \
                 zero or the number of public keys is less than the threshold."
            );
            if !tx_args.force {
                return Err(Error::from(
                    TxSubmitError::InvalidAccountThreshold,
                ));
            }
        }

        Some(threshold)
    } else {
        let invalid_too_few_pks = !public_keys.is_empty()
            && public_keys.len() < account.threshold as usize;

        if invalid_too_few_pks {
            return Err(Error::from(TxSubmitError::InvalidAccountThreshold));
        }

        None
    };

    let vp_code_hash = match vp_code_path {
        Some(code_path) => {
            let vp_hash = query_wasm_code_hash_buf(context, code_path).await?;
            Some(vp_hash)
        }
        None => None,
    };

    let chain_id = tx_args.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, tx_args.expiration.to_datetime());
    if let Some(memo) = &tx_args.memo {
        tx.add_memo(memo);
    }
    let extra_section_hash = vp_code_path.as_ref().zip(vp_code_hash).map(
        |(code_path, vp_code_hash)| {
            tx.add_extra_section_from_hash(
                vp_code_hash,
                Some(code_path.to_string_lossy().into_owned()),
            )
        },
    );

    let data = UpdateAccount {
        addr: account.address,
        vp_code_hash: extra_section_hash,
        public_keys: public_keys.clone(),
        threshold,
    };

    let add_code_hash = |tx: &mut Tx, data: &mut UpdateAccount| {
        let extra_section_hash = vp_code_path.as_ref().zip(vp_code_hash).map(
            |(code_path, vp_code_hash)| {
                tx.add_extra_section_from_hash(
                    vp_code_hash,
                    Some(code_path.to_string_lossy().into_owned()),
                )
            },
        );
        data.vp_code_hash = extra_section_hash;
        Ok(())
    };
    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        add_code_hash,
        fee_amount,
        &signing_data.fee_payer,
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit a custom transaction
pub async fn build_custom(
    context: &impl Namada,
    args::TxCustom {
        tx: tx_args,
        code_path,
        data_path,
        serialized_tx,
        owner,
        disposable_signing_key,
    }: &args::TxCustom,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(owner.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(owner.clone()),
        default_signer,
        vec![],
        *disposable_signing_key,
    )
    .await?;
    let fee_amount = validate_fee(context, tx_args).await?;

    let mut tx = if let Some(serialized_tx) = serialized_tx {
        Tx::try_from_json_bytes(serialized_tx.as_ref()).map_err(|_| {
            Error::Other(
                "Invalid tx deserialization. Please make sure you are passing \
                 a file in .tx format, typically produced from using the \
                 `--dump-tx` flag."
                    .to_string(),
            )
        })?
    } else {
        let code_path = code_path
            .as_ref()
            .ok_or(Error::Other("No code path supplied".to_string()))?;
        let tx_code_hash = query_wasm_code_hash_buf(context, code_path).await?;
        let chain_id = tx_args.chain_id.clone().unwrap();
        let mut tx = Tx::new(chain_id, tx_args.expiration.to_datetime());
        if let Some(memo) = &tx_args.memo {
            tx.add_memo(memo);
        }
        tx.add_code_from_hash(
            tx_code_hash,
            Some(code_path.to_string_lossy().into_owned()),
        );
        data_path.clone().map(|data| tx.add_serialized_data(data));
        tx
    };

    prepare_tx(tx_args, &mut tx, fee_amount, signing_data.fee_payer.clone())
        .await?;

    Ok((tx, signing_data))
}

/// Generate IBC shielded transfer
pub async fn gen_ibc_shielding_transfer<N: Namada>(
    context: &N,
    args: args::GenIbcShieldingTransfer,
) -> Result<Option<MaspTransaction>> {
    let source = IBC;
    let (src_port_id, src_channel_id) =
        get_ibc_src_port_channel(context, &args.port_id, &args.channel_id)
            .await?;
    let ibc_denom =
        rpc::query_ibc_denom(context, &args.token, Some(&source)).await;
    // Need to check the prefix
    let token = namada_ibc::received_ibc_token(
        &ibc_denom,
        &src_port_id,
        &src_channel_id,
        &args.port_id,
        &args.channel_id,
    )
    .map_err(|e| {
        Error::Other(format!("Getting IBC Token failed: error {e}"))
    })?;
    let validated_amount =
        validate_amount(context, args.amount, &token, false).await?;

    // Precompute asset types to increase chances of success in decoding
    let token_map = context.wallet().await.get_addresses();
    let tokens = token_map.values().collect();
    let _ = context
        .shielded_mut()
        .await
        .precompute_asset_types(context.client(), tokens)
        .await;

    let masp_transfer_data = MaspTransferData {
        source: TransferSource::Address(source.clone()),
        target: args.target,
        token: token.clone(),
        amount: validated_amount,
    };
    let shielded_transfer = {
        let mut shielded = context.shielded_mut().await;
        shielded
            .gen_shielded_transfer(
                context,
                vec![masp_transfer_data],
                // Fees are paid from the transparent balance of the relayer
                None,
                args.expiration.to_datetime(),
                true,
            )
            .await
            .map_err(|err| TxSubmitError::MaspError(err.to_string()))?
    };

    Ok(shielded_transfer.map(|st| st.masp_tx))
}

async fn get_ibc_src_port_channel(
    context: &impl Namada,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<(PortId, ChannelId)> {
    use crate::ibc::core::channel::types::channel::ChannelEnd;
    use crate::ibc::primitives::proto::Protobuf;

    let channel_key = channel_key(dest_port_id, dest_channel_id);
    let bytes = rpc::query_storage_value_bytes(
        context.client(),
        &channel_key,
        None,
        false,
    )
    .await?
    .0
    .ok_or_else(|| {
        Error::Other(format!(
            "No channel end: port {dest_port_id}, channel {dest_channel_id}"
        ))
    })?;
    let channel = ChannelEnd::decode_vec(&bytes).map_err(|_| {
        Error::Other(format!(
            "Decoding channel end failed: port {dest_port_id}, channel \
             {dest_channel_id}",
        ))
    })?;
    channel
        .remote
        .channel_id()
        .map(|src_channel| {
            (channel.remote.port_id.clone(), src_channel.clone())
        })
        .ok_or_else(|| {
            Error::Other(format!(
                "The source channel doesn't exist: port {dest_port_id}, \
                 channel {dest_channel_id}"
            ))
        })
}

async fn expect_dry_broadcast(
    to_broadcast: TxBroadcastData,
    context: &impl Namada,
) -> Result<ProcessTxResponse> {
    match to_broadcast {
        TxBroadcastData::DryRun(tx) => {
            let result = rpc::dry_run_tx(context, tx.to_bytes()).await?;
            Ok(ProcessTxResponse::DryRun(result))
        }
        TxBroadcastData::Live { tx, tx_hash: _ } => {
            Err(Error::from(TxSubmitError::ExpectDryRun(tx)))
        }
    }
}

fn lift_rpc_error<T>(res: std::result::Result<T, RpcError>) -> Result<T> {
    res.map_err(|err| Error::from(TxSubmitError::TxBroadcast(err)))
}

/// Returns the given validator if the given address is a validator,
/// otherwise returns an error, force forces the address through even
/// if it isn't a validator
async fn known_validator_or_err(
    validator: Address,
    force: bool,
    context: &impl Namada,
) -> Result<Address> {
    // Check that the validator address exists on chain
    let is_validator = rpc::is_validator(context.client(), &validator).await?;
    if !is_validator {
        if force {
            edisplay_line!(
                context.io(),
                "The address {} doesn't belong to any known validator account.",
                validator
            );
            Ok(validator)
        } else {
            Err(Error::from(TxSubmitError::InvalidValidatorAddress(
                validator,
            )))
        }
    } else {
        Ok(validator)
    }
}

/// general pattern for checking if an address exists on the chain, or
/// throwing an error if it's not forced. Takes a generic error
/// message and the error type.
async fn address_exists_or_err<F>(
    addr: Address,
    force: bool,
    context: &impl Namada,
    message: String,
    err: F,
) -> Result<Address>
where
    F: FnOnce(Address) -> Error,
{
    let addr_exists = rpc::known_address(context.client(), &addr).await?;
    if !addr_exists {
        if force {
            edisplay_line!(context.io(), "{}", message);
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
async fn source_exists_or_err(
    token: Address,
    force: bool,
    context: &impl Namada,
) -> Result<Address> {
    let message =
        format!("The source address {} doesn't exist on chain.", token);
    address_exists_or_err(token, force, context, message, |err| {
        Error::from(TxSubmitError::SourceDoesNotExist(err))
    })
    .await
}

/// Returns the given target address if the given address exists on chain
/// otherwise returns an error, force forces the address through even
/// if it isn't on chain
async fn target_exists_or_err(
    token: Address,
    force: bool,
    context: &impl Namada,
) -> Result<Address> {
    let message =
        format!("The target address {} doesn't exist on chain.", token);
    address_exists_or_err(token, force, context, message, |err| {
        Error::from(TxSubmitError::TargetLocationDoesNotExist(err))
    })
    .await
}

/// Returns the given refund target address if the given address is valid for
/// the IBC shielded transfer. Returns an error if the address is a payment
/// address or given for non-shielded transfer.
async fn get_refund_target(
    context: &impl Namada,
    source: &TransferSource,
    refund_target: &Option<TransferTarget>,
) -> Result<Option<Address>> {
    match (source, refund_target) {
        (_, Some(TransferTarget::PaymentAddress(pa))) => {
            Err(Error::Other(format!(
                "Supporting only a transparent address as a refund target: {}",
                pa,
            )))
        }
        (
            TransferSource::ExtendedSpendingKey(_),
            Some(TransferTarget::Address(addr)),
        ) => Ok(Some(addr.clone())),
        (TransferSource::ExtendedSpendingKey(_), None) => {
            // Generate a new transparent address if it doesn't exist
            let mut rng = OsRng;
            let mut wallet = context.wallet_mut().await;
            let mut alias =
                format!("{IBC_REFUND_ALIAS_PREFIX}-{}", rng.next_u64());
            while wallet.find_address(&alias).is_some() {
                alias = format!("{IBC_REFUND_ALIAS_PREFIX}-{}", rng.next_u64());
            }
            wallet
                .gen_store_secret_key(
                    SchemeType::Ed25519,
                    Some(alias.clone()),
                    false,
                    None,
                    &mut rng,
                )
                .ok_or_else(|| {
                    Error::Other(
                        "Adding a new refund address failed".to_string(),
                    )
                })?;
            wallet.save().map_err(|e| {
                Error::Other(format!("Saving wallet error: {e}"))
            })?;
            let addr = wallet.find_address(alias).ok_or_else(|| {
                Error::Other("Finding the reund address failed".to_string())
            })?;
            Ok(Some(addr.into_owned()))
        }
        (_, Some(_)) => Err(Error::Other(
            "Refund target can't be specified for non-shielded transfer"
                .to_string(),
        )),
        (_, None) => Ok(None),
    }
}

enum CheckBalance {
    Balance(token::Amount),
    Query(storage::Key),
}

/// Checks the balance at the given address is enough to transfer the
/// given amount, along with the balance even existing. Force
/// overrides this.
async fn check_balance_too_low_err<N: Namada>(
    token: &Address,
    source: &Address,
    amount: token::Amount,
    balance: CheckBalance,
    force: bool,
    context: &N,
) -> Result<()> {
    let balance = match balance {
        CheckBalance::Balance(amt) => amt,
        CheckBalance::Query(ref balance_key) => {
            match rpc::query_storage_value::<N::Client, token::Amount>(
                context.client(),
                balance_key,
            )
            .await
            {
                Ok(amt) => amt,
                Err(Error::Query(
                    QueryError::General(_) | QueryError::NoSuchKey(_),
                )) => {
                    if force {
                        edisplay_line!(
                            context.io(),
                            "No balance found for the source {} of token {}",
                            source,
                            token
                        );
                        return Ok(());
                    } else {
                        return Err(Error::from(
                            TxSubmitError::NoBalanceForToken(
                                source.clone(),
                                token.clone(),
                            ),
                        ));
                    }
                }
                // We're either facing a no response or a conversion error
                // either way propagate it up
                Err(err) => return Err(err),
            }
        }
    };

    match balance.checked_sub(amount) {
        Some(_) => Ok(()),
        None => {
            if force {
                edisplay_line!(
                    context.io(),
                    "The balance of the source {} of token {} is lower than \
                     the amount to be transferred. Amount to transfer is {} \
                     and the balance is {}.",
                    source,
                    token,
                    context.format_amount(token, amount).await,
                    context.format_amount(token, balance).await,
                );
                Ok(())
            } else {
                Err(Error::from(TxSubmitError::BalanceTooLow(
                    source.clone(),
                    token.clone(),
                    amount.to_string_native(),
                    balance.to_string_native(),
                )))
            }
        }
    }
}

async fn query_wasm_code_hash_buf(
    context: &impl Namada,
    path: &Path,
) -> Result<Hash> {
    query_wasm_code_hash(context, path.to_string_lossy()).await
}

/// A helper for [`fn build`] that can be used for `on_tx` arg that does nothing
fn do_nothing<D>(_tx: &mut Tx, _data: &mut D) -> Result<()>
where
    D: BorshSerialize,
{
    Ok(())
}

fn proposal_to_vec(proposal: OnChainProposal) -> Result<Vec<u8>> {
    borsh::to_vec(&proposal.content)
        .map_err(|e| Error::from(EncodingError::Conversion(e.to_string())))
}
