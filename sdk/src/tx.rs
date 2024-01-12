//! SDK functions to construct different types of transactions
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use borsh::BorshSerialize;
use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::builder;
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::sapling::fees::{
    ConvertView, InputView as SaplingInputView, OutputView as SaplingOutputView,
};
use masp_primitives::transaction::components::transparent::fees::{
    InputView as TransparentInputView, OutputView as TransparentOutputView,
};
use masp_primitives::transaction::components::I128Sum;
use namada_core::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use namada_core::ibc::apps::transfer::types::packet::PacketData;
use namada_core::ibc::apps::transfer::types::PrefixedCoin;
use namada_core::ibc::core::channel::types::timeout::TimeoutHeight;
use namada_core::ibc::core::client::types::Height as IbcHeight;
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::ibc::primitives::{Msg, Timestamp as IbcTimestamp};
use namada_core::ledger::governance::cli::onchain::{
    DefaultProposal, OnChainProposal, PgfFundingProposal, PgfStewardProposal,
    ProposalVote,
};
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::ledger::governance::storage::vote::StorageProposalVote;
use namada_core::ledger::ibc::storage::channel_key;
use namada_core::ledger::pgf::cli::steward::Commission;
use namada_core::types::address::{Address, InternalAddress, MASP};
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::ibc::{IbcShieldedTransfer, MsgShieldedTransfer};
use namada_core::types::key::*;
use namada_core::types::masp::{TransferSource, TransferTarget};
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token::MaspDenom;
use namada_core::types::transaction::account::{InitAccount, UpdateAccount};
use namada_core::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada_core::types::transaction::pgf::UpdateStewardCommission;
use namada_core::types::transaction::{pos, ResultCode, TxResult};
use namada_core::types::{storage, token};
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::{CommissionPair, ValidatorState};

use crate::args::{self, InputAmount};
use crate::control_flow::time;
use crate::error::{EncodingError, Error, QueryError, Result, TxError};
use crate::io::Io;
use crate::masp::TransferErr::Build;
use crate::masp::{ShieldedContext, ShieldedTransfer};
use crate::proto::{MaspBuilder, Tx};
use crate::queries::Client;
use crate::rpc::{
    self, query_wasm_code_hash, validate_amount, InnerTxResult,
    TxBroadcastData, TxResponse,
};
use crate::signing::{self, SigningTxData, TxSourcePostBalance};
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::tendermint_rpc::error::Error as RpcError;
use crate::wallet::WalletIo;
use crate::{display_line, edisplay_line, Namada};

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
    DryRun(TxResult),
}

impl ProcessTxResponse {
    // Returns a `TxResult` if the transaction applied and was it accepted by
    // all VPs. Note that this always returns false for dry-run transactions.
    pub fn is_applied_and_valid(&self) -> Option<&TxResult> {
        match self {
            ProcessTxResponse::Applied(resp) => {
                if resp.code == ResultCode::Ok {
                    if let InnerTxResult::Success(result) =
                        resp.inner_tx_result()
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
    let tx_id = tx.header_hash();
    let serialized_tx = tx.serialize();
    match args.output_folder.to_owned() {
        Some(path) => {
            let tx_filename = format!("{}.tx", tx_id);
            let tx_path = path.join(tx_filename);
            let out = File::create(&tx_path).unwrap();
            serde_json::to_writer_pretty(out, &serialized_tx)
                .expect("Should be able to write to file.");
            display_line!(
                io,
                "Transaction serialized to {}.",
                tx_path.to_string_lossy()
            );
        }
        None => {
            display_line!(io, "Below the serialized transaction: \n");
            display_line!(io, "{}", serialized_tx)
        }
    }
}

/// Prepare a transaction for signing and submission by adding a wrapper header
/// to it.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_tx(
    context: &impl Namada,
    args: &args::Tx,
    tx: &mut Tx,
    fee_payer: common::PublicKey,
    tx_source_balance: Option<TxSourcePostBalance>,
) -> Result<()> {
    if !args.dry_run {
        let epoch = rpc::query_epoch(context.client()).await?;

        signing::wrap_tx(context, tx, args, tx_source_balance, epoch, fee_payer)
            .await
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
        let wrapper_hash = tx.header_hash().to_string();
        // We use this to determine when the decrypted inner tx makes it
        // on-chain
        let decrypted_hash = tx.raw_header_hash().to_string();
        let to_broadcast = TxBroadcastData::Live {
            tx,
            wrapper_hash,
            decrypted_hash,
        };
        // TODO: implement the code to resubmit the wrapper if it fails because
        // of masp epoch Either broadcast or submit transaction and
        // collect result into sum type
        if args.broadcast_only {
            broadcast_tx(context, &to_broadcast)
                .await
                .map(ProcessTxResponse::Broadcast)
        } else {
            match submit_tx(context, to_broadcast).await {
                Ok(resp) => {
                    if let InnerTxResult::Success(result) =
                        resp.inner_tx_result()
                    {
                        save_initialized_accounts(
                            context,
                            args,
                            result.initialized_accounts.clone(),
                        )
                        .await;
                    }
                    Ok(ProcessTxResponse::Applied(resp))
                }
                Err(x) => Err(x),
            }
        }
    }
}

/// Check if a reveal public key transaction is needed
pub async fn is_reveal_pk_needed<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
    force: bool,
) -> Result<bool>
where
    C: crate::queries::Client + Sync,
{
    // Check if PK revealed
    Ok(force || !has_revealed_pk(client, address).await?)
}

/// Check if the public key for the given address has been revealed
pub async fn has_revealed_pk<C: crate::queries::Client + Sync>(
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
    let signing_data =
        signing::aux_signing_data(context, args, None, Some(public_key.into()))
            .await?;

    build(
        context,
        args,
        args.tx_reveal_code_path.clone(),
        public_key,
        do_nothing,
        &signing_data.fee_payer,
        None,
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
    let (tx, wrapper_tx_hash, decrypted_tx_hash) = match to_broadcast {
        TxBroadcastData::Live {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => Ok((tx, wrapper_hash, decrypted_hash)),
        TxBroadcastData::DryRun(tx) => Err(TxError::ExpectLiveRun(tx.clone())),
    }?;

    tracing::debug!(
        transaction = ?to_broadcast,
        "Broadcasting transaction",
    );

    // TODO: configure an explicit timeout value? we need to hack away at
    // `tendermint-rs` for this, which is currently using a hard-coded 30s
    // timeout.
    let response = lift_rpc_error(
        context.client().broadcast_tx_sync(tx.to_bytes()).await,
    )?;

    if response.code == 0.into() {
        display_line!(context.io(), "Transaction added to mempool.");
        tracing::debug!("Transaction mempool response: {response:#?}");
        // Print the transaction identifiers to enable the extraction of
        // acceptance/application results later
        {
            display_line!(
                context.io(),
                "Wrapper transaction hash: {wrapper_tx_hash}",
            );
            display_line!(
                context.io(),
                "Inner transaction hash: {decrypted_tx_hash}",
            );
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
pub async fn submit_tx(
    context: &impl Namada,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse> {
    let (_, wrapper_hash, decrypted_hash) = match &to_broadcast {
        TxBroadcastData::Live {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => Ok((tx, wrapper_hash, decrypted_hash)),
        TxBroadcastData::DryRun(tx) => Err(TxError::ExpectLiveRun(tx.clone())),
    }?;

    // Broadcast the supplied transaction
    broadcast_tx(context, &to_broadcast).await?;

    let deadline = time::Instant::now()
        + time::Duration::from_secs(
            DEFAULT_NAMADA_EVENTS_MAX_WAIT_TIME_SECONDS,
        );

    tracing::debug!(
        transaction = ?to_broadcast,
        ?deadline,
        "Awaiting transaction approval",
    );

    let response = {
        let wrapper_query = rpc::TxEventQuery::Accepted(wrapper_hash.as_str());
        let event =
            rpc::query_tx_status(context, wrapper_query, deadline).await?;
        let wrapper_resp = TxResponse::from_event(event);

        if display_wrapper_resp_and_get_result(context, &wrapper_resp) {
            display_line!(
                context.io(),
                "Waiting for inner transaction result..."
            );
            // The transaction is now on chain. We wait for it to be decrypted
            // and applied
            // We also listen to the event emitted when the encrypted
            // payload makes its way onto the blockchain
            let decrypted_query =
                rpc::TxEventQuery::Applied(decrypted_hash.as_str());
            let event =
                rpc::query_tx_status(context, decrypted_query, deadline)
                    .await?;
            let inner_resp = TxResponse::from_event(event);

            display_inner_resp(context, &inner_resp);
            Ok(inner_resp)
        } else {
            Ok(wrapper_resp)
        }
    };

    response
}

/// Display a result of a wrapper tx.
/// Returns true if the wrapper tx was successful.
pub fn display_wrapper_resp_and_get_result(
    context: &impl Namada,
    resp: &TxResponse,
) -> bool {
    let result = if resp.code != ResultCode::Ok {
        display_line!(
            context.io(),
            "Wrapper transaction failed with error code {}. Used {} gas.",
            resp.code,
            resp.gas_used,
        );
        false
    } else {
        display_line!(
            context.io(),
            "Wrapper transaction accepted at height {}. Used {} gas.",
            resp.height,
            resp.gas_used,
        );
        true
    };

    tracing::debug!(
        "Full wrapper result: {}",
        serde_json::to_string_pretty(resp).unwrap()
    );
    result
}

/// Display a result of an inner tx.
pub fn display_inner_resp(context: &impl Namada, resp: &TxResponse) {
    match resp.inner_tx_result() {
        InnerTxResult::Success(inner) => {
            display_line!(
                context.io(),
                "Transaction was successfully applied at height {}. Used {} \
                 gas.",
                resp.height,
                inner.gas_used,
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
                "Transaction was rejected by VPs: {}.\nChanged keys: {}",
                serde_json::to_string_pretty(&inner.vps_result.rejected_vps)
                    .unwrap(),
                serde_json::to_string_pretty(&changed_keys).unwrap(),
            );
        }
        InnerTxResult::OtherFailure => {
            edisplay_line!(
                context.io(),
                "Transaction failed.\nDetails: {}",
                serde_json::to_string_pretty(&resp).unwrap()
            );
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
    )
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
            return Err(Error::from(TxError::InvalidCommissionRate(*rate)));
        }

        let pipeline_epoch_minus_one = epoch + params.pipeline_len - 1;

        match rpc::query_commission_rate(
            context.client(),
            &validator,
            Some(pipeline_epoch_minus_one),
        )
        .await?
        {
            Some(CommissionPair {
                commission_rate,
                max_commission_change_per_epoch,
            }) => {
                if rate.is_negative() || *rate > Dec::one() {
                    edisplay_line!(
                        context.io(),
                        "New rate is outside of the allowed range of values \
                         between 0.0 and 1.0."
                    );
                    if !tx_args.force {
                        return Err(Error::from(
                            TxError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
                if rate.abs_diff(&commission_rate)
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
                            TxError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
            }
            None => {
                edisplay_line!(context.io(), "Error retrieving from storage");
                if !tx_args.force {
                    return Err(Error::from(TxError::Retrieval));
                }
            }
        }
    } else {
        edisplay_line!(
            context.io(),
            "The given address {validator} is not a validator."
        );
        if !tx_args.force {
            return Err(Error::from(TxError::InvalidValidatorAddress(
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
        &signing_data.fee_payer,
        None,
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
    )
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
            return Err(Error::from(TxError::InvalidEmail));
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
                return Err(Error::from(TxError::InvalidCommissionRate(*rate)));
            }
        }
        let pipeline_epoch_minus_one = epoch + params.pipeline_len - 1;

        match rpc::query_commission_rate(
            context.client(),
            &validator,
            Some(pipeline_epoch_minus_one),
        )
        .await?
        {
            Some(CommissionPair {
                commission_rate,
                max_commission_change_per_epoch,
            }) => {
                if rate.is_negative() || *rate > Dec::one() {
                    edisplay_line!(
                        context.io(),
                        "New rate is outside of the allowed range of values \
                         between 0.0 and 1.0."
                    );
                    if !tx_args.force {
                        return Err(Error::from(
                            TxError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
                if rate.abs_diff(&commission_rate)
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
                            TxError::InvalidCommissionRate(*rate),
                        ));
                    }
                }
            }
            None => {
                edisplay_line!(context.io(), "Error retrieving from storage");
                if !tx_args.force {
                    return Err(Error::from(TxError::Retrieval));
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
        commission_rate: *commission_rate,
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        data,
        do_nothing,
        &signing_data.fee_payer,
        None,
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
    )
    .await?;

    if !rpc::is_steward(context.client(), steward).await && !tx_args.force {
        edisplay_line!(
            context.io(),
            "The given address {} is not a steward.",
            &steward
        );
        return Err(Error::from(TxError::InvalidSteward(steward.clone())));
    };

    let commission = Commission::try_from(commission.as_ref())
        .map_err(|e| TxError::InvalidStewardCommission(e.to_string()))?;

    if !commission.is_valid() && !tx_args.force {
        edisplay_line!(
            context.io(),
            "The sum of all percentage must not be greater than 1."
        );
        return Err(Error::from(TxError::InvalidStewardCommission(
            "Commission sum is greater than 1.".to_string(),
        )));
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
        &signing_data.fee_payer,
        None,
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
    )
    .await?;

    if !rpc::is_steward(context.client(), steward).await && !tx_args.force {
        edisplay_line!(
            context.io(),
            "The given address {} is not a steward.",
            &steward
        );
        return Err(Error::from(TxError::InvalidSteward(steward.clone())));
    };

    build(
        context,
        tx_args,
        tx_code_path.clone(),
        steward.clone(),
        do_nothing,
        &signing_data.fee_payer,
        None,
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
    )
    .await?;

    if !rpc::is_validator(context.client(), validator).await? {
        edisplay_line!(
            context.io(),
            "The given address {} is not a validator.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let validator_state_at_pipeline = rpc::get_validator_state(
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
            return Err(Error::from(TxError::ValidatorNotCurrentlyJailed(
                validator.clone(),
            )));
        }
    }

    let last_slash_epoch =
        rpc::query_last_infraction_epoch(context.client(), validator).await;
    match last_slash_epoch {
        Ok(Some(last_slash_epoch)) => {
            // Jailed due to slashing
            let eligible_epoch =
                last_slash_epoch + params.slash_processing_epoch_offset();
            if current_epoch < eligible_epoch {
                edisplay_line!(
                    context.io(),
                    "The given validator address {} is currently frozen and \
                     will be eligible to be unjailed starting at epoch {}.",
                    &validator,
                    eligible_epoch
                );
                if !tx_args.force {
                    return Err(Error::from(
                        TxError::ValidatorFrozenFromUnjailing(
                            validator.clone(),
                        ),
                    ));
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
        &signing_data.fee_payer,
        None,
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
    )
    .await?;

    // Check if the validator address is actually a validator
    if !rpc::is_validator(context.client(), validator).await? {
        edisplay_line!(
            context.io(),
            "The given address {} is not a validator.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let validator_state_at_pipeline = rpc::get_validator_state(
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
            return Err(Error::from(TxError::ValidatorInactive(
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
        &signing_data.fee_payer,
        None,
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
    )
    .await?;

    // Check if the validator address is actually a validator
    if !rpc::is_validator(context.client(), validator).await? {
        edisplay_line!(
            context.io(),
            "The given address {} is not a validator.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    for epoch in Epoch::iter_bounds_inclusive(current_epoch, pipeline_epoch) {
        let validator_state =
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
                return Err(Error::from(TxError::ValidatorNotInactive(
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
        &signing_data.fee_payer,
        None,
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
            return Err(Error::from(TxError::RedelegationIsZero));
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
            return Err(Error::from(TxError::RedelegatorIsValidator(
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
            return Err(Error::from(TxError::RedelegationSrcEqDest));
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
        let last_contrib_epoch = redel_end_epoch.prev();
        last_contrib_epoch + params.slash_processing_epoch_offset()
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
            return Err(Error::from(TxError::IncomingRedelIsStillSlashable(
                src_validator.clone(),
                owner.clone(),
            )));
        }
    }

    // Give a redelegation warning based on the pipeline state of the dest
    // validator
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let dest_validator_state_at_pipeline = rpc::get_validator_state(
        context.client(),
        &dest_validator,
        Some(pipeline_epoch),
    )
    .await?;
    if dest_validator_state_at_pipeline == Some(ValidatorState::Inactive)
        && !tx_args.force
    {
        edisplay_line!(
            context.io(),
            "WARNING: the given destination validator address {} is inactive \
             at the pipeline epoch {}. If you would still like to bond to the \
             inactive validator, use the --force option.",
            &dest_validator,
            &pipeline_epoch
        );
        return Err(Error::from(TxError::ValidatorInactive(
            dest_validator.clone(),
            pipeline_epoch,
        )));
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
            return Err(Error::from(TxError::RedelegationAmountTooLarge(
                redel_amount.to_string_native(),
                bond_amount.to_string_native(),
            )));
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
    )
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
        &signing_data.fee_payer,
        None,
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
    )
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
            return Err(Error::from(TxError::NoUnbondReady(epoch)));
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
        &signing_data.fee_payer,
        None,
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
    )
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
        &signing_data.fee_payer,
        None,
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
            return Err(Error::from(TxError::BondIsZero));
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

    let default_address = source.clone().unwrap_or(validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(default_address),
        default_signer,
    )
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
        *to_withdraw += amount;
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
        &signing_data.fee_payer,
        None,
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
                    edisplay_line!(
                        context.io(),
                        "Unexpected behavior reading the unbonds data has \
                         occurred"
                    );
                } else {
                    return Err(Error::from(TxError::UnboundError));
                }
            }
            std::cmp::Ordering::Equal => {
                display_line!(
                    context.io(),
                    "Amount {} withdrawable starting from epoch {}",
                    (latest_withdraw_amount_post - latest_withdraw_amount_pre)
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
        native_token,
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
            return Err(Error::from(TxError::BondIsZero));
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

    // Give a bonding warning based on the pipeline state
    let params: PosParams = rpc::get_pos_params(context.client()).await?;
    let current_epoch = rpc::query_epoch(context.client()).await?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let validator_state_at_pipeline = rpc::get_validator_state(
        context.client(),
        &validator,
        Some(pipeline_epoch),
    )
    .await?;
    if validator_state_at_pipeline == Some(ValidatorState::Inactive)
        && !tx_args.force
    {
        edisplay_line!(
            context.io(),
            "WARNING: the given validator address {} is inactive at the \
             pipeline epoch {}. If you would still like to bond to the \
             inactive validator, use the --force option.",
            &validator,
            &pipeline_epoch
        );
        return Err(Error::from(TxError::ValidatorInactive(
            validator.clone(),
            pipeline_epoch,
        )));
    }

    let default_address = source.clone().unwrap_or(validator.clone());
    let default_signer = Some(default_address.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(default_address.clone()),
        default_signer,
    )
    .await?;

    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let balance_key = token::balance_key(native_token, bond_source);

    // TODO Should we state the same error message for the native token?
    let post_balance = check_balance_too_low_err(
        native_token,
        bond_source,
        *amount,
        balance_key,
        tx_args.force,
        context,
    )
    .await?;
    let tx_source_balance = Some(TxSourcePostBalance {
        post_balance,
        source: bond_source.clone(),
        token: native_token.clone(),
    });

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
        &signing_data.fee_payer,
        tx_source_balance,
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
        native_token: _,
        is_offline: _,
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
    )
    .await?;

    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

    let push_data =
        |tx_builder: &mut Tx, init_proposal_data: &mut InitProposalData| {
            let (_, extra_section_hash) = tx_builder
                .add_extra_section(proposal_to_vec(proposal.proposal)?, None);
            init_proposal_data.content = extra_section_hash;

            if let Some(init_proposal_code) = proposal.data {
                let (_, extra_section_hash) =
                    tx_builder.add_extra_section(init_proposal_code, None);
                init_proposal_data.r#type =
                    ProposalType::Default(Some(extra_section_hash));
            };
            Ok(())
        };
    build(
        context,
        tx,
        tx_code_path.clone(),
        init_proposal_data,
        push_data,
        &signing_data.fee_payer,
        None, // TODO: need to pay the fee to submit a proposal
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
        voter,
        is_offline: _,
        proposal_data: _,
        tx_code_path,
    }: &args::VoteProposal,
    epoch: Epoch,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(voter.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx,
        Some(voter.clone()),
        default_signer.clone(),
    )
    .await?;

    let proposal_vote = ProposalVote::try_from(vote.clone())
        .map_err(|_| TxError::InvalidProposalVote)?;

    let proposal_id = proposal_id.ok_or_else(|| {
        Error::Other("Proposal id must be defined.".to_string())
    })?;
    let proposal = if let Some(proposal) =
        rpc::query_proposal_by_id(context.client(), proposal_id).await?
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

    let is_validator = rpc::is_validator(context.client(), voter).await?;

    if !proposal.can_be_voted(epoch, is_validator) {
        if tx.force {
            eprintln!("Invalid proposal {} vote period.", proposal_id);
        } else {
            return Err(Error::from(TxError::InvalidProposalVotingPeriod(
                proposal_id,
            )));
        }
    }

    let delegations = rpc::get_delegators_delegation_at(
        context.client(),
        voter,
        proposal.voting_start_epoch,
    )
    .await?
    .keys()
    .cloned()
    .collect::<Vec<Address>>();

    let data = VoteProposalData {
        id: proposal_id,
        vote: storage_vote,
        voter: voter.clone(),
        delegations,
    };

    build(
        context,
        tx,
        tx_code_path.clone(),
        data,
        do_nothing,
        &signing_data.fee_payer,
        None,
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
        native_token: _,
        is_offline: _,
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
    )
    .await?;

    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

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
        &signing_data.fee_payer,
        None, // TODO: need to pay the fee to submit a proposal
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
        native_token: _,
        is_offline: _,
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
    )
    .await?;

    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

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
        &signing_data.fee_payer,
        None, // TODO: need to pay the fee to submit a proposal
    )
    .await
    .map(|tx| (tx, signing_data))
}

/// Submit an IBC transfer
pub async fn build_ibc_transfer(
    context: &impl Namada,
    args: &args::TxIbcTransfer,
) -> Result<(Tx, SigningTxData, Option<Epoch>)> {
    let source = args.source.effective_address();
    let signing_data = signing::aux_signing_data(
        context,
        &args.tx,
        Some(source.clone()),
        Some(source.clone()),
    )
    .await?;
    // Check that the source address exists on chain
    let source =
        source_exists_or_err(source.clone(), args.tx.force, context).await?;
    // We cannot check the receiver

    // validate the amount given
    let validated_amount =
        validate_amount(context, args.amount, &args.token, args.tx.force)
            .await
            .expect("expected to validate amount");
    if validated_amount.canonical().denom().0 != 0 {
        return Err(Error::Other(format!(
            "The amount for the IBC transfer should be an integer: {}",
            validated_amount
        )));
    }

    // Check source balance
    let balance_key = token::balance_key(&args.token, &source);

    let post_balance = check_balance_too_low_err(
        &args.token,
        &source,
        validated_amount.amount(),
        balance_key,
        args.tx.force,
        context,
    )
    .await?;
    let tx_source_balance = Some(TxSourcePostBalance {
        post_balance,
        source: source.clone(),
        token: args.token.clone(),
    });

    let tx_code_hash =
        query_wasm_code_hash(context, args.tx_code_path.to_str().unwrap())
            .await
            .map_err(|e| Error::from(QueryError::Wasm(e.to_string())))?;

    // For transfer from a spending key
    let shielded_parts = construct_shielded_parts(
        context,
        &args.source,
        // The token will be escrowed to IBC address
        &TransferTarget::Address(Address::Internal(InternalAddress::Ibc)),
        &args.token,
        validated_amount,
    )
    .await?;
    let shielded_tx_epoch = shielded_parts.as_ref().map(|trans| trans.0.epoch);

    let ibc_denom =
        rpc::query_ibc_denom(context, &args.token.to_string(), Some(&source))
            .await;
    let token = PrefixedCoin {
        denom: ibc_denom.parse().expect("Invalid IBC denom"),
        // Set the IBC amount as an integer
        amount: validated_amount.into(),
    };
    let packet_data = PacketData {
        token,
        sender: source.to_string().into(),
        receiver: args.receiver.clone().into(),
        memo: args.memo.clone().unwrap_or_default().into(),
    };

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
    > = DateTimeUtc::now().try_into();
    let now = now.map_err(|e| Error::Other(e.to_string()))?;
    let now: IbcTimestamp = now.into();
    let timeout_timestamp = if let Some(offset) = args.timeout_sec_offset {
        (now + Duration::new(offset, 0))
            .map_err(|e| Error::Other(e.to_string()))?
    } else if timeout_height == TimeoutHeight::Never {
        // we cannot set 0 to both the height and the timestamp
        (now + Duration::new(3600, 0))
            .map_err(|e| Error::Other(e.to_string()))?
    } else {
        IbcTimestamp::none()
    };

    let message = MsgTransfer {
        port_id_on_a: args.port_id.clone(),
        chan_id_on_a: args.channel_id.clone(),
        packet_data,
        timeout_height_on_b: timeout_height,
        timeout_timestamp_on_b: timeout_timestamp,
    };

    let chain_id = args.tx.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, args.tx.expiration);

    let data = match shielded_parts {
        Some((shielded_transfer, asset_types)) => {
            let masp_tx_hash =
                tx.add_masp_tx_section(shielded_transfer.masp_tx.clone()).1;
            let transfer = token::Transfer {
                source: source.clone(),
                // The token will be escrowed to IBC address
                target: Address::Internal(InternalAddress::Ibc),
                token: args.token.clone(),
                amount: validated_amount,
                // The address could be a payment address, but the address isn't
                // that of this chain.
                key: None,
                // Link the Transfer to the MASP Transaction by hash code
                shielded: Some(masp_tx_hash),
            };
            tx.add_masp_builder(MaspBuilder {
                asset_types,
                metadata: shielded_transfer.metadata,
                builder: shielded_transfer.builder,
                target: masp_tx_hash,
            });
            let shielded_transfer = IbcShieldedTransfer {
                transfer,
                masp_tx: shielded_transfer.masp_tx,
            };
            MsgShieldedTransfer {
                message,
                shielded_transfer,
            }
            .serialize_to_vec()
        }
        None => {
            let any_msg = message.to_any();
            let mut data = vec![];
            prost::Message::encode(&any_msg, &mut data)
                .map_err(TxError::EncodeFailure)?;
            data
        }
    };

    tx.add_code_from_hash(
        tx_code_hash,
        Some(args.tx_code_path.to_string_lossy().into_owned()),
    )
    .add_serialized_data(data);

    prepare_tx(
        context,
        &args.tx,
        &mut tx,
        signing_data.fee_payer.clone(),
        tx_source_balance,
    )
    .await?;

    Ok((tx, signing_data, shielded_tx_epoch))
}

/// Abstraction for helping build transactions
#[allow(clippy::too_many_arguments)]
pub async fn build<F, D>(
    context: &impl Namada,
    tx_args: &crate::args::Tx,
    path: PathBuf,
    data: D,
    on_tx: F,
    gas_payer: &common::PublicKey,
    tx_source_balance: Option<TxSourcePostBalance>,
) -> Result<Tx>
where
    F: FnOnce(&mut Tx, &mut D) -> Result<()>,
    D: BorshSerialize,
{
    build_pow_flag(
        context,
        tx_args,
        path,
        data,
        on_tx,
        gas_payer,
        tx_source_balance,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn build_pow_flag<F, D>(
    context: &impl Namada,
    tx_args: &crate::args::Tx,
    path: PathBuf,
    mut data: D,
    on_tx: F,
    gas_payer: &common::PublicKey,
    tx_source_balance: Option<TxSourcePostBalance>,
) -> Result<Tx>
where
    F: FnOnce(&mut Tx, &mut D) -> Result<()>,
    D: BorshSerialize,
{
    let chain_id = tx_args.chain_id.clone().unwrap();

    let mut tx_builder = Tx::new(chain_id, tx_args.expiration);

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

    prepare_tx(
        context,
        tx_args,
        &mut tx_builder,
        gas_payer.clone(),
        tx_source_balance,
    )
    .await?;
    Ok(tx_builder)
}

/// Try to decode the given asset type and add its decoding to the supplied set.
/// Returns true only if a new decoding has been added to the given set.
async fn add_asset_type(
    asset_types: &mut HashSet<(Address, MaspDenom, Option<Epoch>)>,
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
async fn used_asset_types<P, R, K, N>(
    context: &impl Namada,
    builder: &Builder<P, R, K, N>,
) -> std::result::Result<HashSet<(Address, MaspDenom, Option<Epoch>)>, RpcError>
{
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

/// Submit an ordinary transfer
pub async fn build_transfer<N: Namada>(
    context: &N,
    args: &mut args::TxTransfer,
) -> Result<(Tx, SigningTxData, Option<Epoch>)> {
    let default_signer = Some(args.source.effective_address());
    let signing_data = signing::aux_signing_data(
        context,
        &args.tx,
        Some(args.source.effective_address()),
        default_signer,
    )
    .await?;

    let source = args.source.effective_address();
    let target = args.target.effective_address();

    // Check that the source address exists on chain
    source_exists_or_err(source.clone(), args.tx.force, context).await?;
    // Check that the target address exists on chain
    target_exists_or_err(target.clone(), args.tx.force, context).await?;
    // Check source balance
    let balance_key = token::balance_key(&args.token, &source);

    // validate the amount given
    let validated_amount =
        validate_amount(context, args.amount, &args.token, args.tx.force)
            .await?;

    args.amount = InputAmount::Validated(validated_amount);
    let post_balance = check_balance_too_low_err(
        &args.token,
        &source,
        validated_amount.amount(),
        balance_key,
        args.tx.force,
        context,
    )
    .await?;
    let tx_source_balance = Some(TxSourcePostBalance {
        post_balance,
        source: source.clone(),
        token: args.token.clone(),
    });

    let masp_addr = MASP;

    // For MASP sources, use a special sentinel key recognized by VPs as default
    // signer. Also, if the transaction is shielded, redact the amount and token
    // types by setting the transparent value to 0 and token type to a constant.
    // This has no side-effect because transaction is to self.
    let (transparent_amount, transparent_token) =
        if source == masp_addr && target == masp_addr {
            // TODO Refactor me, we shouldn't rely on any specific token here.
            (token::Amount::zero().into(), args.native_token.clone())
        } else {
            (validated_amount, args.token.clone())
        };
    // Determine whether to pin this transaction to a storage key
    let key = match &args.target {
        TransferTarget::PaymentAddress(pa) if pa.is_pinned() => Some(pa.hash()),
        _ => None,
    };

    let shielded_parts = construct_shielded_parts(
        context,
        &args.source,
        &args.target,
        &args.token,
        validated_amount,
    )
    .await?;
    let shielded_tx_epoch = shielded_parts.as_ref().map(|trans| trans.0.epoch);

    // Construct the corresponding transparent Transfer object
    let transfer = token::Transfer {
        source: source.clone(),
        target: target.clone(),
        token: transparent_token.clone(),
        amount: transparent_amount,
        key: key.clone(),
        // Link the Transfer to the MASP Transaction by hash code
        shielded: None,
    };

    let add_shielded = |tx: &mut Tx, transfer: &mut token::Transfer| {
        // Add the MASP Transaction and its Builder to facilitate validation
        if let Some((
            ShieldedTransfer {
                builder,
                masp_tx,
                metadata,
                epoch: _,
            },
            asset_types,
        )) = shielded_parts
        {
            // Add a MASP Transaction section to the Tx and get the tx hash
            let masp_tx_hash = tx.add_masp_tx_section(masp_tx).1;
            transfer.shielded = Some(masp_tx_hash);

            tracing::debug!("Transfer data {:?}", transfer);

            tx.add_masp_builder(MaspBuilder {
                asset_types,
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
        context,
        &args.tx,
        args.tx_code_path.clone(),
        transfer,
        add_shielded,
        &signing_data.fee_payer,
        tx_source_balance,
    )
    .await?;
    Ok((tx, signing_data, shielded_tx_epoch))
}

// Construct the shielded part of the transaction, if any
async fn construct_shielded_parts<N: Namada>(
    context: &N,
    source: &TransferSource,
    target: &TransferTarget,
    token: &Address,
    amount: token::DenominatedAmount,
) -> Result<
    Option<(
        ShieldedTransfer,
        HashSet<(Address, MaspDenom, Option<Epoch>)>,
    )>,
> {
    let stx_result =
        ShieldedContext::<N::ShieldedUtils>::gen_shielded_transfer(
            context, source, target, token, amount,
        )
        .await;

    let shielded_parts = match stx_result {
        Ok(Some(stx)) => stx,
        Ok(None) => return Ok(None),
        Err(Build(builder::Error::InsufficientFunds(_))) => {
            return Err(TxError::NegativeBalanceAfterTransfer(
                Box::new(source.effective_address()),
                amount.amount().to_string_native(),
                Box::new(token.clone()),
            )
            .into());
        }
        Err(err) => return Err(TxError::MaspError(err.to_string()).into()),
    };

    // Get the decoded asset types used in the transaction to give offline
    // wallet users more information
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
        signing::aux_signing_data(context, tx_args, None, None).await?;

    let vp_code_hash = query_wasm_code_hash_buf(context, vp_code_path).await?;

    let threshold = match threshold {
        Some(threshold) => *threshold,
        None => {
            if public_keys.len() == 1 {
                1u8
            } else {
                return Err(Error::from(TxError::MissingAccountThreshold));
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
        &signing_data.fee_payer,
        None,
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
    )
    .await?;

    let addr = if let Some(account) =
        rpc::get_account_info(context.client(), addr).await?
    {
        account.address
    } else if tx_args.force {
        addr.clone()
    } else {
        return Err(Error::from(TxError::LocationDoesNotExist(addr.clone())));
    };

    let vp_code_hash = match vp_code_path {
        Some(code_path) => {
            let vp_hash = query_wasm_code_hash_buf(context, code_path).await?;
            Some(vp_hash)
        }
        None => None,
    };

    let chain_id = tx_args.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, tx_args.expiration);
    let extra_section_hash = vp_code_path.as_ref().zip(vp_code_hash).map(
        |(code_path, vp_code_hash)| {
            tx.add_extra_section_from_hash(
                vp_code_hash,
                Some(code_path.to_string_lossy().into_owned()),
            )
        },
    );

    let data = UpdateAccount {
        addr,
        vp_code_hash: extra_section_hash,
        public_keys: public_keys.clone(),
        threshold: *threshold,
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
        &signing_data.fee_payer,
        None,
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
    }: &args::TxCustom,
) -> Result<(Tx, SigningTxData)> {
    let default_signer = Some(owner.clone());
    let signing_data = signing::aux_signing_data(
        context,
        tx_args,
        Some(owner.clone()),
        default_signer,
    )
    .await?;

    let mut tx = if let Some(serialized_tx) = serialized_tx {
        Tx::deserialize(serialized_tx.as_ref()).map_err(|_| {
            Error::Other("Invalid tx deserialization.".to_string())
        })?
    } else {
        let code_path = code_path
            .as_ref()
            .ok_or(Error::Other("No code path supplied".to_string()))?;
        let tx_code_hash = query_wasm_code_hash_buf(context, code_path).await?;
        let chain_id = tx_args.chain_id.clone().unwrap();
        let mut tx = Tx::new(chain_id, tx_args.expiration);
        tx.add_code_from_hash(
            tx_code_hash,
            Some(code_path.to_string_lossy().into_owned()),
        );
        data_path.clone().map(|data| tx.add_serialized_data(data));
        tx
    };

    prepare_tx(
        context,
        tx_args,
        &mut tx,
        signing_data.fee_payer.clone(),
        None,
    )
    .await?;

    Ok((tx, signing_data))
}

/// Generate IBC shielded transfer
pub async fn gen_ibc_shielded_transfer<N: Namada>(
    context: &N,
    args: args::GenIbcShieldedTransafer,
) -> Result<Option<IbcShieldedTransfer>> {
    let key = match args.target.payment_address() {
        Some(pa) if pa.is_pinned() => Some(pa.hash()),
        Some(_) => None,
        None => return Ok(None),
    };
    let source = Address::Internal(InternalAddress::Ibc);
    let (src_port_id, src_channel_id) =
        get_ibc_src_port_channel(context, &args.port_id, &args.channel_id)
            .await?;
    let ibc_denom =
        rpc::query_ibc_denom(context, &args.token, Some(&source)).await;
    let prefixed_denom = ibc_denom
        .parse()
        .map_err(|_| Error::Other(format!("Invalid IBC denom: {ibc_denom}")))?;
    let token = namada_core::ledger::ibc::received_ibc_token(
        &prefixed_denom,
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

    let shielded_transfer =
        ShieldedContext::<N::ShieldedUtils>::gen_shielded_transfer(
            context,
            &TransferSource::Address(source.clone()),
            &args.target,
            &token,
            validated_amount,
        )
        .await
        .map_err(|err| TxError::MaspError(err.to_string()))?;

    let transfer = token::Transfer {
        source: source.clone(),
        target: MASP,
        token: token.clone(),
        amount: validated_amount,
        key,
        shielded: None,
    };
    if let Some(shielded_transfer) = shielded_transfer {
        // TODO: Workaround for decoding the asset_type later
        let mut shielded = context.shielded_mut().await;
        for denom in MaspDenom::iter() {
            let epoch = shielded_transfer.epoch;
            shielded
                .get_asset_type(context.client(), epoch, token.clone(), denom)
                .await
                .map_err(|_| {
                    Error::Other("unable to create asset type".to_string())
                })?;
        }
        let _ = shielded.save().await;

        Ok(Some(IbcShieldedTransfer {
            transfer,
            masp_tx: shielded_transfer.masp_tx,
        }))
    } else {
        Ok(None)
    }
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
        TxBroadcastData::Live {
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
            Err(Error::from(TxError::InvalidValidatorAddress(validator)))
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
        Error::from(TxError::SourceDoesNotExist(err))
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
        Error::from(TxError::TargetLocationDoesNotExist(err))
    })
    .await
}

/// Checks the balance at the given address is enough to transfer the
/// given amount, along with the balance even existing. Force
/// overrides this. Returns the updated balance for fee check if necessary
async fn check_balance_too_low_err<N: Namada>(
    token: &Address,
    source: &Address,
    amount: token::Amount,
    balance_key: storage::Key,
    force: bool,
    context: &N,
) -> Result<token::Amount> {
    match rpc::query_storage_value::<N::Client, token::Amount>(
        context.client(),
        &balance_key,
    )
    .await
    {
        Ok(balance) => match balance.checked_sub(amount) {
            Some(diff) => Ok(diff),
            None => {
                if force {
                    edisplay_line!(
                        context.io(),
                        "The balance of the source {} of token {} is lower \
                         than the amount to be transferred. Amount to \
                         transfer is {} and the balance is {}.",
                        source,
                        token,
                        context.format_amount(token, amount).await,
                        context.format_amount(token, balance).await,
                    );
                    Ok(token::Amount::zero())
                } else {
                    Err(Error::from(TxError::BalanceTooLow(
                        source.clone(),
                        token.clone(),
                        amount.to_string_native(),
                        balance.to_string_native(),
                    )))
                }
            }
        },
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
                Ok(token::Amount::zero())
            } else {
                Err(Error::from(TxError::NoBalanceForToken(
                    source.clone(),
                    token.clone(),
                )))
            }
        }
        // We're either facing a no response or a conversion error
        // either way propagate it up
        Err(err) => Err(err),
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
