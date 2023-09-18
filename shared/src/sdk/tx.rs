//! SDK functions to construct different types of transactions
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
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
use masp_primitives::transaction::components::I32Sum;
use namada_core::ledger::governance::cli::onchain::{
    DefaultProposal, OnChainProposal, PgfFundingProposal, PgfStewardProposal,
    ProposalVote,
};
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::ledger::governance::storage::vote::StorageProposalVote;
use namada_core::ledger::pgf::cli::steward::Commission;
use namada_core::types::address::{masp, Address, InternalAddress};
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::token::MaspDenom;
use namada_core::types::transaction::governance::{
    InitProposalData, VoteProposalData,
};
use namada_core::types::transaction::pgf::UpdateStewardCommission;
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::{CommissionPair, ValidatorState};

use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ibc::applications::transfer::PrefixedCoin;
use crate::ibc::core::ics04_channel::timeout::TimeoutHeight;
use crate::ibc::core::timestamp::Timestamp as IbcTimestamp;
use crate::ibc::core::Msg;
use crate::ibc::Height as IbcHeight;
use crate::ledger::ibc::storage::ibc_denom_key;
use crate::proto::{MaspBuilder, Tx};
use crate::sdk::args::{self, InputAmount};
use crate::sdk::error::{EncodingError, Error, QueryError, Result, TxError};
use crate::sdk::masp::TransferErr::Build;
use crate::sdk::masp::{ShieldedContext, ShieldedTransfer, ShieldedUtils};
use crate::sdk::rpc::{
    self, format_denominated_amount, query_wasm_code_hash, validate_amount,
    TxBroadcastData, TxResponse,
};
use crate::sdk::signing::{self, TxSourcePostBalance};
use crate::sdk::wallet::{Wallet, WalletUtils};
use crate::tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use crate::tendermint_rpc::error::Error as RpcError;
use crate::types::control_flow::{time, ProceedOrElse};
use crate::types::error::{EncodingError, Error, QueryError, Result, TxError};
use crate::types::io::Io;
use crate::types::key::*;
use crate::types::masp::TransferTarget;
use crate::types::storage::Epoch;
use crate::types::time::DateTimeUtc;
use crate::types::transaction::account::{InitAccount, UpdateAccount};
use crate::types::transaction::{pos, TxType};
use crate::types::{storage, token};
use crate::{display_line, edisplay_line, vm};

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
pub fn dump_tx<IO: Io>(args: &args::Tx, tx: Tx) {
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
                IO,
                "Transaction serialized to {}.",
                tx_path.to_string_lossy()
            );
        }
        None => {
            display_line!(IO, "Below the serialized transaction: \n");
            display_line!(IO, "{}", serialized_tx)
        }
    }
}

/// Prepare a transaction for signing and submission by adding a wrapper header
/// to it.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_tx<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    _wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args: &args::Tx,
    tx: &mut Tx,
    fee_payer: common::PublicKey,
    tx_source_balance: Option<TxSourcePostBalance>,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> Result<Option<Epoch>> {
    if !args.dry_run {
        let epoch = rpc::query_epoch(client).await?;

        Ok(signing::wrap_tx::<_, _, IO>(
            client,
            shielded,
            tx,
            args,
            tx_source_balance,
            epoch,
            fee_payer,
            #[cfg(not(feature = "mainnet"))]
            requires_pow,
        )
        .await)
    } else {
        Ok(None)
    }
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
pub async fn process_tx<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    IO: Io,
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

    if args.dry_run || args.dry_run_wrapper {
        expect_dry_broadcast::<_, IO>(TxBroadcastData::DryRun(tx), client).await
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
        let to_broadcast = TxBroadcastData::Live {
            tx,
            wrapper_hash,
            decrypted_hash,
        };
        // TODO: implement the code to resubmit the wrapper if it fails because
        // of masp epoch Either broadcast or submit transaction and
        // collect result into sum type
        if args.broadcast_only {
            broadcast_tx::<_, IO>(client, &to_broadcast)
                .await
                .map(ProcessTxResponse::Broadcast)
        } else {
            match submit_tx::<_, IO>(client, to_broadcast).await {
                Ok(x) => {
                    save_initialized_accounts::<U, IO>(
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
pub async fn is_reveal_pk_needed<C: crate::sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
    force: bool,
) -> Result<bool>
where
    C: crate::sdk::queries::Client + Sync,
{
    // Check if PK revealed
    Ok(force || !has_revealed_pk(client, address).await?)
}

/// Check if the public key for the given address has been revealed
pub async fn has_revealed_pk<C: crate::sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool> {
    rpc::is_public_key_revealed(client, address).await
}

/// Submit transaction to reveal the given public key
pub async fn build_reveal_pk<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args: &args::Tx,
    address: &Address,
    public_key: &common::PublicKey,
    fee_payer: &common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    display_line!(
        IO,
        "Submitting a tx to reveal the public key for address {address}..."
    );

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        args,
        args.tx_reveal_code_path.clone(),
        public_key,
        do_nothing,
        fee_payer,
        None,
    )
    .await
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx<C: crate::ledger::queries::Client + Sync, IO: Io>(
    rpc_cli: &C,
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
    let response =
        lift_rpc_error(rpc_cli.broadcast_tx_sync(tx.to_bytes().into()).await)?;

    if response.code == 0.into() {
        display_line!(IO, "Transaction added to mempool: {:?}", response);
        // Print the transaction identifiers to enable the extraction of
        // acceptance/application results later
        {
            display_line!(
                IO,
                "Wrapper transaction hash: {:?}",
                wrapper_tx_hash
            );
            display_line!(
                IO,
                "Inner transaction hash: {:?}",
                decrypted_tx_hash
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
pub async fn submit_tx<C, IO: Io>(
    client: &C,
    to_broadcast: TxBroadcastData,
) -> Result<TxResponse>
where
    C: crate::sdk::queries::Client + Sync,
{
    let (_, wrapper_hash, decrypted_hash) = match &to_broadcast {
        TxBroadcastData::Live {
            tx,
            wrapper_hash,
            decrypted_hash,
        } => Ok((tx, wrapper_hash, decrypted_hash)),
        TxBroadcastData::DryRun(tx) => Err(TxError::ExpectLiveRun(tx.clone())),
    }?;

    // Broadcast the supplied transaction
    broadcast_tx::<_, IO>(client, &to_broadcast).await?;

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
        let event =
            rpc::query_tx_status::<_, IO>(client, wrapper_query, deadline)
                .await
                .proceed_or(TxError::AcceptTimeout)?;
        let parsed = TxResponse::from_event(event);
        let tx_to_str = |parsed| {
            serde_json::to_string_pretty(parsed).map_err(|err| {
                Error::from(EncodingError::Serde(err.to_string()))
            })
        };
        display_line!(
            IO,
            "Transaction accepted with result: {}",
            tx_to_str(&parsed)?
        );
        // The transaction is now on chain. We wait for it to be decrypted
        // and applied
        if parsed.code == 0.to_string() {
            // We also listen to the event emitted when the encrypted
            // payload makes its way onto the blockchain
            let decrypted_query =
                rpc::TxEventQuery::Applied(decrypted_hash.as_str());
            let event = rpc::query_tx_status::<_, IO>(
                client,
                decrypted_query,
                deadline,
            )
            .await
            .proceed_or(TxError::AppliedTimeout)?;
            let parsed = TxResponse::from_event(event);
            display_line!(
                IO,
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
pub async fn save_initialized_accounts<U: WalletUtils, IO: Io>(
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    let len = initialized_accounts.len();
    if len != 0 {
        // Store newly initialized account addresses in the wallet
        display_line!(
            IO,
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
                    display_line!(
                        IO,
                        "Added alias {} for address {}.",
                        new_alias,
                        encoded
                    );
                }
                _ => {
                    display_line!(IO, "No alias added for address {}.", encoded)
                }
            };
        }
    }
}

/// Submit validator comission rate change
pub async fn build_validator_commission_change<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::CommissionRateChange {
        tx: tx_args,
        validator,
        rate,
        tx_code_path,
    }: args::CommissionRateChange,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let epoch = rpc::query_epoch(client).await?;

    let params: PosParams = rpc::get_pos_params(client).await?;

    let validator = validator.clone();
    if rpc::is_validator(client, &validator).await? {
        if rate < Dec::zero() || rate > Dec::one() {
            edisplay_line!(
                IO,
                "Invalid new commission rate, received {}",
                rate
            );
            return Err(Error::from(TxError::InvalidCommissionRate(rate)));
        }

        let pipeline_epoch_minus_one = epoch + params.pipeline_len - 1;

        match rpc::query_commission_rate(
            client,
            &validator,
            Some(pipeline_epoch_minus_one),
        )
        .await?
        {
            Some(CommissionPair {
                commission_rate,
                max_commission_change_per_epoch,
            }) => {
                if rate.abs_diff(&commission_rate)
                    > max_commission_change_per_epoch
                {
                    edisplay_line!(
                        IO,
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
                edisplay_line!(IO, "Error retrieving from storage");
                if !tx_args.force {
                    return Err(Error::from(TxError::Retrieval));
                }
            }
        }
    } else {
        edisplay_line!(IO, "The given address {validator} is not a validator.");
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

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        data,
        do_nothing,
        &fee_payer,
        None,
    )
    .await
}

/// Craft transaction to update a steward commission
pub async fn build_update_steward_commission<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::UpdateStewardCommission {
        tx: tx_args,
        steward,
        commission,
        tx_code_path,
    }: args::UpdateStewardCommission,
    gas_payer: &common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    if !rpc::is_steward(client, &steward).await && !tx_args.force {
        edisplay_line!(IO, "The given address {} is not a steward.", &steward);
        return Err(Error::from(TxError::InvalidSteward(steward.clone())));
    };

    let commission = Commission::try_from(commission.as_ref())
        .map_err(|e| TxError::InvalidStewardCommission(e.to_string()))?;

    if !commission.is_valid() && !tx_args.force {
        edisplay_line!(
            IO,
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

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        data,
        do_nothing,
        gas_payer,
        None,
    )
    .await
}

/// Craft transaction to resign as a steward
pub async fn build_resign_steward<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::ResignSteward {
        tx: tx_args,
        steward,
        tx_code_path,
    }: args::ResignSteward,
    gas_payer: &common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    if !rpc::is_steward(client, &steward).await && !tx_args.force {
        edisplay_line!(IO, "The given address {} is not a steward.", &steward);
        return Err(Error::from(TxError::InvalidSteward(steward.clone())));
    };

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        steward,
        do_nothing,
        gas_payer,
        None,
    )
    .await
}

/// Submit transaction to unjail a jailed validator
pub async fn build_unjail_validator<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::TxUnjailValidator {
        tx: tx_args,
        validator,
        tx_code_path,
    }: args::TxUnjailValidator,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    if !rpc::is_validator(client, &validator).await? {
        edisplay_line!(
            IO,
            "The given address {} is not a validator.",
            &validator
        );
        if !tx_args.force {
            return Err(Error::from(TxError::InvalidValidatorAddress(
                validator.clone(),
            )));
        }
    }

    let params: PosParams = rpc::get_pos_params(client).await?;
    let current_epoch = rpc::query_epoch(client).await?;
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let validator_state_at_pipeline =
        rpc::get_validator_state(client, &validator, Some(pipeline_epoch))
            .await?
            .ok_or_else(|| {
                Error::from(TxError::Other(
                    "Validator state should be defined.".to_string(),
                ))
            })?;
    if validator_state_at_pipeline != ValidatorState::Jailed {
        edisplay_line!(
            IO,
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
    match last_slash_epoch {
        Ok(last_slash_epoch) => {
            let eligible_epoch =
                last_slash_epoch + params.slash_processing_epoch_offset();
            if current_epoch < eligible_epoch {
                edisplay_line!(
                    IO,
                    "The given validator address {} is currently frozen and \
                     not yet eligible to be unjailed.",
                    &validator
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
        Err(Error::Query(
            QueryError::NoSuchKey(_) | QueryError::General(_),
        )) => {
            return Err(Error::from(TxError::Other(format!(
                "The given validator address {} is currently frozen and not \
                 yet eligible to be unjailed.",
                &validator
            ))));
        }
        Err(err) => return Err(err),
    }

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        validator,
        do_nothing,
        &fee_payer,
        None,
    )
    .await
}

/// Submit transaction to withdraw an unbond
pub async fn build_withdraw<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::Withdraw {
        tx: tx_args,
        validator,
        source,
        tx_code_path,
    }: args::Withdraw,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let epoch = rpc::query_epoch(client).await?;

    let validator = known_validator_or_err::<_, IO>(
        validator.clone(),
        tx_args.force,
        client,
    )
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
    .await?;

    if tokens.is_zero() {
        edisplay_line!(
            IO,
            "There are no unbonded bonds ready to withdraw in the current \
             epoch {}.",
            epoch
        );
        rpc::query_and_print_unbonds::<_, IO>(client, &bond_source, &validator)
            .await?;
        if !tx_args.force {
            return Err(Error::from(TxError::NoUnbondReady(epoch)));
        }
    } else {
        display_line!(
            IO,
            "Found {} tokens that can be withdrawn.",
            tokens.to_string_native()
        );
        display_line!(IO, "Submitting transaction to withdraw them...");
    }

    let data = pos::Withdraw { validator, source };

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        data,
        do_nothing,
        &fee_payer,
        None,
    )
    .await
}

/// Submit a transaction to unbond
pub async fn build_unbond<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::Unbond {
        tx: tx_args,
        validator,
        amount,
        source,
        tx_code_path,
    }: args::Unbond,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>, Option<(Epoch, token::Amount)>)> {
    let source = source.clone();
    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());

    if !tx_args.force {
        known_validator_or_err::<_, IO>(
            validator.clone(),
            tx_args.force,
            client,
        )
        .await?;

        let bond_amount =
            rpc::query_bond(client, &bond_source, &validator, None).await?;
        display_line!(
            IO,
            "Bond amount available for unbonding: {} NAM",
            bond_amount.to_string_native()
        );

        if amount > bond_amount {
            edisplay_line!(
                IO,
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
        rpc::query_unbond_with_slashing(client, &bond_source, &validator)
            .await?;
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

    let (tx, epoch) = build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        data,
        do_nothing,
        &fee_payer,
        None,
    )
    .await?;
    Ok((tx, epoch, latest_withdrawal_pre))
}

/// Query the unbonds post-tx
pub async fn query_unbonds<C: crate::ledger::queries::Client + Sync, IO: Io>(
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
                        IO,
                        "Unexpected behavior reading the unbonds data has \
                         occurred"
                    );
                } else {
                    return Err(Error::from(TxError::UnboundError));
                }
            }
            std::cmp::Ordering::Equal => {
                display_line!(
                    IO,
                    "Amount {} withdrawable starting from epoch {}",
                    (latest_withdraw_amount_post - latest_withdraw_amount_pre)
                        .to_string_native(),
                    latest_withdraw_epoch_post
                );
            }
            std::cmp::Ordering::Greater => {
                display_line!(
                    IO,
                    "Amount {} withdrawable starting from epoch {}",
                    latest_withdraw_amount_post.to_string_native(),
                    latest_withdraw_epoch_post,
                );
            }
        }
    } else {
        display_line!(
            IO,
            "Amount {} withdrawable starting from epoch {}",
            latest_withdraw_amount_post.to_string_native(),
            latest_withdraw_epoch_post,
        );
    }
    Ok(())
}

/// Submit a transaction to bond
pub async fn build_bond<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::Bond {
        tx: tx_args,
        validator,
        amount,
        source,
        native_token,
        tx_code_path,
    }: args::Bond,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let validator = known_validator_or_err::<_, IO>(
        validator.clone(),
        tx_args.force,
        client,
    )
    .await?;

    // Check that the source address exists on chain
    let source = match source.clone() {
        Some(source) => {
            source_exists_or_err::<_, IO>(source, tx_args.force, client)
                .await
                .map(Some)
        }
        None => Ok(source.clone()),
    }?;
    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let balance_key = token::balance_key(&native_token, bond_source);

    // TODO Should we state the same error message for the native token?
    let post_balance = check_balance_too_low_err::<_, IO>(
        &native_token,
        bond_source,
        amount,
        balance_key,
        tx_args.force,
        client,
    )
    .await?;
    let tx_source_balance = Some(TxSourcePostBalance {
        post_balance,
        source: bond_source.clone(),
        token: native_token,
    });

    let data = pos::Bond {
        validator,
        amount,
        source,
    };

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        data,
        do_nothing,
        &fee_payer,
        tx_source_balance,
    )
    .await
}

/// Build a default proposal governance
pub async fn build_default_proposal<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
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
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
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
    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx,
        tx_code_path,
        init_proposal_data,
        push_data,
        &fee_payer,
        None, // TODO: need to pay the fee to submit a proposal
    )
    .await
}

/// Build a proposal vote
pub async fn build_vote_proposal<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
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
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let proposal_vote = ProposalVote::try_from(vote)
        .map_err(|_| TxError::InvalidProposalVote)?;

    let proposal_id = proposal_id.ok_or_else(|| {
        Error::Other("Proposal id must be defined.".to_string())
    })?;
    let proposal = if let Some(proposal) =
        rpc::query_proposal_by_id(client, proposal_id).await?
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

    let is_validator = rpc::is_validator(client, &voter).await?;

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

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx,
        tx_code_path,
        data,
        do_nothing,
        &fee_payer,
        None,
    )
    .await
}

/// Build a pgf funding proposal governance
pub async fn build_pgf_funding_proposal<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
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
    fee_payer: &common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

    let add_section = |tx: &mut Tx, data: &mut InitProposalData| {
        let (_, extra_section_hash) =
            tx.add_extra_section(proposal_to_vec(proposal.proposal)?);
        data.content = extra_section_hash;
        Ok(())
    };
    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx,
        tx_code_path,
        init_proposal_data,
        add_section,
        fee_payer,
        None, // TODO: need to pay the fee to submit a proposal
    )
    .await
}

/// Build a pgf funding proposal governance
pub async fn build_pgf_stewards_proposal<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
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
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let init_proposal_data = InitProposalData::try_from(proposal.clone())
        .map_err(|e| TxError::InvalidProposal(e.to_string()))?;

    let add_section = |tx: &mut Tx, data: &mut InitProposalData| {
        let (_, extra_section_hash) =
            tx.add_extra_section(proposal_to_vec(proposal.proposal)?);
        data.content = extra_section_hash;
        Ok(())
    };

    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx,
        tx_code_path,
        init_proposal_data,
        add_section,
        &fee_payer,
        None, // TODO: need to pay the fee to submit a proposal
    )
    .await
}

/// Submit an IBC transfer
pub async fn build_ibc_transfer<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args: args::TxIbcTransfer,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    // Check that the source address exists on chain
    let source = source_exists_or_err::<_, IO>(
        args.source.clone(),
        args.tx.force,
        client,
    )
    .await?;
    // We cannot check the receiver

    // validate the amount given
    let validated_amount = validate_amount::<_, IO>(
        client,
        args.amount,
        &args.token,
        args.tx.force,
    )
    .await?;
    if validated_amount.canonical().denom.0 != 0 {
        return Err(Error::Other(format!(
            "The amount for the IBC transfer should be an integer: {}",
            validated_amount
        )));
    }

    // Check source balance
    let balance_key = token::balance_key(&args.token, &source);

    let post_balance = check_balance_too_low_err::<_, IO>(
        &args.token,
        &source,
        validated_amount.amount,
        balance_key,
        args.tx.force,
        client,
    )
    .await?;
    let tx_source_balance = Some(TxSourcePostBalance {
        post_balance,
        source: source.clone(),
        token: args.token.clone(),
    });

    let tx_code_hash = query_wasm_code_hash::<_, IO>(
        client,
        args.tx_code_path.to_str().unwrap(),
    )
    .await
    .map_err(|e| Error::from(QueryError::Wasm(e.to_string())))?;

    let ibc_denom = match &args.token {
        Address::Internal(InternalAddress::IbcToken(hash)) => {
            let ibc_denom_key = ibc_denom_key(hash);
            rpc::query_storage_value::<C, String>(client, &ibc_denom_key)
                .await
                .map_err(|_e| TxError::TokenDoesNotExist(args.token.clone()))?
        }
        _ => args.token.to_string(),
    };
    let token = PrefixedCoin {
        denom: ibc_denom.parse().expect("Invalid IBC denom"),
        // Set the IBC amount as an integer
        amount: validated_amount.into(),
    };
    let packet_data = PacketData {
        token,
        sender: source.to_string().into(),
        receiver: args.receiver.into(),
        memo: args.memo.unwrap_or_default().into(),
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

    let msg = MsgTransfer {
        port_id_on_a: args.port_id,
        chan_id_on_a: args.channel_id,
        packet_data,
        timeout_height_on_b: timeout_height,
        timeout_timestamp_on_b: timeout_timestamp,
    };

    let any_msg = msg.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data)
        .map_err(TxError::EncodeFailure)?;

    let chain_id = args.tx.chain_id.clone().unwrap();
    let mut tx = Tx::new(chain_id, args.tx.expiration);
    tx.add_code_from_hash(tx_code_hash)
        .add_serialized_data(data);

    let epoch = prepare_tx::<C, U, V, IO>(
        client,
        wallet,
        shielded,
        &args.tx,
        &mut tx,
        fee_payer,
        tx_source_balance,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;

    Ok((tx, epoch))
}

/// Abstraction for helping build transactions
#[allow(clippy::too_many_arguments)]
pub async fn build<C: crate::ledger::queries::Client + Sync, U, V, F, D, IO>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    tx_args: &crate::sdk::args::Tx,
    path: PathBuf,
    data: D,
    on_tx: F,
    gas_payer: &common::PublicKey,
    tx_source_balance: Option<TxSourcePostBalance>,
) -> Result<(Tx, Option<Epoch>)>
where
    F: FnOnce(&mut Tx, &mut D) -> Result<()>,
    D: BorshSerialize,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
{
    build_pow_flag::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        tx_args,
        path,
        data,
        on_tx,
        gas_payer,
        tx_source_balance,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn build_pow_flag<
    C: crate::ledger::queries::Client + Sync,
    U,
    V,
    F,
    D,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    tx_args: &crate::sdk::args::Tx,
    path: PathBuf,
    mut data: D,
    on_tx: F,
    gas_payer: &common::PublicKey,
    tx_source_balance: Option<TxSourcePostBalance>,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> Result<(Tx, Option<Epoch>)>
where
    F: FnOnce(&mut Tx, &mut D) -> Result<()>,
    D: BorshSerialize,
    U: WalletUtils,
    V: ShieldedUtils,
{
    let chain_id = tx_args.chain_id.clone().unwrap();

    let mut tx_builder = Tx::new(chain_id, tx_args.expiration);

    let tx_code_hash =
        query_wasm_code_hash::<_, IO>(client, path.to_string_lossy())
            .await
            .map_err(|e| Error::from(QueryError::Wasm(e.to_string())))?;

    on_tx(&mut tx_builder, &mut data)?;

    tx_builder.add_code_from_hash(tx_code_hash).add_data(data);

    let epoch = prepare_tx::<C, U, V, IO>(
        client,
        wallet,
        shielded,
        tx_args,
        &mut tx_builder,
        gas_payer.clone(),
        tx_source_balance,
        #[cfg(not(feature = "mainnet"))]
        requires_pow,
    )
    .await?;
    Ok((tx_builder, epoch))
}

/// Try to decode the given asset type and add its decoding to the supplied set.
/// Returns true only if a new decoding has been added to the given set.
async fn add_asset_type<
    C: crate::sdk::queries::Client + Sync,
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
    C: crate::sdk::queries::Client + Sync,
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
            I32Sum::from(output.conversion().clone()).components()
        {
            add_asset_type(&mut asset_types, shielded, client, *asset_type)
                .await;
        }
    }
    Ok(asset_types)
}

/// Submit an ordinary transfer
pub async fn build_transfer<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    mut args: args::TxTransfer,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let source = args.source.effective_address();
    let target = args.target.effective_address();
    let token = args.token.clone();

    // Check that the source address exists on chain
    source_exists_or_err::<_, IO>(source.clone(), args.tx.force, client)
        .await?;
    // Check that the target address exists on chain
    target_exists_or_err::<_, IO>(target.clone(), args.tx.force, client)
        .await?;
    // Check source balance
    let balance_key = token::balance_key(&token, &source);

    // validate the amount given
    let validated_amount =
        validate_amount::<_, IO>(client, args.amount, &token, args.tx.force)
            .await?;

    args.amount = InputAmount::Validated(validated_amount);
    let post_balance = check_balance_too_low_err::<C, IO>(
        &token,
        &source,
        validated_amount.amount,
        balance_key,
        args.tx.force,
        client,
    )
    .await?;
    let tx_source_balance = Some(TxSourcePostBalance {
        post_balance,
        source: source.clone(),
        token: token.clone(),
    });

    let masp_addr = masp();

    // For MASP sources, use a special sentinel key recognized by VPs as default
    // signer. Also, if the transaction is shielded, redact the amount and token
    // types by setting the transparent value to 0 and token type to a constant.
    // This has no side-effect because transaction is to self.
    let (_amount, token) = if source == masp_addr && target == masp_addr {
        // TODO Refactor me, we shouldn't rely on any specific token here.
        (token::Amount::default(), args.native_token.clone())
    } else {
        (validated_amount.amount, token)
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
        .gen_shielded_transfer::<_, IO>(client, args.clone())
        .await;

    let shielded_parts = match stx_result {
        Ok(stx) => Ok(stx),
        Err(Build(builder::Error::InsufficientFunds(_))) => {
            Err(TxError::NegativeBalanceAfterTransfer(
                Box::new(source.clone()),
                validated_amount.amount.to_string_native(),
                Box::new(token.clone()),
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
    let (tx, unshielding_epoch) = build_pow_flag::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &args.tx,
        args.tx_code_path,
        transfer,
        add_shielded,
        &fee_payer,
        tx_source_balance,
        #[cfg(not(feature = "mainnet"))]
        is_source_faucet,
    )
    .await?;
    // Manage the two masp epochs
    let masp_epoch = match (unshielding_epoch, shielded_tx_epoch) {
        (Some(fee_unshield_epoch), Some(transfer_unshield_epoch)) => {
            // If the two masp epochs are different, either the wrapper or the
            // inner tx will fail, so abort tx creation
            if fee_unshield_epoch != transfer_unshield_epoch && !args.tx.force {
                return Err(Error::Other(
                    "Fee unshilding masp tx and inner tx masp transaction \
                     were crafted on an epoch boundary"
                        .to_string(),
                ));
            }
            // Take the smaller of the two epochs
            Some(fee_unshield_epoch.min(transfer_unshield_epoch))
        }
        (Some(_fee_unshielding_epoch), None) => unshielding_epoch,
        (None, Some(_transfer_unshield_epoch)) => shielded_tx_epoch,
        (None, None) => None,
    };
    Ok((tx, masp_epoch))
}

/// Submit a transaction to initialize an account
pub async fn build_init_account<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::TxInitAccount {
        tx: tx_args,
        vp_code_path,
        tx_code_path,
        public_keys,
        threshold,
    }: args::TxInitAccount,
    fee_payer: &common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let vp_code_hash =
        query_wasm_code_hash_buf::<_, IO>(client, &vp_code_path).await?;

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
    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        data,
        add_code_hash,
        fee_payer,
        None,
    )
    .await
}

/// Submit a transaction to update a VP
pub async fn build_update_account<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::TxUpdateAccount {
        tx: tx_args,
        vp_code_path,
        tx_code_path,
        addr,
        public_keys,
        threshold,
    }: args::TxUpdateAccount,
    fee_payer: common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let addr =
        if let Some(account) = rpc::get_account_info(client, &addr).await? {
            account.address
        } else if tx_args.force {
            addr
        } else {
            return Err(Error::from(TxError::LocationDoesNotExist(addr)));
        };

    let vp_code_hash = match vp_code_path {
        Some(code_path) => {
            let vp_hash =
                query_wasm_code_hash_buf::<_, IO>(client, &code_path).await?;
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
    build::<_, _, _, _, _, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        tx_code_path,
        data,
        add_code_hash,
        &fee_payer,
        None,
    )
    .await
}

/// Submit a custom transaction
pub async fn build_custom<
    C: crate::sdk::queries::Client + Sync,
    U: WalletUtils,
    V: ShieldedUtils,
    IO: Io,
>(
    client: &C,
    wallet: &mut Wallet<U>,
    shielded: &mut ShieldedContext<V>,
    args::TxCustom {
        tx: tx_args,
        code_path,
        data_path,
        serialized_tx,
        owner: _,
    }: args::TxCustom,
    fee_payer: &common::PublicKey,
) -> Result<(Tx, Option<Epoch>)> {
    let mut tx = if let Some(serialized_tx) = serialized_tx {
        Tx::deserialize(serialized_tx.as_ref()).map_err(|_| {
            Error::Other("Invalid tx deserialization.".to_string())
        })?
    } else {
        let tx_code_hash = query_wasm_code_hash_buf::<_, IO>(
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

    let epoch = prepare_tx::<C, U, V, IO>(
        client,
        wallet,
        shielded,
        &tx_args,
        &mut tx,
        fee_payer.clone(),
        None,
        #[cfg(not(feature = "mainnet"))]
        false,
    )
    .await?;

    Ok((tx, epoch))
}

async fn expect_dry_broadcast<
    C: crate::ledger::queries::Client + Sync,
    IO: Io,
>(
    to_broadcast: TxBroadcastData,
    client: &C,
) -> Result<ProcessTxResponse> {
    match to_broadcast {
        TxBroadcastData::DryRun(tx) => {
            rpc::dry_run_tx::<_, IO>(client, tx.to_bytes()).await?;
            Ok(ProcessTxResponse::DryRun)
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
async fn known_validator_or_err<
    C: crate::ledger::queries::Client + Sync,
    IO: Io,
>(
    validator: Address,
    force: bool,
    client: &C,
) -> Result<Address> {
    // Check that the validator address exists on chain
    let is_validator = rpc::is_validator(client, &validator).await?;
    if !is_validator {
        if force {
            edisplay_line!(
                IO,
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
async fn address_exists_or_err<C, F, IO: Io>(
    addr: Address,
    force: bool,
    client: &C,
    message: String,
    err: F,
) -> Result<Address>
where
    C: crate::sdk::queries::Client + Sync,
    F: FnOnce(Address) -> Error,
{
    let addr_exists = rpc::known_address::<C>(client, &addr).await?;
    if !addr_exists {
        if force {
            edisplay_line!(IO, "{}", message);
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
async fn source_exists_or_err<
    C: crate::ledger::queries::Client + Sync,
    IO: Io,
>(
    token: Address,
    force: bool,
    client: &C,
) -> Result<Address> {
    let message =
        format!("The source address {} doesn't exist on chain.", token);
    address_exists_or_err::<_, _, IO>(token, force, client, message, |err| {
        Error::from(TxError::SourceDoesNotExist(err))
    })
    .await
}

/// Returns the given target address if the given address exists on chain
/// otherwise returns an error, force forces the address through even
/// if it isn't on chain
async fn target_exists_or_err<
    C: crate::ledger::queries::Client + Sync,
    IO: Io,
>(
    token: Address,
    force: bool,
    client: &C,
) -> Result<Address> {
    let message =
        format!("The target address {} doesn't exist on chain.", token);
    address_exists_or_err::<_, _, IO>(token, force, client, message, |err| {
        Error::from(TxError::TargetLocationDoesNotExist(err))
    })
    .await
}

/// Checks the balance at the given address is enough to transfer the
/// given amount, along with the balance even existing. Force
/// overrides this. Returns the updated balance for fee check if necessary
async fn check_balance_too_low_err<
    C: crate::ledger::queries::Client + Sync,
    IO: Io,
>(
    token: &Address,
    source: &Address,
    amount: token::Amount,
    balance_key: storage::Key,
    force: bool,
    client: &C,
) -> Result<token::Amount> {
    match rpc::query_storage_value::<C, token::Amount>(client, &balance_key)
        .await
    {
        Ok(balance) => match balance.checked_sub(amount) {
            Some(diff) => Ok(diff),
            None => {
                if force {
                    edisplay_line!(
                        IO,
                        "The balance of the source {} of token {} is lower \
                         than the amount to be transferred. Amount to \
                         transfer is {} and the balance is {}.",
                        source,
                        token,
                        format_denominated_amount::<_, IO>(
                            client, token, amount
                        )
                        .await,
                        format_denominated_amount::<_, IO>(
                            client, token, balance
                        )
                        .await,
                    );
                    Ok(token::Amount::default())
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
                    IO,
                    "No balance found for the source {} of token {}",
                    source,
                    token
                );
                Ok(token::Amount::default())
            } else {
                Err(Error::from(TxError::NoBalanceForToken(
                    source.clone(),
                    token.clone(),
                )))
            }
        }
        // We're either facing a no response or a conversion error
        // either way propigate it up
        Err(err) => Err(err),
    }
}

#[allow(dead_code)]
fn validate_untrusted_code_err<IO: Io>(
    vp_code: &Vec<u8>,
    force: bool,
) -> Result<()> {
    if let Err(err) = vm::validate_untrusted_wasm(vp_code) {
        if force {
            edisplay_line!(
                IO,
                "Validity predicate code validation failed with {}",
                err
            );
            Ok(())
        } else {
            Err(Error::from(TxError::WasmValidationFailure(err)))
        }
    } else {
        Ok(())
    }
}
async fn query_wasm_code_hash_buf<
    C: crate::ledger::queries::Client + Sync,
    IO: Io,
>(
    client: &C,
    path: &Path,
) -> Result<Hash> {
    query_wasm_code_hash::<_, IO>(client, path.to_string_lossy()).await
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
