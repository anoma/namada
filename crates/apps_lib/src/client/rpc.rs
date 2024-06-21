//! Client RPC queries

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use borsh::BorshDeserialize;
use data_encoding::HEXLOWER;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada_sdk::address::{Address, InternalAddress, MASP};
use namada_sdk::collections::{HashMap, HashSet};
use namada_sdk::control_flow::time::{Duration, Instant};
use namada_sdk::events::Event;
use namada_sdk::governance::parameters::GovernanceParameters;
use namada_sdk::governance::pgf::parameters::PgfParameters;
use namada_sdk::governance::pgf::storage::steward::StewardDetail;
use namada_sdk::governance::storage::keys as governance_storage;
use namada_sdk::governance::storage::proposal::{
    StoragePgfFunding, StorageProposal,
};
use namada_sdk::governance::utils::{ProposalVotes, VotePower};
use namada_sdk::governance::ProposalVote;
use namada_sdk::hash::Hash;
use namada_sdk::io::Io;
use namada_sdk::key::*;
use namada_sdk::masp::{BalanceOwner, MaspEpoch, MaspTokenRewardData};
use namada_sdk::parameters::{storage as param_storage, EpochDuration};
use namada_sdk::proof_of_stake::types::{
    CommissionPair, Slash, ValidatorMetaData, ValidatorState,
    ValidatorStateInfo, WeightedValidator,
};
use namada_sdk::proof_of_stake::PosParams;
use namada_sdk::queries::{Client, RPC};
use namada_sdk::rpc::{
    self, enriched_bonds_and_unbonds, query_epoch, TxResponse,
};
use namada_sdk::storage::{BlockHeight, BlockResults, Epoch};
use namada_sdk::tendermint_rpc::endpoint::status;
use namada_sdk::token::MaspDigitPos;
use namada_sdk::tx::display_batch_resp;
use namada_sdk::wallet::AddressVpType;
use namada_sdk::{
    display, display_line, edisplay_line, error, state as storage, token,
    Namada,
};

use crate::cli::{self, args};
use crate::facade::tendermint::merkle::proof::ProofOps;

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status(
    namada: &impl Namada,
    status: namada_sdk::rpc::TxEventQuery<'_>,
    deadline: Instant,
) -> Event {
    rpc::query_tx_status(namada, status, deadline)
        .await
        .unwrap()
}

/// Query and print the epoch of the last committed block
pub async fn query_and_print_epoch(context: &impl Namada) -> Epoch {
    let epoch = rpc::query_epoch(context.client()).await.unwrap();
    display_line!(context.io(), "Last committed epoch: {}", epoch);
    epoch
}

/// Query and print the masp epoch of the last committed block
pub async fn query_and_print_masp_epoch(context: &impl Namada) -> MaspEpoch {
    let epoch = rpc::query_masp_epoch(context.client()).await.unwrap();
    display_line!(context.io(), "Last committed masp epoch: {}", epoch);
    epoch
}

/// Query and print some information to help discern when the next epoch will
/// begin.
pub async fn query_and_print_next_epoch_info(context: &impl Namada) {
    let (this_epoch_first_height, epoch_duration) =
        rpc::query_next_epoch_info(context.client()).await.unwrap();

    display_line!(
        context.io(),
        "First block height of this current epoch: {this_epoch_first_height}."
    );
    display_line!(
        context.io(),
        "Minimum number of blocks in an epoch: {}.",
        epoch_duration.min_num_of_blocks
    );
    display_line!(
        context.io(),
        "Minimum amount of time for an epoch: {} seconds.",
        epoch_duration.min_duration
    );
    display_line!(
        context.io(),
        "\nEarliest height at which the next epoch can begin is block {}.",
        this_epoch_first_height.0 + epoch_duration.min_num_of_blocks
    );
}

/// Query and print node's status.
pub async fn query_and_print_status(
    context: &impl Namada,
) -> Option<status::Response> {
    let status = context.client().status().await;
    match status {
        Ok(status) => {
            display_line!(context.io(), "Node's status {status:#?}");
            Some(status)
        }
        Err(err) => {
            edisplay_line!(context.io(), "Status query failed with {err:#?}");
            None
        }
    }
}

/// Query the last committed block
pub async fn query_block(context: &impl Namada) {
    let block = namada_sdk::rpc::query_block(context.client())
        .await
        .unwrap();
    match block {
        Some(block) => {
            display_line!(
                context.io(),
                "Last committed block height: {}, time: {}",
                block.height,
                block.time
            );
        }
        None => {
            display_line!(context.io(), "No block has been committed yet.");
        }
    }
}

/// Query the results of the last committed block
pub async fn query_results<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    _args: args::Query,
) -> Vec<BlockResults> {
    unwrap_client_response::<C, Vec<BlockResults>>(
        RPC.shell().read_results(client).await,
    )
}

/// Query the raw bytes of given storage key
pub async fn query_raw_bytes<N: Namada>(
    context: &N,
    args: args::QueryRawBytes,
) {
    let response = unwrap_client_response::<N::Client, _>(
        RPC.shell()
            .storage_value(
                context.client(),
                None,
                None,
                false,
                &args.storage_key,
            )
            .await,
    );
    if !response.data.is_empty() {
        display_line!(
            context.io(),
            "Found data: 0x{}",
            HEXLOWER.encode(&response.data)
        );
    } else {
        display_line!(
            context.io(),
            "No data found for key {}",
            args.storage_key
        );
    }
}

/// Query token balance(s)
pub async fn query_balance(context: &impl Namada, args: args::QueryBalance) {
    match &args.owner {
        BalanceOwner::Address(_) => {
            query_transparent_balance(context, args).await
        }
        BalanceOwner::FullViewingKey(_) => {
            query_shielded_balance(context, args).await
        }
    }
}

/// Query token balance(s)
async fn query_transparent_balance(
    context: &impl Namada,
    args: args::QueryBalance,
) {
    let args::QueryBalance {
        // Token owner (needs to be a transparent address)
        owner,
        // The token to query
        token,
        ..
    } = args;

    let owner = owner
        .address()
        .expect("Balance owner should have been a transparent address");

    let token_alias = lookup_token_alias(context, &token, &owner).await;
    let token_balance_result =
        namada_sdk::rpc::get_token_balance(context.client(), &token, &owner)
            .await;

    match token_balance_result {
        Ok(balance) => {
            let balance = context.format_amount(&token, balance).await;
            display_line!(context.io(), "{token_alias}: {balance}");
        }
        Err(e) => {
            display_line!(
                context.io(),
                "Error querying balance of {token_alias}: {e}"
            );
        }
    }
}

/// Return the token alias of the given `token`.
async fn lookup_token_alias(
    context: &impl Namada,
    token: &Address,
    owner: &Address,
) -> String {
    match token {
        Address::Internal(InternalAddress::Erc20(eth_addr)) => {
            eth_addr.to_canonical()
        }
        Address::Internal(InternalAddress::IbcToken(_)) => {
            let ibc_denom =
                rpc::query_ibc_denom(context, token.to_string(), Some(owner))
                    .await;

            context.wallet().await.lookup_ibc_token_alias(ibc_denom)
        }
        _ => context
            .wallet()
            .await
            .find_alias(token)
            .map(|alias| alias.to_string())
            .unwrap_or(token.to_string()),
    }
}

/// Query votes for the given proposal
pub async fn query_proposal_votes(
    context: &impl Namada,
    args: args::QueryProposalVotes,
) {
    let result = namada_sdk::rpc::query_proposal_votes(
        context.client(),
        args.proposal_id,
    )
    .await
    .unwrap();

    match args.voter {
        Some(voter) => {
            match result.into_iter().find(|vote| vote.delegator == voter) {
                Some(vote) => display_line!(context.io(), "{}", vote,),
                None => display_line!(
                    context.io(),
                    "The address {} has not voted on proposal {}",
                    voter,
                    args.proposal_id
                ),
            }
        }
        None => {
            display_line!(
                context.io(),
                "Votes for proposal id {}\n",
                args.proposal_id
            );
            for vote in result {
                display_line!(context.io(), "{}\n", vote);
            }
        }
    }
}

/// Query Proposals
pub async fn query_proposal(context: &impl Namada, args: args::QueryProposal) {
    let current_epoch = query_and_print_epoch(context).await;

    if let Some(id) = args.proposal_id {
        let proposal =
            query_proposal_by_id(context.client(), id).await.unwrap();
        if let Some(proposal) = proposal {
            display_line!(
                context.io(),
                "{}",
                proposal.to_string_with_status(current_epoch)
            );
        } else {
            edisplay_line!(context.io(), "No proposal found with id: {}", id);
        }
    } else {
        let last_proposal_id_key = governance_storage::get_counter_key();
        let last_proposal_id: u64 =
            query_storage_value(context.client(), &last_proposal_id_key)
                .await
                .unwrap();

        let from_id = if last_proposal_id > 10 {
            last_proposal_id - 10
        } else {
            0
        };

        display_line!(context.io(), "id: {}", last_proposal_id);

        for id in from_id..last_proposal_id {
            let proposal = query_proposal_by_id(context.client(), id)
                .await
                .unwrap()
                .expect("Proposal should be written to storage.");
            display_line!(context.io(), "{}", proposal);
        }
    }
}

/// Query proposal by Id
pub async fn query_proposal_by_id<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    proposal_id: u64,
) -> Result<Option<StorageProposal>, error::Error> {
    namada_sdk::rpc::query_proposal_by_id(client, proposal_id).await
}

/// Query token shielded balance(s)
async fn query_shielded_balance(
    context: &impl Namada,
    args: args::QueryBalance,
) {
    let args::QueryBalance {
        // Token owner (needs to be a viewing key)
        owner,
        // The token to query
        token,
        // Used to control whether conversions are automatically performed
        no_conversions,
        ..
    } = args;

    let viewing_key = ExtendedFullViewingKey::from(
        owner
            .full_viewing_key()
            .expect("Balance owner should have been a masp full viewing key"),
    )
    .fvk
    .vk;

    // Pre-compute the masp asset types of `token`
    {
        let mut shielded = context.shielded_mut().await;
        let _ = shielded.load().await;
        let _ = shielded
            .precompute_asset_types(context.client(), vec![&token])
            .await;
        // Save the update state so that future fetches can be short-circuited
        let _ = shielded.save().await;
    }

    // The epoch is required to identify timestamped tokens
    let masp_epoch = query_and_print_masp_epoch(context).await;

    // Query the token alias in the wallet for pretty printing token balances
    let token_alias = lookup_token_alias(context, &token, &MASP).await;

    // Query the multi-asset balance at the given spending key
    let mut shielded = context.shielded_mut().await;

    let no_balance = || {
        display_line!(context.io(), "{token_alias}: 0");
    };

    let balance = if no_conversions {
        let Some(bal) = shielded
            .compute_shielded_balance(&viewing_key)
            .await
            .unwrap()
        else {
            no_balance();
            return;
        };
        bal
    } else {
        let Some(bal) = shielded
            .compute_exchanged_balance(
                context.client(),
                context.io(),
                &viewing_key,
                masp_epoch,
            )
            .await
            .unwrap()
        else {
            no_balance();
            return;
        };
        bal
    };

    let total_balance = shielded
        .decode_combine_sum_to_epoch(context.client(), balance, masp_epoch)
        .await
        .0
        .get(&token);

    if total_balance.is_zero() {
        no_balance();
    } else {
        display_line!(
            context.io(),
            "{}: {}",
            token_alias,
            context.format_amount(&token, total_balance.into()).await
        );
    }
}

pub async fn query_proposal_result(
    context: &impl Namada,
    args: args::QueryProposalResult,
) {
    let proposal_id = args.proposal_id;

    let current_epoch = query_epoch(context.client()).await.unwrap();
    let proposal_result =
        namada_sdk::rpc::query_proposal_result(context.client(), proposal_id)
            .await;
    let proposal_query =
        namada_sdk::rpc::query_proposal_by_id(context.client(), proposal_id)
            .await;

    if let (Ok(Some(proposal_result)), Ok(Some(proposal_query))) =
        (proposal_result, proposal_query)
    {
        display_line!(context.io(), "Proposal Id: {} ", proposal_id);
        if current_epoch >= proposal_query.voting_end_epoch {
            display_line!(context.io(), "{:4}{}", "", proposal_result);
        } else {
            display_line!(
                context.io(),
                "{:4}Still voting until epoch {} begins.",
                "",
                proposal_query.voting_end_epoch
            );
            let res = format!("{}", proposal_result);
            if let Some(idx) = res.find(' ') {
                let slice = &res[idx..];
                display_line!(context.io(), "{:4}Currently{}", "", slice);
            } else {
                display_line!(
                    context.io(),
                    "{:4}Error parsing the result string",
                    "",
                );
            }
        }
    } else {
        edisplay_line!(context.io(), "Proposal {} not found.", proposal_id);
    }
}

pub async fn query_account(context: &impl Namada, args: args::QueryAccount) {
    let account = rpc::get_account_info(context.client(), &args.owner)
        .await
        .unwrap();
    if let Some(account) = account {
        display_line!(context.io(), "Address: {}", account.address);
        display_line!(context.io(), "Threshold: {}", account.threshold);
        display_line!(context.io(), "Public keys:");
        for (public_key, _) in account.public_keys_map.pk_to_idx {
            display_line!(context.io(), "- {}", public_key);
        }
    } else {
        display_line!(context.io(), "No account exists for {}", args.owner);
    }
}

pub async fn query_pgf(context: &impl Namada, _args: args::QueryPgf) {
    let stewards = query_pgf_stewards(context.client()).await;
    let fundings = query_pgf_fundings(context.client()).await;

    match stewards.is_empty() {
        true => {
            display_line!(
                context.io(),
                "Pgf stewards: no stewards are currently set."
            )
        }
        false => {
            display_line!(context.io(), "Pgf stewards:");
            for steward in stewards {
                display_line!(context.io(), "{:4}- {}", "", steward.address);
                display_line!(context.io(), "{:4}  Reward distribution:", "");
                for (address, percentage) in steward.reward_distribution {
                    display_line!(
                        context.io(),
                        "{:6}- {} to {}",
                        "",
                        percentage,
                        address
                    );
                }
            }
        }
    }

    match fundings.is_empty() {
        true => {
            display_line!(
                context.io(),
                "Pgf fundings: no fundings are currently set."
            )
        }
        false => {
            display_line!(context.io(), "Pgf fundings:");
            for funding in fundings {
                display_line!(
                    context.io(),
                    "{:4}- {} for {}",
                    "",
                    funding.detail.target(),
                    funding.detail.amount().to_string_native()
                );
            }
        }
    }
}

pub async fn query_protocol_parameters(
    context: &impl Namada,
    _args: args::QueryProtocolParameters,
) {
    let governance_parameters =
        query_governance_parameters(context.client()).await;
    display_line!(context.io(), "\nGovernance Parameters");
    display_line!(
        context.io(),
        "{:4}Min. proposal fund: {}",
        "",
        governance_parameters.min_proposal_fund.to_string_native()
    );
    display_line!(
        context.io(),
        "{:4}Max. proposal code size: {}",
        "",
        governance_parameters.max_proposal_code_size
    );
    display_line!(
        context.io(),
        "{:4}Min. proposal voting period: {}",
        "",
        governance_parameters.min_proposal_voting_period
    );
    display_line!(
        context.io(),
        "{:4}Max. proposal period: {}",
        "",
        governance_parameters.max_proposal_period
    );
    display_line!(
        context.io(),
        "{:4}Max. proposal content size: {}",
        "",
        governance_parameters.max_proposal_content_size
    );
    display_line!(
        context.io(),
        "{:4}Min. proposal grace epochs: {}",
        "",
        governance_parameters.min_proposal_grace_epochs
    );

    let pgf_parameters = query_pgf_parameters(context.client()).await;
    display_line!(context.io(), "\nPublic Goods Funding Parameters");
    display_line!(
        context.io(),
        "{:4}Pgf inflation rate: {}",
        "",
        pgf_parameters.pgf_inflation_rate
    );
    display_line!(
        context.io(),
        "{:4}Steward inflation rate: {}",
        "",
        pgf_parameters.stewards_inflation_rate
    );

    display_line!(context.io(), "\nProtocol parameters");
    let key = param_storage::get_epoch_duration_storage_key();
    let epoch_duration: EpochDuration =
        query_storage_value(context.client(), &key)
            .await
            .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Min. epoch duration: {}",
        "",
        epoch_duration.min_duration
    );
    display_line!(
        context.io(),
        "{:4}Min. number of blocks: {}",
        "",
        epoch_duration.min_num_of_blocks
    );

    let key = param_storage::get_tx_allowlist_storage_key();
    let vp_allowlist: Vec<String> = query_storage_value(context.client(), &key)
        .await
        .expect("Parameter should be defined.");
    display_line!(context.io(), "{:4}VP allowlist: {:?}", "", vp_allowlist);

    let key = param_storage::get_tx_allowlist_storage_key();
    let tx_allowlist: Vec<String> = query_storage_value(context.client(), &key)
        .await
        .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Transactions allowlist: {:?}",
        "",
        tx_allowlist
    );

    let key = param_storage::get_max_block_gas_key();
    let max_block_gas: u64 = query_storage_value(context.client(), &key)
        .await
        .expect("Parameter should be defined.");
    display_line!(context.io(), "{:4}Max block gas: {:?}", "", max_block_gas);

    let key = param_storage::get_masp_fee_payment_gas_limit_key();
    let masp_fee_payment_gas_limit: u64 =
        query_storage_value(context.client(), &key)
            .await
            .expect("Parameter should be defined.");
    display_line!(
        context.io(),
        "{:4}Masp fee payment gas limit: {:?}",
        "",
        masp_fee_payment_gas_limit
    );

    let key = param_storage::get_gas_cost_key();
    let gas_cost_table: BTreeMap<Address, token::Amount> =
        query_storage_value(context.client(), &key)
            .await
            .expect("Parameter should be defined.");
    display_line!(context.io(), "{:4}Gas cost table:", "");
    for (token, gas_cost) in gas_cost_table {
        display_line!(context.io(), "{:8}{}: {:?}", "", token, gas_cost);
    }

    display_line!(context.io(), "PoS parameters");
    let pos_params = query_pos_parameters(context.client()).await;
    display_line!(
        context.io(),
        "{:4}Pipeline length: {}",
        "",
        pos_params.pipeline_len
    );
    display_line!(
        context.io(),
        "{:4}Unbonding length: {}",
        "",
        pos_params.unbonding_len
    );
    display_line!(
        context.io(),
        "{:4}Cubic slashing window length: {}",
        "",
        pos_params.cubic_slashing_window_length
    );
    display_line!(
        context.io(),
        "{:4}Max. consensus validator slots: {}",
        "",
        pos_params.max_validator_slots
    );
    display_line!(
        context.io(),
        "{:4}Validator stake threshold: {}",
        "",
        pos_params.validator_stake_threshold
    );
    display_line!(
        context.io(),
        "{:4}Duplicate vote minimum slash rate: {}",
        "",
        pos_params.duplicate_vote_min_slash_rate
    );
    display_line!(
        context.io(),
        "{:4}Light client attack minimum slash rate: {}",
        "",
        pos_params.light_client_attack_min_slash_rate
    );
    display_line!(
        context.io(),
        "{:4}Liveness window: {} blocks",
        "",
        pos_params.liveness_window_check
    );
    display_line!(
        context.io(),
        "{:4}Liveness threshold: {}",
        "",
        pos_params.liveness_threshold
    );
    display_line!(
        context.io(),
        "{:4}Block proposer reward: {}",
        "",
        pos_params.block_proposer_reward
    );
    display_line!(
        context.io(),
        "{:4}Block vote reward: {}",
        "",
        pos_params.block_vote_reward
    );
    display_line!(
        context.io(),
        "{:4}Max inflation rate: {}",
        "",
        pos_params.max_inflation_rate
    );
    display_line!(
        context.io(),
        "{:4}Target staked ratio: {}",
        "",
        pos_params.target_staked_ratio
    );
    display_line!(
        context.io(),
        "{:4}Inflation kP gain: {}",
        "",
        pos_params.rewards_gain_p
    );
    display_line!(
        context.io(),
        "{:4}Inflation kD gain: {}",
        "",
        pos_params.rewards_gain_d
    );
    display_line!(
        context.io(),
        "{:4}Votes per raw token: {}",
        "",
        pos_params.tm_votes_per_token
    );
}

pub async fn query_bond<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> token::Amount {
    unwrap_client_response::<C, token::Amount>(
        RPC.vp().pos().bond(client, source, validator, &epoch).await,
    )
}

pub async fn query_unbond_with_slashing<
    C: namada_sdk::queries::Client + Sync,
>(
    client: &C,
    source: &Address,
    validator: &Address,
) -> HashMap<(Epoch, Epoch), token::Amount> {
    unwrap_client_response::<C, HashMap<(Epoch, Epoch), token::Amount>>(
        RPC.vp()
            .pos()
            .unbond_with_slashing(client, source, validator)
            .await,
    )
}

pub async fn query_pos_parameters<C: namada_sdk::queries::Client + Sync>(
    client: &C,
) -> PosParams {
    unwrap_client_response::<C, PosParams>(
        RPC.vp().pos().pos_params(client).await,
    )
}

pub async fn query_consensus_keys<C: namada_sdk::queries::Client + Sync>(
    client: &C,
) -> BTreeSet<common::PublicKey> {
    unwrap_client_response::<C, BTreeSet<common::PublicKey>>(
        RPC.vp().pos().consensus_key_set(client).await,
    )
}

pub async fn query_pgf_stewards<C: namada_sdk::queries::Client + Sync>(
    client: &C,
) -> Vec<StewardDetail> {
    unwrap_client_response::<C, _>(RPC.vp().pgf().stewards(client).await)
}

pub async fn query_pgf_fundings<C: namada_sdk::queries::Client + Sync>(
    client: &C,
) -> Vec<StoragePgfFunding> {
    unwrap_client_response::<C, _>(RPC.vp().pgf().funding(client).await)
}

pub async fn query_pgf_parameters<C: namada_sdk::queries::Client + Sync>(
    client: &C,
) -> PgfParameters {
    unwrap_client_response::<C, _>(RPC.vp().pgf().parameters(client).await)
}

pub async fn query_and_print_unbonds(
    context: &impl Namada,
    source: &Address,
    validator: &Address,
) {
    let unbonds =
        query_unbond_with_slashing(context.client(), source, validator).await;
    let current_epoch = query_epoch(context.client()).await.unwrap();

    let mut total_withdrawable = token::Amount::zero();
    let mut not_yet_withdrawable = HashMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        if withdraw_epoch <= current_epoch {
            total_withdrawable =
                total_withdrawable.checked_add(amount).unwrap();
        } else {
            let withdrawable_amount =
                not_yet_withdrawable.entry(withdraw_epoch).or_default();
            *withdrawable_amount =
                withdrawable_amount.checked_add(amount).unwrap();
        }
    }
    if !total_withdrawable.is_zero() {
        display_line!(
            context.io(),
            "Total withdrawable now: {}.",
            total_withdrawable.to_string_native()
        );
    }
    if !not_yet_withdrawable.is_empty() {
        display_line!(context.io(), "Current epoch: {current_epoch}.");
    }
    for (withdraw_epoch, amount) in not_yet_withdrawable {
        display_line!(
            context.io(),
            "Amount {} withdrawable starting from epoch {withdraw_epoch}.",
            amount.to_string_native(),
        );
    }
}

pub async fn query_withdrawable_tokens<
    C: namada_sdk::queries::Client + Sync,
>(
    client: &C,
    bond_source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> token::Amount {
    unwrap_client_response::<C, token::Amount>(
        RPC.vp()
            .pos()
            .withdrawable_tokens(client, bond_source, validator, &epoch)
            .await,
    )
}

/// Query PoS bond(s) and unbond(s)
pub async fn query_bonds(
    context: &impl Namada,
    args: args::QueryBonds,
) -> std::io::Result<()> {
    let epoch = query_and_print_epoch(context).await;

    let source = args.owner;
    let validator = args.validator;

    let stdout = io::stdout();
    let mut w = stdout.lock();

    let bonds_and_unbonds = enriched_bonds_and_unbonds(
        context.client(),
        epoch,
        &source,
        &validator,
    )
    .await
    .unwrap();

    for (bond_id, details) in &bonds_and_unbonds.data {
        let bond_type = if bond_id.source == bond_id.validator {
            format!("Self-bonds from {}", bond_id.validator)
        } else {
            format!(
                "Delegations from {} to {}",
                bond_id.source, bond_id.validator
            )
        };
        display_line!(context.io(), &mut w; "{}:", bond_type)?;
        for bond in &details.data.bonds {
            display_line!(
                context.io(),
                &mut w;
                "  Remaining active bond from epoch {}: Δ {} (slashed {})",
                bond.start,
                bond.amount.to_string_native(),
                bond.slashed_amount.unwrap_or_default().to_string_native()
            )?;
        }
        if !details.bonds_total.is_zero() {
            display_line!(
                context.io(),
                &mut w;
                "Active (slashable) bonds total: {}",
                details.bonds_total_active().unwrap().to_string_native()
            )?;
        }
        display_line!(context.io(), &mut w; "Bonds total: {}", details.bonds_total.to_string_native())?;
        display_line!(context.io(), &mut w; "")?;

        if !details.data.unbonds.is_empty() {
            let bond_type = if bond_id.source == bond_id.validator {
                format!("Unbonded self-bonds from {}", bond_id.validator)
            } else {
                format!("Unbonded delegations from {}", bond_id.source)
            };
            display_line!(context.io(), &mut w; "{}:", bond_type)?;
            for unbond in &details.data.unbonds {
                display_line!(
                    context.io(),
                    &mut w;
                    "  Withdrawable from epoch {} (active from {}): Δ {} (slashed {})",
                    unbond.withdraw,
                    unbond.start,
                    unbond.amount.to_string_native(),
                    unbond.slashed_amount.unwrap_or_default().to_string_native()
                )?;
            }
            display_line!(
                context.io(),
                &mut w;
                "Unbonded total: {}",
                details.unbonds_total.to_string_native()
            )?;
        }
        display_line!(
            context.io(),
            &mut w;
            "Withdrawable total: {}",
            details.total_withdrawable.to_string_native()
        )?;
        display_line!(context.io(), &mut w; "")?;
    }
    if bonds_and_unbonds.bonds_total != bonds_and_unbonds.bonds_total_slashed {
        display_line!(
            context.io(),
            &mut w;
            "All bonds total active: {}",
            bonds_and_unbonds.bonds_total_active().unwrap().to_string_native()
        )?;
    }
    display_line!(
        context.io(),
        &mut w;
        "All bonds total: {}",
        bonds_and_unbonds.bonds_total.to_string_native()
    )?;
    display_line!(
        context.io(),
        &mut w;
        "All bonds total slashed: {}",
        bonds_and_unbonds.bonds_total_slashed.to_string_native()
    )?;

    if bonds_and_unbonds.unbonds_total
        != bonds_and_unbonds.unbonds_total_slashed
    {
        display_line!(
            context.io(),
            &mut w;
            "All unbonds total active: {}",
            bonds_and_unbonds.unbonds_total_active().unwrap().to_string_native()
        )?;
    }
    display_line!(
        context.io(),
        &mut w;
        "All unbonds total: {}",
        bonds_and_unbonds.unbonds_total.to_string_native()
    )?;
    display_line!(
        context.io(),
        &mut w;
        "All unbonds total withdrawable: {}",
        bonds_and_unbonds.total_withdrawable.to_string_native()
    )?;
    display_line!(
        context.io(),
        &mut w;
        "All unbonds total slashed: {}",
        bonds_and_unbonds.unbonds_total_slashed.to_string_native()
    )?;
    Ok(())
}

/// Query PoS bonded stake
pub async fn query_bonded_stake<N: Namada>(
    context: &N,
    args: args::QueryBondedStake,
) {
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => query_and_print_epoch(context).await,
    };

    match args.validator {
        Some(validator) => {
            // Find bonded stake for the given validator
            let stake =
                get_validator_stake(context.client(), epoch, &validator).await;
            match stake {
                Some(stake) => {
                    display_line!(
                        context.io(),
                        "Bonded stake of validator {validator}: {}",
                        stake.to_string_native()
                    );
                    query_and_print_validator_state(
                        context,
                        args::QueryValidatorState {
                            query: args.query,
                            validator,
                            epoch: args.epoch,
                        },
                    )
                    .await;
                }
                None => {
                    display_line!(
                        context.io(),
                        "No bonded stake found for {validator}"
                    );
                }
            }
        }
        None => {
            let consensus: BTreeSet<WeightedValidator> =
                unwrap_client_response::<N::Client, _>(
                    RPC.vp()
                        .pos()
                        .consensus_validator_set(context.client(), &Some(epoch))
                        .await,
                );
            let below_capacity: BTreeSet<WeightedValidator> =
                unwrap_client_response::<N::Client, _>(
                    RPC.vp()
                        .pos()
                        .below_capacity_validator_set(
                            context.client(),
                            &Some(epoch),
                        )
                        .await,
                );

            // Iterate all validators
            let stdout = io::stdout();
            let mut w = stdout.lock();

            display_line!(context.io(), &mut w; "Consensus validators:")
                .unwrap();
            for val in consensus.into_iter().rev() {
                display_line!(
                    context.io(),
                    &mut w;
                    "  {}: {}",
                    val.address.encode(),
                    val.bonded_stake.to_string_native()
                )
                .unwrap();
            }
            if !below_capacity.is_empty() {
                display_line!(context.io(), &mut w; "Below capacity validators:")
                    .unwrap();
                for val in below_capacity.into_iter().rev() {
                    display_line!(
                        context.io(),
                        &mut w;
                        "  {}: {}",
                        val.address.encode(),
                        val.bonded_stake.to_string_native()
                    )
                    .unwrap();
                }
            }
        }
    }

    let total_staked_tokens =
        get_total_staked_tokens(context.client(), epoch).await;
    display_line!(
        context.io(),
        "Total bonded stake: {}",
        total_staked_tokens.to_string_native()
    );
}

/// Query and return validator's commission rate and max commission rate change
/// per epoch
pub async fn query_commission_rate<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> CommissionPair {
    unwrap_client_response::<C, CommissionPair>(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )
}

/// Query and return validator's metadata
pub async fn query_metadata<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    validator: &Address,
) -> Option<ValidatorMetaData> {
    unwrap_client_response::<C, Option<ValidatorMetaData>>(
        RPC.vp().pos().validator_metadata(client, validator).await,
    )
}

/// Query and return validator's state
pub async fn query_validator_state<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> ValidatorStateInfo {
    unwrap_client_response::<C, ValidatorStateInfo>(
        RPC.vp()
            .pos()
            .validator_state(client, validator, &epoch)
            .await,
    )
}

/// Query and return the available reward tokens corresponding to the bond
pub async fn query_rewards<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    source: &Option<Address>,
    validator: &Address,
) -> token::Amount {
    unwrap_client_response::<C, token::Amount>(
        RPC.vp().pos().rewards(client, validator, source).await,
    )
}

/// Query a validator's state information
pub async fn query_and_print_validator_state(
    context: &impl Namada,
    args: args::QueryValidatorState,
) {
    let validator = args.validator;
    let (state, epoch): ValidatorStateInfo =
        query_validator_state(context.client(), &validator, args.epoch).await;

    match state {
        Some(state) => match state {
            ValidatorState::Consensus => {
                display_line!(
                    context.io(),
                    "Validator {validator} is in the consensus set in epoch \
                     {epoch}"
                )
            }
            ValidatorState::BelowCapacity => {
                display_line!(
                    context.io(),
                    "Validator {validator} is in the below-capacity set in \
                     epoch {epoch}"
                )
            }
            ValidatorState::BelowThreshold => {
                display_line!(
                    context.io(),
                    "Validator {validator} is in the below-threshold set in \
                     epoch {epoch}"
                )
            }
            ValidatorState::Inactive => {
                display_line!(
                    context.io(),
                    "Validator {validator} is inactive in epoch {epoch}"
                )
            }
            ValidatorState::Jailed => {
                display_line!(
                    context.io(),
                    "Validator {validator} is jailed in epoch {epoch}"
                )
            }
        },
        None => display_line!(
            context.io(),
            "Validator {validator} not found in epoch {epoch}. This account \
             may not be a validator, or the validator account has been \
             recently initialized and may not be active yet. It is also \
             possible that this data is no longer available in storage if an \
             epoch before the current epoch has been queried."
        ),
    }
}

/// Query PoS validator's commission rate information
pub async fn query_and_print_commission_rate(
    context: &impl Namada,
    args: args::QueryCommissionRate,
) {
    let validator = args.validator;

    let CommissionPair {
        commission_rate,
        max_commission_change_per_epoch,
        epoch: query_epoch,
    } = query_commission_rate(context.client(), &validator, args.epoch).await;
    match (commission_rate, max_commission_change_per_epoch) {
        (Some(commission_rate), Some(max_commission_change_per_epoch)) => {
            display_line!(
                context.io(),
                "Validator {validator} commission rate: {commission_rate}, \
                 max change per epoch: {max_commission_change_per_epoch} in \
                 epoch {query_epoch}"
            )
        }
        (None, None) => display_line!(
            context.io(),
            "Validator {validator} not found in epoch {query_epoch}. This \
             account may not be a validator, or the validator account has \
             been recently initialized and may not be active yet. It is also \
             possible that this data is no longer available in storage if an \
             epoch before the current epoch has been queried."
        ),
        _ => display_line!(
            context.io(),
            "Only one of the commission rate and max commission change per \
             epoch was found for validator {validator} in epoch \
             {query_epoch}. This is a bug and should be reported."
        ),
    }
}

/// Query PoS validator's metadata
pub async fn query_and_print_metadata(
    context: &impl Namada,
    args: args::QueryMetaData,
) {
    let validator = args.validator;

    let metadata: Option<ValidatorMetaData> =
        query_metadata(context.client(), &validator).await;

    match metadata {
        Some(ValidatorMetaData {
            email,
            description,
            website,
            discord_handle,
            avatar,
            name,
        }) => {
            display_line!(
                context.io(),
                "Validator {} metadata:",
                validator.encode()
            );
            if let Some(name) = name {
                display_line!(context.io(), "Validator name: {}", name);
            } else {
                display_line!(context.io(), "No validator name");
            }
            display_line!(context.io(), "Email: {}", email);
            if let Some(description) = description {
                display_line!(context.io(), "Description: {}", description);
            } else {
                display_line!(context.io(), "No description");
            }
            if let Some(website) = website {
                display_line!(context.io(), "Website: {}", website);
            } else {
                display_line!(context.io(), "No website");
            }
            if let Some(discord_handle) = discord_handle {
                display_line!(
                    context.io(),
                    "Discord handle: {}",
                    discord_handle
                );
            } else {
                display_line!(context.io(), "No discord handle");
            }
            if let Some(avatar) = avatar {
                display_line!(context.io(), "Avatar: {}", avatar);
            } else {
                display_line!(context.io(), "No avatar");
            }
        }
        None => display_line!(
            context.io(),
            "Validator {} does not have an email set and may not exist",
            validator.encode()
        ),
    }

    // Get commission rate info for the current epoch
    let CommissionPair {
        commission_rate,
        max_commission_change_per_epoch,
        epoch: query_epoch,
    } = query_commission_rate(context.client(), &validator, None).await;
    match (commission_rate, max_commission_change_per_epoch) {
        (Some(commission_rate), Some(max_commission_change_per_epoch)) => {
            display_line!(
                context.io(),
                "Validator {validator} commission rate: {commission_rate}, \
                 max change per epoch: {max_commission_change_per_epoch} in \
                 epoch {query_epoch}"
            )
        }
        (None, None) => display_line!(
            context.io(),
            "Validator {validator} not found in epoch {query_epoch}. This \
             account may not be a validator, or the validator account has \
             been recently initialized and may not be active yet. It is also \
             possible that this data is no longer available in storage if an \
             epoch before the current epoch has been queried."
        ),
        _ => display_line!(
            context.io(),
            "Only one of the commission rate and max commission change per \
             epoch was found for validator {validator} in epoch \
             {query_epoch}. This is a bug and should be reported."
        ),
    }
}

/// Query PoS slashes
pub async fn query_slashes<N: Namada>(context: &N, args: args::QuerySlashes) {
    match args.validator {
        Some(validator) => {
            // Find slashes for the given validator
            let slashes: Vec<Slash> = unwrap_client_response::<N::Client, _>(
                RPC.vp()
                    .pos()
                    .validator_slashes(context.client(), &validator)
                    .await,
            );
            if !slashes.is_empty() {
                display_line!(context.io(), "Processed slashes:");
                let stdout = io::stdout();
                let mut w = stdout.lock();
                for slash in slashes {
                    display_line!(
                        context.io(),
                        &mut w;
                        "Infraction epoch {}, block height {}, type {}, rate \
                         {}",
                        slash.epoch,
                        slash.block_height,
                        slash.r#type,
                        slash.rate
                    )
                    .unwrap();
                }
            } else {
                display_line!(
                    context.io(),
                    "No processed slashes found for {}",
                    validator.encode()
                )
            }
            // Find enqueued slashes to be processed in the future for the given
            // validator
            let enqueued_slashes: HashMap<
                Address,
                BTreeMap<Epoch, Vec<Slash>>,
            > = unwrap_client_response::<N::Client, _>(
                RPC.vp().pos().enqueued_slashes(context.client()).await,
            );
            let enqueued_slashes = enqueued_slashes.get(&validator).cloned();
            if let Some(enqueued) = enqueued_slashes {
                display_line!(
                    context.io(),
                    "\nEnqueued slashes for future processing"
                );
                for (epoch, slashes) in enqueued {
                    display_line!(
                        context.io(),
                        "To be processed in epoch {}",
                        epoch
                    );
                    for slash in slashes {
                        let stdout = io::stdout();
                        let mut w = stdout.lock();
                        display_line!(
                            context.io(),
                            &mut w;
                            "Infraction epoch {}, block height {}, type {}",
                            slash.epoch, slash.block_height, slash.r#type,
                        )
                        .unwrap();
                    }
                }
            } else {
                display_line!(
                    context.io(),
                    "No enqueued slashes found for {}",
                    validator.encode()
                )
            }
        }
        None => {
            let all_slashes: HashMap<Address, Vec<Slash>> =
                unwrap_client_response::<N::Client, _>(
                    RPC.vp().pos().slashes(context.client()).await,
                );

            if !all_slashes.is_empty() {
                let stdout = io::stdout();
                let mut w = stdout.lock();
                display_line!(context.io(), "Processed slashes:");
                for (validator, slashes) in all_slashes.into_iter() {
                    for slash in slashes {
                        display_line!(
                            context.io(),
                            &mut w;
                            "Infraction epoch {}, block height {}, rate {}, \
                             type {}, validator {}",
                            slash.epoch,
                            slash.block_height,
                            slash.rate,
                            slash.r#type,
                            validator,
                        )
                        .unwrap();
                    }
                }
            } else {
                display_line!(context.io(), "No processed slashes found")
            }

            // Find enqueued slashes to be processed in the future for the given
            // validator
            let enqueued_slashes: HashMap<
                Address,
                BTreeMap<Epoch, Vec<Slash>>,
            > = unwrap_client_response::<N::Client, _>(
                RPC.vp().pos().enqueued_slashes(context.client()).await,
            );
            if !enqueued_slashes.is_empty() {
                display_line!(
                    context.io(),
                    "\nEnqueued slashes for future processing"
                );
                for (validator, slashes_by_epoch) in enqueued_slashes {
                    for (epoch, slashes) in slashes_by_epoch {
                        display_line!(
                            context.io(),
                            "\nTo be processed in epoch {}",
                            epoch
                        );
                        for slash in slashes {
                            let stdout = io::stdout();
                            let mut w = stdout.lock();
                            display_line!(
                                context.io(),
                                &mut w;
                                "Infraction epoch {}, block height {}, type \
                                 {}, validator {}",
                                slash.epoch,
                                slash.block_height,
                                slash.r#type,
                                validator
                            )
                            .unwrap();
                        }
                    }
                }
            } else {
                display_line!(
                    context.io(),
                    "\nNo enqueued slashes found for future processing"
                )
            }
        }
    }
}

pub async fn query_and_print_rewards<N: Namada>(
    context: &N,
    args: args::QueryRewards,
) {
    let (source, validator) = (args.source, args.validator);

    let rewards = query_rewards(context.client(), &source, &validator).await;
    display_line!(
        context.io(),
        "Current rewards available for claim: {} NAM",
        rewards.to_string_native()
    );
}

pub async fn query_delegations<N: Namada>(
    context: &N,
    args: args::QueryDelegations,
) {
    let owner = args.owner;
    let delegations: HashSet<Address> = unwrap_client_response::<N::Client, _>(
        RPC.vp()
            .pos()
            .delegation_validators(context.client(), &owner, &None)
            .await,
    );
    if delegations.is_empty() {
        display_line!(
            context.io(),
            "No delegations found active in the current epoch"
        );
    } else {
        display_line!(
            context.io(),
            "Found delegations in the current epoch to:"
        );
        for delegation in delegations {
            display_line!(context.io(), "  {delegation}");
        }
    }
}

pub async fn query_find_validator<N: Namada>(
    context: &N,
    args: args::QueryFindValidator,
) {
    let args::QueryFindValidator {
        query: _,
        tm_addr,
        mut validator_addr,
    } = args;
    if let Some(tm_addr) = tm_addr {
        if tm_addr.len() != 40 {
            edisplay_line!(
                context.io(),
                "Expected 40 characters in Tendermint address, got {}",
                tm_addr.len()
            );
            cli::safe_exit(1);
        }
        let tm_addr = tm_addr.to_ascii_uppercase();
        let validator = unwrap_client_response::<N::Client, _>(
            RPC.vp()
                .pos()
                .validator_by_tm_addr(context.client(), &tm_addr)
                .await,
        );
        match validator {
            Some(address) => {
                display_line!(
                    context.io(),
                    "Found validator address \"{address}\"."
                );
                if validator_addr.is_none() {
                    validator_addr = Some(address);
                }
            }
            None => {
                display_line!(
                    context.io(),
                    "No validator with Tendermint address {tm_addr} found."
                )
            }
        }
    }
    if let Some(validator_addr) = validator_addr {
        if let Some(consensus_key) = unwrap_client_response::<N::Client, _>(
            RPC.vp()
                .pos()
                .consensus_key(context.client(), &validator_addr)
                .await,
        ) {
            let pkh: PublicKeyHash = (&consensus_key).into();
            display_line!(context.io(), "Consensus key: {consensus_key}");
            display_line!(
                context.io(),
                "Tendermint key: {}",
                tm_consensus_key_raw_hash(&consensus_key)
            );
            display_line!(context.io(), "Consensus key hash: {}", pkh);
        } else {
            display_line!(
                context.io(),
                "Consensus key for validator {validator_addr} could not be \
                 found."
            )
        }
    }
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
    index: u8,
) -> Result<Option<common::PublicKey>, error::Error> {
    rpc::get_public_key_at(client, address, index).await
}

/// Check if the given address has any bonds.
pub async fn is_validator<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::is_validator(client, address)
        .await
        .unwrap()
}

/// Check if a given address is a known delegator
pub async fn is_delegator<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::is_delegator(client, address)
        .await
        .unwrap()
}

pub async fn is_delegator_at<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> bool {
    namada_sdk::rpc::is_delegator_at(client, address, epoch)
        .await
        .unwrap()
}

/// Check if the given address has any bonds.
pub async fn has_bonds<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::has_bonds(client, address).await.unwrap()
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    namada_sdk::rpc::known_address(client, address)
        .await
        .unwrap()
}

/// Query for all conversions.
pub async fn query_conversions(
    context: &impl Namada,
    args: args::QueryConversions,
) {
    // The chosen token type of the conversions
    let target_token = args.token;

    if target_token.as_ref().is_none() {
        // Query and print the total rewards first
        let total_rewards = rpc::query_masp_total_rewards(context.client())
            .await
            .expect("MASP total rewards should be present");
        display!(
            context.io(),
            "Total rewards of native token minted for shielded pool: {}",
            total_rewards.to_string_native()
        );
    }

    // To facilitate human readable token addresses
    let tokens = context
        .wallet()
        .await
        .get_addresses_with_vp_type(AddressVpType::Token);
    let conversions = rpc::query_conversions(context.client())
        .await
        .expect("Conversions should be defined");
    // Track whether any non-sentinel conversions are found
    let mut conversions_found = false;
    for (addr, _denom, digit, epoch, amt) in conversions.values() {
        // If the user has specified any targets, then meet them
        // If we have a sentinel conversion, then skip printing
        if matches!(&target_token, Some(target) if target != addr)
            || matches!(&args.epoch, Some(target) if target != epoch)
            || amt.is_zero()
        {
            continue;
        }
        conversions_found = true;
        // Print the asset to which the conversion applies
        display!(
            context.io(),
            "{}*2^{}[{}]: ",
            tokens.get(addr).cloned().unwrap_or_else(|| addr.clone()),
            *digit as u8 * 64,
            epoch,
        );
        // Now print out the components of the allowed conversion
        let mut prefix = "";
        for (asset_type, val) in amt.components() {
            // Look up the address and epoch of asset to facilitate pretty
            // printing
            let (addr, _denom, digit, epoch, _) = &conversions[asset_type];
            // Now print out this component of the conversion
            display!(
                context.io(),
                "{}{} {}*2^{}[{}]",
                prefix,
                val,
                tokens.get(addr).cloned().unwrap_or_else(|| addr.clone()),
                *digit as u8 * 64,
                epoch
            );
            // Future iterations need to be prefixed with +
            prefix = " + ";
        }
        // Allowed conversions are always implicit equations
        display_line!(context.io(), " = 0");
    }
    if !conversions_found {
        display_line!(
            context.io(),
            "No conversions found satisfying specified criteria."
        );
    }
}

/// Query a conversion.
pub async fn query_conversion<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    asset_type: AssetType,
) -> Option<(
    Address,
    token::Denomination,
    MaspDigitPos,
    MaspEpoch,
    I128Sum,
    MerklePath<Node>,
)> {
    namada_sdk::rpc::query_conversion(client, asset_type).await
}

/// Query to read the tokens that earn masp rewards.
pub async fn query_masp_reward_tokens(context: &impl Namada) {
    let tokens = namada_sdk::rpc::query_masp_reward_tokens(context.client())
        .await
        .expect("The tokens that may earn MASP rewards should be defined");
    display_line!(context.io(), "The following tokens may earn MASP rewards:");
    for MaspTokenRewardData {
        name,
        address,
        max_reward_rate,
        kp_gain,
        kd_gain,
        locked_amount_target,
    } in tokens
    {
        display_line!(context.io(), "{}: {}", name, address);
        display_line!(context.io(), "  Max reward rate: {}", max_reward_rate);
        display_line!(context.io(), "  Kp gain: {}", kp_gain);
        display_line!(context.io(), "  Kd gain: {}", kd_gain);
        display_line!(
            context.io(),
            "  Locked amount target: {}",
            locked_amount_target
        );
    }
}

/// Query a wasm code hash
pub async fn query_wasm_code_hash(
    context: &impl Namada,
    code_path: impl AsRef<str>,
) -> Result<Hash, error::Error> {
    rpc::query_wasm_code_hash(context, code_path).await
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<C: namada_sdk::queries::Client + Sync, T>(
    client: &C,
    key: &storage::Key,
) -> Result<T, error::Error>
where
    T: BorshDeserialize,
{
    namada_sdk::rpc::query_storage_value(client, key).await
}

/// Query a storage value and the proof without decoding.
pub async fn query_storage_value_bytes<
    C: namada_sdk::queries::Client + Sync,
>(
    client: &C,
    key: &storage::Key,
    height: Option<BlockHeight>,
    prove: bool,
) -> (Option<Vec<u8>>, Option<ProofOps>) {
    namada_sdk::rpc::query_storage_value_bytes(client, key, height, prove)
        .await
        .unwrap()
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<'b, T>(
    context: &'b impl Namada,
    key: &storage::Key,
) -> Option<impl 'b + Iterator<Item = (storage::Key, T)>>
where
    T: BorshDeserialize,
{
    rpc::query_storage_prefix(context, key).await.unwrap()
}

/// Query to check if the given storage key exists.
pub async fn query_has_storage_key<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    key: &storage::Key,
) -> bool {
    namada_sdk::rpc::query_has_storage_key(client, key)
        .await
        .unwrap()
}

/// Call the corresponding `tx_event_query` RPC method, to fetch
/// the current status of a transaction.
pub async fn query_tx_events<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    tx_event_query: namada_sdk::rpc::TxEventQuery<'_>,
) -> std::result::Result<Option<Event>, <C as namada_sdk::queries::Client>::Error>
{
    namada_sdk::rpc::query_tx_events(client, tx_event_query).await
}

/// Lookup the results of applying the specified transaction to the
/// blockchain.
pub async fn query_result(context: &impl Namada, args: args::QueryResult) {
    display_line!(
        context.io(),
        "Checking if tx {} is applied...",
        args.tx_hash
    );

    match rpc::query_tx_status(
        context,
        namada_sdk::rpc::TxEventQuery::Applied(&args.tx_hash),
        Instant::now() + Duration::from_secs(10),
    )
    .await
    {
        Ok(resp) => {
            let resp = match TxResponse::try_from(resp) {
                Ok(resp) => resp,
                Err(err) => {
                    edisplay_line!(context.io(), "{err}");
                    cli::safe_exit(1)
                }
            };
            display_batch_resp(context, &resp);
        }
        Err(err) => {
            // Print the errors that caused the lookups to fail
            edisplay_line!(context.io(), "{}", err);
            cli::safe_exit(1)
        }
    }
}

pub async fn epoch_sleep(context: &impl Namada, _args: args::Query) {
    let start_epoch = query_and_print_epoch(context).await;
    loop {
        tokio::time::sleep(core::time::Duration::from_secs(1)).await;
        let current_epoch = query_epoch(context.client()).await.unwrap();
        if current_epoch > start_epoch {
            display_line!(context.io(), "Reached epoch {}", current_epoch);
            break;
        }
    }
}

pub async fn get_bond_amount_at<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Option<token::Amount> {
    let total_active = unwrap_client_response::<C, token::Amount>(
        RPC.vp()
            .pos()
            .bond_with_slashing(client, delegator, validator, &Some(epoch))
            .await,
    );
    Some(total_active)
}

pub async fn get_all_validators<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> HashSet<Address> {
    namada_sdk::rpc::get_all_validators(client, epoch)
        .await
        .unwrap()
}

pub async fn get_total_staked_tokens<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> token::Amount {
    namada_sdk::rpc::get_total_staked_tokens(client, epoch)
        .await
        .unwrap()
}

/// Get the total stake of a validator at the given epoch. The total stake is a
/// sum of validator's self-bonds and delegations to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::zero())`.
async fn get_validator_stake<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
    validator: &Address,
) -> Option<token::Amount> {
    unwrap_client_response::<C, Option<token::Amount>>(
        RPC.vp()
            .pos()
            .validator_stake(client, validator, &Some(epoch))
            .await,
    )
}

pub async fn get_delegation_validators<
    C: namada_sdk::queries::Client + Sync,
>(
    client: &C,
    address: &Address,
) -> HashSet<Address> {
    let epoch = namada_sdk::rpc::query_epoch(client).await.unwrap();
    namada_sdk::rpc::get_delegation_validators(client, address, epoch)
        .await
        .unwrap()
}

pub async fn get_delegations_of_delegator_at<
    C: namada_sdk::queries::Client + Sync,
>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> HashMap<Address, token::Amount> {
    namada_sdk::rpc::get_delegations_of_delegator_at(client, address, epoch)
        .await
        .unwrap()
}

pub async fn query_governance_parameters<
    C: namada_sdk::queries::Client + Sync,
>(
    client: &C,
) -> GovernanceParameters {
    namada_sdk::rpc::query_governance_parameters(client).await
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<C: namada_sdk::queries::Client, T>(
    response: Result<T, C::Error>,
) -> T {
    response.unwrap_or_else(|err| {
        eprintln!("Error in the query: {:?}", err);
        cli::safe_exit(1)
    })
}

pub async fn compute_proposal_votes<C: namada_sdk::queries::Client + Sync>(
    client: &C,
    proposal_id: u64,
    epoch: Epoch,
) -> ProposalVotes {
    let votes = namada_sdk::rpc::query_proposal_votes(client, proposal_id)
        .await
        .unwrap();

    let mut validators_vote: HashMap<Address, ProposalVote> =
        HashMap::default();
    let mut validator_voting_power: HashMap<Address, VotePower> =
        HashMap::default();
    let mut delegators_vote: HashMap<Address, ProposalVote> =
        HashMap::default();
    let mut delegator_voting_power: HashMap<
        Address,
        HashMap<Address, VotePower>,
    > = HashMap::default();

    for vote in votes {
        if vote.is_validator() {
            let validator_stake =
                get_validator_stake(client, epoch, &vote.validator.clone())
                    .await
                    .unwrap_or_default();

            validators_vote.insert(vote.validator.clone(), vote.data);
            validator_voting_power.insert(vote.validator, validator_stake);
        } else {
            let delegator_stake = get_bond_amount_at(
                client,
                &vote.delegator,
                &vote.validator,
                epoch,
            )
            .await;

            if let Some(stake) = delegator_stake {
                delegators_vote.insert(vote.delegator.clone(), vote.data);
                delegator_voting_power
                    .entry(vote.delegator.clone())
                    .or_default()
                    .insert(vote.validator, stake);
            } else {
                continue;
            }
        }
    }

    ProposalVotes {
        validators_vote,
        validator_voting_power,
        delegators_vote,
        delegator_voting_power,
    }
}
