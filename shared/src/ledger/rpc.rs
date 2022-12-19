use crate::tendermint_rpc::Client;
use crate::types::storage::Epoch;
use crate::ledger::queries::RPC;
use crate::types::storage::BlockResults;
use std::collections::HashMap;
use crate::types::token;
use namada_core::types::address::Address;
use borsh::BorshDeserialize;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use crate::types::storage::{
    BlockHeight, PrefixValue,
};
use crate::tendermint::merkle::proof::Proof;
use crate::ledger::pos::{
    self, BondId, Bonds, Slash,
};
use crate::types::storage;
use masp_primitives::sapling::Node;
use crate::types::token::balance_key;
use crate::types::key::*;
use crate::ledger::events::Event;
use crate::types::hash::Hash;
use crate::tendermint_rpc::query::Query;
use crate::proto::Tx;
use serde::Serialize;
use crate::tendermint_rpc::error::Error as TError;
use crate::tendermint_rpc::Order;
use crate::types::governance::VotePower;
use crate::types::governance::ProposalVote;
use crate::ledger::native_vp::governance::utils::Votes;
use crate::ledger::governance::storage as gov_storage;
use std::collections::HashSet;
use crate::ledger::governance::parameters::GovParams;
use crate::types::governance::ProposalResult;
use crate::types::governance::TallyResult;
use itertools::Itertools;
use crate::ledger::pos::types::decimal_mult_u64;
use tokio::time::{Duration, Instant};

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    status: TxEventQuery<'_>,
    deadline: Instant,
) -> Event {
    const ONE_SECOND: Duration = Duration::from_secs(1);
    // sleep for the duration of `backoff`,
    // and update the underlying value
    async fn sleep_update(query: TxEventQuery<'_>, backoff: &mut Duration) {
        tracing::debug!(
            ?query,
            duration = ?backoff,
            "Retrying tx status query after timeout",
        );
        // simple linear backoff - if an event is not available,
        // increase the backoff duration by one second
        tokio::time::sleep(*backoff).await;
        *backoff += ONE_SECOND;
    }
    tokio::time::timeout_at(deadline, async move {
        let mut backoff = ONE_SECOND;

        loop {
            tracing::debug!(query = ?status, "Querying tx status");
            let maybe_event = match query_tx_events(client, status).await {
                Ok(response) => response,
                Err(err) => {
                    //tracing::debug!(%err, "ABCI query failed");
                    sleep_update(status, &mut backoff).await;
                    continue;
                }
            };
            if let Some(e) = maybe_event {
                break Ok(e);
            }
            sleep_update(status, &mut backoff).await;
        }
    })
    .await
    .map_err(|_| {
        eprintln!("Transaction status query deadline of {deadline:?} exceeded");
    })
    .and_then(|result| result)
    .unwrap_or_else(|_| panic!())
}

/// Query the epoch of the last committed block
pub async fn query_epoch<C: Client + crate::ledger::queries::Client + Sync>(client: &C) -> Epoch {
    let epoch = unwrap_client_response::<C, _>(RPC.shell().epoch(client).await);
    println!("Last committed epoch: {}", epoch);
    epoch
}

/// Query the last committed block
pub async fn query_block<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
) -> crate::tendermint_rpc::endpoint::block::Response {
    let response = client.latest_block().await.unwrap();
    println!(
        "Last committed block ID: {}, height: {}, time: {}",
        response.block_id,
        response.block.header.height,
        response.block.header.time
    );
    response
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<C: crate::ledger::queries::Client, T>(response: Result<T, C::Error>) -> T {
    response.unwrap_or_else(|err| {
        panic!("Error in the query");
    })
}

/// Query the results of the last committed block
pub async fn query_results<C: Client + crate::ledger::queries::Client + Sync>(client: &C) -> Vec<BlockResults> {
    unwrap_client_response::<C, _>(RPC.shell().read_results(client).await)
}

/// Query token amount of owner.
pub async fn get_token_balance<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    token: &Address,
    owner: &Address,
) -> Option<token::Amount> {
    let balance_key = balance_key(token, owner);
    query_storage_value(client, &balance_key).await
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> Option<common::PublicKey> {
    let key = pk_key(address);
    query_storage_value(client, &key).await
}

/// Check if the given address is a known validator.
pub async fn is_validator<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    unwrap_client_response::<C, _>(RPC.vp().pos().is_validator(client, address).await)
}

/// Check if a given address is a known delegator
pub async fn is_delegator<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    let bonds_prefix = pos::bonds_for_source_prefix(address);
    let bonds =
        query_storage_prefix::<C, pos::Bonds>(&client, &bonds_prefix).await;
    bonds.is_some() && bonds.unwrap().count() > 0
}

pub async fn is_delegator_at<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> bool {
    let key = pos::bonds_for_source_prefix(address);
    let bonds_iter = query_storage_prefix::<C, pos::Bonds>(client, &key).await;
    if let Some(mut bonds) = bonds_iter {
        bonds.any(|(_, bond)| bond.get(epoch).is_some())
    } else {
        false
    }
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    match address {
        Address::Established(_) => {
            // Established account exists if it has a VP
            let key = storage::Key::validity_predicate(address);
            query_has_storage_key(client, &key).await
        }
        Address::Implicit(_) | Address::Internal(_) => true,
    }
}

/// Query a conversion.
pub async fn query_conversion<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    asset_type: AssetType,
) -> Option<(
    Address,
    Epoch,
    masp_primitives::transaction::components::Amount,
    MerklePath<Node>,
)> {
    Some(unwrap_client_response::<C, _>(
        RPC.shell().read_conversion(client, &asset_type).await,
    ))
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<C: Client + crate::ledger::queries::Client + Sync, T>(
    client: &C,
    key: &storage::Key,
) -> Option<T>
where
    T: BorshDeserialize,
{
    // In case `T` is a unit (only thing that encodes to 0 bytes), we have to
    // use `storage_has_key` instead of `storage_value`, because `storage_value`
    // returns 0 bytes when the key is not found.
    let maybe_unit = T::try_from_slice(&[]);
    if let Ok(unit) = maybe_unit {
        return if unwrap_client_response::<C, _>(
            RPC.shell().storage_has_key(client, key).await,
        ) {
            Some(unit)
        } else {
            None
        };
    }

    let response = unwrap_client_response::<C, _>(
        RPC.shell()
            .storage_value(client, None, None, false, key)
            .await,
    );
    if response.data.is_empty() {
        return None;
    }
    T::try_from_slice(&response.data[..])
        .map(Some)
        .unwrap_or_else(|err| {
            panic!("Error decoding the value: {}", err);
        })
}

/// Query a storage value and the proof without decoding.
pub async fn query_storage_value_bytes<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    key: &storage::Key,
    height: Option<BlockHeight>,
    prove: bool,
) -> (Option<Vec<u8>>, Option<Proof>) {
    let data = None;
    let response = unwrap_client_response::<C, _>(
        RPC.shell()
            .storage_value(client, data, height, prove, key)
            .await,
    );
    if response.data.is_empty() {
        (None, response.proof)
    } else {
        (Some(response.data), response.proof)
    }
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<C: Client + crate::ledger::queries::Client + Sync, T>(
    client: &C,
    key: &storage::Key,
) -> Option<impl Iterator<Item = (storage::Key, T)>>
where
    T: BorshDeserialize,
{
    let values = unwrap_client_response::<C, _>(
        RPC.shell()
            .storage_prefix(client, None, None, false, key)
            .await,
    );
    let decode =
        |PrefixValue { key, value }: PrefixValue| match T::try_from_slice(
            &value[..],
        ) {
            Err(err) => {
                eprintln!(
                    "Skipping a value for key {}. Error in decoding: {}",
                    key, err
                );
                None
            }
            Ok(value) => Some((key, value)),
        };
    if values.data.is_empty() {
        None
    } else {
        Some(values.data.into_iter().filter_map(decode))
    }
}

/// Query to check if the given storage key exists.
pub async fn query_has_storage_key<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    key: &storage::Key,
) -> bool {
    unwrap_client_response::<C, _>(RPC.shell().storage_has_key(client, key).await)
}

/// Represents a query for an event pertaining to the specified transaction
#[derive(Debug, Copy, Clone)]
pub enum TxEventQuery<'a> {
    Accepted(&'a str),
    Applied(&'a str),
}

impl<'a> TxEventQuery<'a> {
    /// The event type to which this event query pertains
    pub fn event_type(self) -> &'static str {
        match self {
            TxEventQuery::Accepted(_) => "accepted",
            TxEventQuery::Applied(_) => "applied",
        }
    }

    /// The transaction to which this event query pertains
    pub fn tx_hash(self) -> &'a str {
        match self {
            TxEventQuery::Accepted(tx_hash) => tx_hash,
            TxEventQuery::Applied(tx_hash) => tx_hash,
        }
    }
}

/// Transaction event queries are semantically a subset of general queries
impl<'a> From<TxEventQuery<'a>> for Query {
    fn from(tx_query: TxEventQuery<'a>) -> Self {
        match tx_query {
            TxEventQuery::Accepted(tx_hash) => {
                Query::default().and_eq("accepted.hash", tx_hash)
            }
            TxEventQuery::Applied(tx_hash) => {
                Query::default().and_eq("applied.hash", tx_hash)
            }
        }
    }
}

/// Call the corresponding `tx_event_query` RPC method, to fetch
/// the current status of a transation.
pub async fn query_tx_events<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    tx_event_query: TxEventQuery<'_>,
) -> std::result::Result<Option<Event>, <C as crate::ledger::queries::Client>::Error> {
    let tx_hash: Hash = tx_event_query.tx_hash().try_into().unwrap();
    match tx_event_query {
        TxEventQuery::Accepted(_) => RPC
            .shell()
            .accepted(client, &tx_hash)
            .await
            /*.wrap_err_with(|| {
                eyre!("Failed querying whether a transaction was accepted")
            })*/,
        TxEventQuery::Applied(_) => RPC
            .shell()
            .applied(client, &tx_hash)
            .await
            /*.wrap_err_with(|| {
                eyre!("Error querying whether a transaction was applied")
            })*/,
    }
}

/// Dry run a transaction
pub async fn dry_run_tx<C: Client + crate::ledger::queries::Client + Sync>(client: &C, tx_bytes: Vec<u8>) -> namada_core::types::transaction::TxResult {
    let (data, height, prove) = (Some(tx_bytes), None, false);
    unwrap_client_response::<C, _>(
        RPC.shell().dry_run_tx(client, data, height, prove).await,
    )
    .data
}

/// Data needed for broadcasting a tx and
/// monitoring its progress on chain
///
/// Txs may be either a dry run or else
/// they should be encrypted and included
/// in a wrapper.
#[derive(Debug, Clone)]
pub enum TxBroadcastData {
    DryRun(Tx),
    Wrapper {
        tx: Tx,
        wrapper_hash: String,
        decrypted_hash: String,
    },
}

/// A parsed event from tendermint relating to a transaction
#[derive(Debug, Serialize)]
pub struct TxResponse {
    pub info: String,
    pub log: String,
    pub height: String,
    pub hash: String,
    pub code: String,
    pub gas_used: String,
    pub initialized_accounts: Vec<Address>,
}

impl TryFrom<Event> for TxResponse {
    type Error = String;

    fn try_from(event: Event) -> Result<Self, Self::Error> {
        fn missing_field_err(field: &str) -> String {
            format!("Field \"{field}\" not present in event")
        }

        let hash = event
            .get("hash")
            .ok_or_else(|| missing_field_err("hash"))?
            .clone();
        let info = event
            .get("info")
            .ok_or_else(|| missing_field_err("info"))?
            .clone();
        let log = event
            .get("log")
            .ok_or_else(|| missing_field_err("log"))?
            .clone();
        let height = event
            .get("height")
            .ok_or_else(|| missing_field_err("height"))?
            .clone();
        let code = event
            .get("code")
            .ok_or_else(|| missing_field_err("code"))?
            .clone();
        let gas_used = event
            .get("gas_used")
            .ok_or_else(|| missing_field_err("gas_used"))?
            .clone();
        let initialized_accounts = event
            .get("initialized_accounts")
            .map(String::as_str)
            // TODO: fix finalize block, to return initialized accounts,
            // even when we reject a tx?
            .map_or(Ok(vec![]), |initialized_accounts| {
                serde_json::from_str(initialized_accounts)
                    .map_err(|err| format!("JSON decode error: {err}"))
            })?;

        Ok(TxResponse {
            hash,
            info,
            log,
            height,
            code,
            gas_used,
            initialized_accounts,
        })
    }
}

impl TxResponse {
    /// Convert an [`Event`] to a [`TxResponse`], or error out.
    pub fn from_event(event: Event) -> Self {
        event.try_into().unwrap_or_else(|err| {
            panic!("Error fetching TxResponse: {err}");
        })
    }
}

/// Lookup the full response accompanying the specified transaction event
// TODO: maybe remove this in favor of `query_tx_status`
pub async fn query_tx_response<C: Client + Sync>(
    client: &C,
    tx_query: TxEventQuery<'_>,
) -> Result<TxResponse, TError> {
    // Find all blocks that apply a transaction with the specified hash
    let blocks = &client
        .block_search(tx_query.into(), 1, 255, Order::Ascending)
        .await
        .expect("Unable to query for transaction with given hash")
        .blocks;
    // Get the block results corresponding to a block to which
    // the specified transaction belongs
    let block = &blocks
        .get(0)
        .ok_or_else(|| {
            TError::server(
                "Unable to find a block applying the given transaction"
                    .to_string(),
            )
        })?
        .block;
    let response_block_results = client
        .block_results(block.header.height)
        .await
        .expect("Unable to retrieve block containing transaction");
    // Search for the event where the specified transaction is
    // applied to the blockchain
    let query_event_opt =
        response_block_results.end_block_events.and_then(|events| {
            events
                .iter()
                .find(|event| {
                    event.type_str == tx_query.event_type()
                        && event.attributes.iter().any(|tag| {
                            tag.key.as_ref() == "hash"
                                && tag.value.as_ref() == tx_query.tx_hash()
                        })
                })
                .cloned()
        });
    let query_event = query_event_opt.ok_or_else(|| {
        TError::server(
            "Unable to find the event corresponding to the specified \
             transaction"
                .to_string(),
        )
    })?;
    // Reformat the event attributes so as to ease value extraction
    let event_map: std::collections::HashMap<&str, &str> = query_event
        .attributes
        .iter()
        .map(|tag| (tag.key.as_ref(), tag.value.as_ref()))
        .collect();
    // Summarize the transaction results that we were searching for
    let result = TxResponse {
        info: event_map["info"].to_string(),
        log: event_map["log"].to_string(),
        height: event_map["height"].to_string(),
        hash: event_map["hash"].to_string(),
        code: event_map["code"].to_string(),
        gas_used: event_map["gas_used"].to_string(),
        initialized_accounts: serde_json::from_str(
            event_map["initialized_accounts"],
        )
        .unwrap_or_default(),
    };
    Ok(result)
}

pub async fn get_proposal_votes<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
    proposal_id: u64,
) -> Votes {
    let validators = get_all_validators(client, epoch).await;

    let vote_prefix_key =
        gov_storage::get_proposal_vote_prefix_key(proposal_id);
    let vote_iter =
        query_storage_prefix::<C, ProposalVote>(client, &vote_prefix_key).await;

    let mut yay_validators: HashMap<Address, VotePower> = HashMap::new();
    let mut yay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();
    let mut nay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();

    if let Some(vote_iter) = vote_iter {
        for (key, vote) in vote_iter {
            let voter_address = gov_storage::get_voter_address(&key)
                .expect("Vote key should contain the voting address.")
                .clone();
            if vote.is_yay() && validators.contains(&voter_address) {
                let amount: VotePower =
                    get_validator_stake(client, epoch, &voter_address)
                        .await
                        .into();
                yay_validators.insert(voter_address, amount);
            } else if !validators.contains(&voter_address) {
                let validator_address =
                    gov_storage::get_vote_delegation_address(&key)
                        .expect(
                            "Vote key should contain the delegation address.",
                        )
                        .clone();
                let delegator_token_amount = get_bond_amount_at(
                    client,
                    &voter_address,
                    &validator_address,
                    epoch,
                )
                .await;
                if let Some(amount) = delegator_token_amount {
                    if vote.is_yay() {
                        let entry =
                            yay_delegators.entry(voter_address).or_default();
                        entry
                            .insert(validator_address, VotePower::from(amount));
                    } else {
                        let entry =
                            nay_delegators.entry(voter_address).or_default();
                        entry
                            .insert(validator_address, VotePower::from(amount));
                    }
                }
            }
        }
    }

    Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    }
}

pub async fn get_all_validators<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> HashSet<Address> {
    unwrap_client_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_addresses(client, &Some(epoch))
            .await,
    )
}

pub async fn get_total_staked_tokens<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> token::Amount {
    unwrap_client_response::<C, _>(
        RPC.vp().pos().total_stake(client, &Some(epoch)).await,
    )
}

pub async fn get_validator_stake<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
    validator: &Address,
) -> token::Amount {
    unwrap_client_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_stake(client, validator, &Some(epoch))
            .await,
    )
}

pub async fn get_delegators_delegation<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> HashSet<Address> {
    unwrap_client_response::<C, _>(RPC.vp().pos().delegations(client, address).await)
}

pub async fn get_governance_parameters<C: Client + crate::ledger::queries::Client + Sync>(client: &C) -> GovParams {
    use crate::types::token::Amount;
    let key = gov_storage::get_max_proposal_code_size_key();
    let max_proposal_code_size = query_storage_value::<C, u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_max_proposal_content_key();
    let max_proposal_content_size = query_storage_value::<C, u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_fund_key();
    let min_proposal_fund = query_storage_value::<C, Amount>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_grace_epoch_key();
    let min_proposal_grace_epochs = query_storage_value::<C, u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_min_proposal_period_key();
    let min_proposal_period = query_storage_value::<C, u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    let key = gov_storage::get_max_proposal_period_key();
    let max_proposal_period = query_storage_value::<C, u64>(client, &key)
        .await
        .expect("Parameter should be definied.");

    GovParams {
        min_proposal_fund: u64::from(min_proposal_fund),
        max_proposal_code_size,
        min_proposal_period,
        max_proposal_period,
        max_proposal_content_size,
        min_proposal_grace_epochs,
    }
}

// Compute the result of a proposal
pub async fn compute_tally<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
    votes: Votes,
) -> ProposalResult {
    let total_staked_tokens: VotePower =
        get_total_staked_tokens(client, epoch).await.into();

    let Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    } = votes;

    let mut total_yay_staked_tokens = VotePower::from(0_u64);
    for (_, amount) in yay_validators.clone().into_iter() {
        total_yay_staked_tokens += amount;
    }

    // YAY: Add delegator amount whose validator didn't vote / voted nay
    for (_, vote_map) in yay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if !yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens += vote_power;
            }
        }
    }

    // NAY: Remove delegator amount whose validator validator vote yay
    for (_, vote_map) in nay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens -= vote_power;
            }
        }
    }

    if total_yay_staked_tokens >= (total_staked_tokens / 3) * 2 {
        ProposalResult {
            result: TallyResult::Passed,
            total_voting_power: total_staked_tokens,
            total_yay_power: total_yay_staked_tokens,
            total_nay_power: 0,
        }
    } else {
        ProposalResult {
            result: TallyResult::Rejected,
            total_voting_power: total_staked_tokens,
            total_yay_power: total_yay_staked_tokens,
            total_nay_power: 0,
        }
    }
}

pub async fn get_bond_amount_at<C: Client + crate::ledger::queries::Client + Sync>(
    client: &C,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Option<token::Amount> {
    let slashes_key = pos::validator_slashes_key(validator);
    let slashes = query_storage_value::<C, pos::Slashes>(client, &slashes_key)
        .await
        .unwrap_or_default();
    let bond_key = pos::bond_key(&BondId {
        source: delegator.clone(),
        validator: validator.clone(),
    });
    let epoched_bonds = query_storage_value::<C, Bonds>(client, &bond_key).await;
    match epoched_bonds {
        Some(epoched_bonds) => {
            let mut delegated_amount: token::Amount = 0.into();
            for bond in epoched_bonds.iter() {
                let mut to_deduct = bond.neg_deltas;
                for (epoch_start, &(mut delta)) in
                    bond.pos_deltas.iter().sorted()
                {
                    // deduct bond's neg_deltas
                    if to_deduct > delta {
                        to_deduct -= delta;
                        // If the whole bond was deducted, continue to
                        // the next one
                        continue;
                    } else {
                        delta -= to_deduct;
                        to_deduct = token::Amount::default();
                    }

                    delta = apply_slashes(
                        &slashes,
                        delta,
                        *epoch_start,
                        None,
                    );
                    if epoch >= *epoch_start {
                        delegated_amount += delta;
                    }
                }
            }
            Some(delegated_amount)
        }
        None => None,
    }
}

/// Accumulate slashes starting from `epoch_start` until (optionally)
/// `withdraw_epoch` and apply them to the token amount `delta`.
fn apply_slashes(
    slashes: &[Slash],
    mut delta: token::Amount,
    epoch_start: Epoch,
    withdraw_epoch: Option<Epoch>,
) -> token::Amount {
    let mut slashed = token::Amount::default();
    for slash in slashes {
        if slash.epoch >= epoch_start
            && slash.epoch < withdraw_epoch.unwrap_or_else(|| u64::MAX.into())
        {
            let raw_delta: u64 = delta.into();
            let current_slashed =
                token::Amount::from(decimal_mult_u64(slash.rate, raw_delta));
            slashed += current_slashed;
            delta -= current_slashed;
        }
    }
    delta
}
