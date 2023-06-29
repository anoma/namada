//! SDK RPC queries
use std::collections::{HashMap, HashSet};

use borsh::BorshDeserialize;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use namada_core::ledger::storage::LastBlock;
use namada_core::ledger::testnet_pow;
use namada_core::types::address::Address;
use namada_core::types::storage::Key;
use namada_core::types::token::{
    Amount, DenominatedAmount, Denomination, MaspDenom, TokenAddress,
};
use namada_proof_of_stake::types::{BondsAndUnbondsDetails, CommissionPair};
use serde::Serialize;
use tokio::time::Duration;

use crate::ledger::args::InputAmount;
use crate::ledger::events::Event;
use crate::ledger::governance::parameters::GovParams;
use crate::ledger::governance::storage as gov_storage;
use crate::ledger::native_vp::governance::utils::Votes;
use crate::ledger::queries::vp::pos::EnrichedBondsAndUnbondsDetails;
use crate::ledger::queries::RPC;
use crate::proto::Tx;
use crate::tendermint::merkle::proof::Proof;
use crate::tendermint_rpc::error::Error as TError;
use crate::tendermint_rpc::query::Query;
use crate::tendermint_rpc::Order;
use crate::types::governance::{ProposalVote, VotePower};
use crate::types::hash::Hash;
use crate::types::key::*;
use crate::types::storage::{BlockHeight, BlockResults, Epoch, PrefixValue};
use crate::types::token::balance_key;
use crate::types::{storage, token};

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    status: TxEventQuery<'_>,
    deadline: Duration,
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
        async_std::task::sleep(*backoff).await;
        *backoff += ONE_SECOND;
    }

    let mut backoff = ONE_SECOND;
    loop {
        tracing::debug!(query = ?status, "Querying tx status");
        let maybe_event = match query_tx_events(client, status).await {
            Ok(response) => response,
            Err(_err) => {
                // tracing::debug!(%err, "ABCI query failed");
                sleep_update(status, &mut backoff).await;
                continue;
            }
        };
        if let Some(e) = maybe_event {
            break e;
        } else if deadline < backoff {
            panic!(
                "Transaction status query deadline of {deadline:?} exceeded"
            );
        } else {
            sleep_update(status, &mut backoff).await;
        }
    }
}

/// Query the epoch of the last committed block
pub async fn query_epoch<C: crate::ledger::queries::Client + Sync>(
    client: &C,
) -> Epoch {
    let epoch = unwrap_client_response::<C, _>(RPC.shell().epoch(client).await);
    epoch
}

/// Query the last committed block, if any.
pub async fn query_block<C: crate::ledger::queries::Client + Sync>(
    client: &C,
) -> Option<LastBlock> {
    // NOTE: We're not using `client.latest_block()` because it may return an
    // updated block from pre-commit before it's actually committed
    unwrap_client_response::<C, _>(RPC.shell().last_block(client).await)
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<C: crate::ledger::queries::Client, T>(
    response: Result<T, C::Error>,
) -> T {
    response.unwrap_or_else(|_err| {
        panic!("Error in the query");
    })
}

/// Query the results of the last committed block
pub async fn query_results<C: crate::ledger::queries::Client + Sync>(
    client: &C,
) -> Vec<BlockResults> {
    unwrap_client_response::<C, _>(RPC.shell().read_results(client).await)
}

/// Query token amount of owner.
pub async fn get_token_balance<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    token: &Address,
    owner: &Address,
) -> Option<token::Amount> {
    let balance_key = balance_key(token, owner);
    query_storage_value(client, &balance_key).await
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> Option<common::PublicKey> {
    let key = pk_key(address);
    query_storage_value(client, &key).await
}

/// Check if the given address is a known validator.
pub async fn is_validator<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    unwrap_client_response::<C, _>(
        RPC.vp().pos().is_validator(client, address).await,
    )
}

/// Check if a given address is a known delegator
pub async fn is_delegator<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    unwrap_client_response::<C, bool>(
        RPC.vp().pos().is_delegator(client, address, &None).await,
    )
}

/// Check if a given address is a known delegator at the given epoch
pub async fn is_delegator_at<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> bool {
    unwrap_client_response::<C, bool>(
        RPC.vp()
            .pos()
            .is_delegator(client, address, &Some(epoch))
            .await,
    )
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C: crate::ledger::queries::Client + Sync>(
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

#[cfg(not(feature = "mainnet"))]
/// Check if the given address is a testnet faucet account address.
pub async fn is_faucet_account<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    unwrap_client_response::<C, bool>(RPC.vp().is_faucet(client, address).await)
}

#[cfg(not(feature = "mainnet"))]
/// Get faucet account address, if any is setup for the network.
pub async fn get_faucet_address<C: crate::ledger::queries::Client + Sync>(
    client: &C,
) -> Option<Address> {
    unwrap_client_response::<C, Option<Address>>(
        RPC.vp().get_faucet_address(client).await,
    )
}

#[cfg(not(feature = "mainnet"))]
/// Obtain a PoW challenge for a withdrawal from a testnet faucet account, if
/// any is setup for the network.
pub async fn get_testnet_pow_challenge<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    source: Address,
) -> testnet_pow::Challenge {
    unwrap_client_response::<C, testnet_pow::Challenge>(
        RPC.vp().testnet_pow_challenge(client, source).await,
    )
}

/// Query a conversion.
pub async fn query_conversion<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    asset_type: AssetType,
) -> Option<(
    Address,
    Option<Key>,
    MaspDenom,
    Epoch,
    masp_primitives::transaction::components::Amount,
    MerklePath<Node>,
)> {
    Some(unwrap_client_response::<C, _>(
        RPC.shell().read_conversion(client, &asset_type).await,
    ))
}

/// Query a wasm code hash
pub async fn query_wasm_code_hash<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    code_path: impl AsRef<str>,
) -> Option<Hash> {
    let hash_key = Key::wasm_hash(code_path.as_ref());
    match query_storage_value_bytes(client, &hash_key, None, false)
        .await
        .0
    {
        Some(hash) => {
            Some(Hash::try_from(&hash[..]).expect("Invalid code hash"))
        }
        None => {
            eprintln!(
                "The corresponding wasm code of the code path {} doesn't \
                 exist on chain.",
                code_path.as_ref(),
            );
            None
        }
    }
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<C, T>(
    client: &C,
    key: &storage::Key,
) -> Option<T>
where
    T: BorshDeserialize,
    C: crate::ledger::queries::Client + Sync,
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
pub async fn query_storage_value_bytes<
    C: crate::ledger::queries::Client + Sync,
>(
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
pub async fn query_storage_prefix<C: crate::ledger::queries::Client + Sync, T>(
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
pub async fn query_has_storage_key<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    key: &storage::Key,
) -> bool {
    unwrap_client_response::<C, _>(
        RPC.shell().storage_has_key(client, key).await,
    )
}

/// Represents a query for an event pertaining to the specified transaction
#[derive(Debug, Copy, Clone)]
pub enum TxEventQuery<'a> {
    /// Queries whether transaction with given hash was accepted
    Accepted(&'a str),
    /// Queries whether transaction with given hash was applied
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
pub async fn query_tx_events<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    tx_event_query: TxEventQuery<'_>,
) -> std::result::Result<
    Option<Event>,
    <C as crate::ledger::queries::Client>::Error,
> {
    let tx_hash: Hash = tx_event_query.tx_hash().try_into().unwrap();
    match tx_event_query {
        TxEventQuery::Accepted(_) => {
            RPC.shell().accepted(client, &tx_hash).await
        }
        /*.wrap_err_with(|| {
            eyre!("Failed querying whether a transaction was accepted")
        })*/,
        TxEventQuery::Applied(_) => RPC.shell().applied(client, &tx_hash).await, /*.wrap_err_with(|| {
                                                                                     eyre!("Error querying whether a transaction was applied")
                                                                                 })*/
    }
}

/// Dry run a transaction
pub async fn dry_run_tx<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    tx_bytes: Vec<u8>,
) -> namada_core::types::transaction::TxResult {
    let (data, height, prove) = (Some(tx_bytes), None, false);
    let result = unwrap_client_response::<C, _>(
        RPC.shell().dry_run_tx(client, data, height, prove).await,
    )
    .data;
    println! {"Dry-run result: {}", result};
    result
}

/// Data needed for broadcasting a tx and
/// monitoring its progress on chain
///
/// Txs may be either a dry run or else
/// they should be encrypted and included
/// in a wrapper.
#[derive(Debug, Clone)]
pub enum TxBroadcastData {
    /// Dry run broadcast data
    DryRun(Tx),
    /// Wrapper broadcast data
    Wrapper {
        /// Transaction to broadcast
        tx: Tx,
        /// Hash of the wrapper transaction
        wrapper_hash: String,
        /// Hash of decrypted transaction
        decrypted_hash: String,
    },
}

/// A parsed event from tendermint relating to a transaction
#[derive(Debug, Serialize)]
pub struct TxResponse {
    /// Response information
    pub info: String,
    /// Response log
    pub log: String,
    /// Block height
    pub height: String,
    /// Transaction height
    pub hash: String,
    /// Response code
    pub code: String,
    /// Gas used
    pub gas_used: String,
    /// Initialized accounts
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
pub async fn query_tx_response<C: crate::ledger::queries::Client + Sync>(
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

/// Get the votes for a given proposal id
pub async fn get_proposal_votes<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
    proposal_id: u64,
) -> Votes {
    let validators = get_all_validators(client, epoch).await;

    let vote_prefix_key =
        gov_storage::get_proposal_vote_prefix_key(proposal_id);
    let vote_iter =
        query_storage_prefix::<C, ProposalVote>(client, &vote_prefix_key).await;

    let mut yay_validators: HashMap<Address, (VotePower, ProposalVote)> =
        HashMap::new();
    let mut delegators: HashMap<
        Address,
        HashMap<Address, (VotePower, ProposalVote)>,
    > = HashMap::new();

    if let Some(vote_iter) = vote_iter {
        for (key, vote) in vote_iter {
            let voter_address = gov_storage::get_voter_address(&key)
                .expect("Vote key should contain the voting address.")
                .clone();
            if vote.is_yay() && validators.contains(&voter_address) {
                let amount: VotePower =
                    get_validator_stake(client, epoch, &voter_address)
                        .await
                        .try_into()
                        .expect("Amount of bonds");
                yay_validators.insert(voter_address, (amount, vote));
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
                    let entry = delegators.entry(voter_address).or_default();
                    entry.insert(
                        validator_address,
                        (VotePower::from(amount), vote),
                    );
                }
            }
        }
    }

    Votes {
        yay_validators,
        delegators,
    }
}

/// Get all validators in the given epoch
pub async fn get_all_validators<C: crate::ledger::queries::Client + Sync>(
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

/// Get the total staked tokens in the given epoch
pub async fn get_total_staked_tokens<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    epoch: Epoch,
) -> token::Amount {
    unwrap_client_response::<C, _>(
        RPC.vp().pos().total_stake(client, &Some(epoch)).await,
    )
}

/// Get the given validator's stake at the given epoch
pub async fn get_validator_stake<C: crate::ledger::queries::Client + Sync>(
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
    .unwrap_or_default()
}

/// Get the delegator's delegation
pub async fn get_delegators_delegation<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    address: &Address,
) -> HashSet<Address> {
    unwrap_client_response::<C, _>(
        RPC.vp().pos().delegation_validators(client, address).await,
    )
}

/// Query and return validator's commission rate and max commission rate change
/// per epoch
pub async fn query_commission_rate<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Option<CommissionPair> {
    unwrap_client_response::<C, Option<CommissionPair>>(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )
}

/// Query a validator's bonds for a given epoch
pub async fn query_bond<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> token::Amount {
    unwrap_client_response::<C, token::Amount>(
        RPC.vp().pos().bond(client, source, validator, &epoch).await,
    )
}

/// Query a validator's unbonds for a given epoch
pub async fn query_and_print_unbonds<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    source: &Address,
    validator: &Address,
) {
    let unbonds = query_unbond_with_slashing(client, source, validator).await;
    let current_epoch = query_epoch(client).await;

    let mut total_withdrawable = token::Amount::default();
    let mut not_yet_withdrawable = HashMap::<Epoch, token::Amount>::new();
    for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter() {
        if withdraw_epoch <= current_epoch {
            total_withdrawable += amount;
        } else {
            let withdrawable_amount =
                not_yet_withdrawable.entry(withdraw_epoch).or_default();
            *withdrawable_amount += amount;
        }
    }
    if total_withdrawable != token::Amount::default() {
        println!(
            "Total withdrawable now: {}.",
            total_withdrawable.to_string_native()
        );
    }
    if !not_yet_withdrawable.is_empty() {
        println!("Current epoch: {current_epoch}.")
    }
    for (withdraw_epoch, amount) in not_yet_withdrawable {
        println!(
            "Amount {} withdrawable starting from epoch {withdraw_epoch}.",
            amount.to_string_native()
        );
    }
}

/// Query withdrawable tokens in a validator account for a given epoch
pub async fn query_withdrawable_tokens<
    C: crate::ledger::queries::Client + Sync,
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

/// Query all unbonds for a validator, applying slashes
pub async fn query_unbond_with_slashing<
    C: crate::ledger::queries::Client + Sync,
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

/// Get the givernance parameters
pub async fn get_governance_parameters<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
) -> GovParams {
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
        min_proposal_fund: u128::try_from(min_proposal_fund)
            .expect("Amount out of bounds") as u64,
        max_proposal_code_size,
        min_proposal_period,
        max_proposal_period,
        max_proposal_content_size,
        min_proposal_grace_epochs,
    }
}

/// Get the bond amount at the given epoch
pub async fn get_bond_amount_at<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Option<token::Amount> {
    let (_total, total_active) = unwrap_client_response::<C, (Amount, Amount)>(
        RPC.vp()
            .pos()
            .bond_with_slashing(client, delegator, validator, &Some(epoch))
            .await,
    );
    Some(total_active)
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs.
pub async fn bonds_and_unbonds<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> BondsAndUnbondsDetails {
    unwrap_client_response::<C, _>(
        RPC.vp()
            .pos()
            .bonds_and_unbonds(client, source, validator)
            .await,
    )
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs, enriched with extra information calculated from
/// the data.
pub async fn enriched_bonds_and_unbonds<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    current_epoch: Epoch,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> EnrichedBondsAndUnbondsDetails {
    unwrap_client_response::<C, _>(
        RPC.vp()
            .pos()
            .enriched_bonds_and_unbonds(
                client,
                current_epoch,
                source,
                validator,
            )
            .await,
    )
}

/// Get the correct representation of the amount given the token type.
pub async fn validate_amount<C: crate::ledger::queries::Client + Sync>(
    client: &C,
    amount: InputAmount,
    token: &Address,
    sub_prefix: &Option<Key>,
    force: bool,
) -> Option<token::DenominatedAmount> {
    let input_amount = match amount {
        InputAmount::Unvalidated(amt) => amt.canonical(),
        InputAmount::Validated(amt) => return Some(amt),
    };
    let denom = unwrap_client_response::<C, Option<Denomination>>(
        RPC.vp()
            .token()
            .denomination(client, token, sub_prefix)
            .await,
    )
    .or_else(|| {
        if force {
            println!(
                "No denomination found for token: {token}, but --force was \
                 passed. Defaulting to the provided denomination."
            );
            Some(input_amount.denom)
        } else {
            println!(
                "No denomination found for token: {token}, the input \
                 arguments could not be parsed."
            );
            None
        }
    })?;
    if denom < input_amount.denom && !force {
        println!(
            "The input amount contained a higher precision than allowed by \
             {token}."
        );
        None
    } else {
        match input_amount.increase_precision(denom) {
            Ok(res) => Some(res),
            Err(_) => {
                println!(
                    "The amount provided requires more the 256 bits to \
                     represent."
                );
                None
            }
        }
    }
}

/// Look up the denomination of a token in order to format it
/// correctly as a string.
pub async fn format_denominated_amount<
    C: crate::ledger::queries::Client + Sync,
>(
    client: &C,
    token: &TokenAddress,
    amount: token::Amount,
) -> String {
    let denom = unwrap_client_response::<C, Option<Denomination>>(
        RPC.vp()
            .token()
            .denomination(client, &token.address, &token.sub_prefix)
            .await,
    )
    .unwrap_or_else(|| {
        println!(
            "No denomination found for token: {token}, defaulting to zero \
             decimal places"
        );
        0.into()
    });
    DenominatedAmount { amount, denom }.to_string()
}
