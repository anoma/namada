//! SDK RPC queries

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::ControlFlow;
use std::str::FromStr;

use borsh::BorshDeserialize;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use namada_core::ledger::governance::parameters::GovernanceParameters;
use namada_core::ledger::governance::storage::proposal::StorageProposal;
use namada_core::ledger::governance::utils::Vote;
use namada_core::ledger::ibc::storage::{
    ibc_denom_key, ibc_denom_key_prefix, is_ibc_denom_key,
};
use namada_core::ledger::storage::LastBlock;
use namada_core::types::account::Account;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::hash::Hash;
use namada_core::types::key::common;
use namada_core::types::storage::{
    BlockHeight, BlockResults, Epoch, Key, PrefixValue,
};
use namada_core::types::token::{
    Amount, DenominatedAmount, Denomination, MaspDenom,
};
use namada_core::types::transaction::{ResultCode, TxResult};
use namada_core::types::{storage, token};
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::{
    BondsAndUnbondsDetails, CommissionPair, ValidatorMetaData, ValidatorState,
};
use serde::Serialize;

use crate::args::InputAmount;
use crate::control_flow::time;
use crate::error::{EncodingError, Error, QueryError, TxError};
use crate::events::Event;
use crate::internal_macros::echo_error;
use crate::io::Io;
use crate::proto::Tx;
use crate::queries::vp::pos::EnrichedBondsAndUnbondsDetails;
use crate::queries::{Client, RPC};
use crate::tendermint::block::Height;
use crate::tendermint::merkle::proof::ProofOps;
use crate::tendermint_rpc::error::Error as TError;
use crate::tendermint_rpc::query::Query;
use crate::tendermint_rpc::Order;
use crate::{display_line, edisplay_line, error, Namada};

/// Query the status of a given transaction.
///
/// If a response is not delivered until `deadline`, we exit the cli with an
/// error.
pub async fn query_tx_status(
    context: &impl Namada,
    status: TxEventQuery<'_>,
    deadline: time::Instant,
) -> Result<Event, Error> {
    time::Sleep {
        strategy: time::LinearBackoff {
            delta: time::Duration::from_secs(1),
        },
    }
    .timeout(deadline, || async {
        tracing::debug!(query = ?status, "Querying tx status");
        let maybe_event = match query_tx_events(context.client(), status).await
        {
            Ok(response) => response,
            Err(err) => {
                tracing::debug!(
                    query = ?status,
                    %err,
                    "ABCI query failed, retrying tx status query \
                     after timeout",
                );
                return ControlFlow::Continue(());
            }
        };
        if let Some(e) = maybe_event {
            tracing::debug!(event = ?e, "Found tx event");
            ControlFlow::Break(e)
        } else {
            tracing::debug!(
                query = ?status,
                "No tx events found, retrying tx status query \
                 after timeout",
            );
            ControlFlow::Continue(())
        }
    })
    .await
    .map_err(|_| {
        edisplay_line!(
            context.io(),
            "Transaction status query deadline of {deadline:?} exceeded"
        );
        match status {
            TxEventQuery::Accepted(_) => Error::Tx(TxError::AcceptTimeout),
            TxEventQuery::Applied(_) => Error::Tx(TxError::AppliedTimeout),
        }
    })
}

/// Query the epoch of the last committed block
pub async fn query_epoch<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<Epoch, error::Error> {
    convert_response::<C, _>(RPC.shell().epoch(client).await)
}

/// Query the address of the native token
pub async fn query_native_token<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<Address, error::Error> {
    convert_response::<C, _>(RPC.shell().native_token(client).await)
}

/// Query the epoch of the given block height, if it exists.
/// Will return none if the input block height is greater than
/// the latest committed block height.
pub async fn query_epoch_at_height<C: crate::queries::Client + Sync>(
    client: &C,
    height: BlockHeight,
) -> Result<Option<Epoch>, error::Error> {
    convert_response::<C, _>(RPC.shell().epoch_at_height(client, &height).await)
}

/// Query the last committed block, if any.
pub async fn query_block<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<Option<LastBlock>, error::Error> {
    // NOTE: We're not using `client.latest_block()` because it may return an
    // updated block from pre-commit before it's actually committed
    convert_response::<C, _>(RPC.shell().last_block(client).await)
}

/// A helper to unwrap client's response. Will shut down process on error.
fn unwrap_client_response<C: crate::queries::Client, T>(
    response: Result<T, C::Error>,
) -> T {
    response.unwrap_or_else(|err| {
        panic!("Error in the query: {:?}", err.to_string());
    })
}

/// A helper to turn client's response into an error type that can be used with
/// ? The exact error type is a `QueryError::NoResponse`, and thus should be
/// seen as getting no response back from a query.
fn convert_response<C: crate::queries::Client, T>(
    response: Result<T, C::Error>,
) -> Result<T, Error> {
    response.map_err(|err| Error::from(QueryError::NoResponse(err.to_string())))
}

/// Query the results of the last committed block
pub async fn query_results<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<Vec<BlockResults>, Error> {
    convert_response::<C, _>(RPC.shell().read_results(client).await)
}

/// Query token amount of owner.
pub async fn get_token_balance<C: crate::queries::Client + Sync>(
    client: &C,
    token: &Address,
    owner: &Address,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp().token().balance(client, token, owner).await,
    )
}

/// Check if the given address is a known validator.
pub async fn is_validator<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool, Error> {
    convert_response::<C, _>(RPC.vp().pos().is_validator(client, address).await)
}

/// Check if the given address is a pgf steward.
pub async fn is_steward<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> bool {
    unwrap_client_response::<C, _>(
        RPC.vp().pgf().is_steward(client, address).await,
    )
}

/// Check if a given address is a known delegator
pub async fn is_delegator<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(
        RPC.vp().pos().is_delegator(client, address, &None).await,
    )
}

/// Check if a given address is a known delegator at the given epoch
pub async fn is_delegator_at<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(
        RPC.vp()
            .pos()
            .is_delegator(client, address, &Some(epoch))
            .await,
    )
}

/// Find if the given source address has any bonds.
pub async fn has_bonds<C: crate::queries::Client + Sync>(
    client: &C,
    source: &Address,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(RPC.vp().pos().has_bonds(client, source).await)
}

/// Get the set of consensus keys registered in the network
pub async fn get_consensus_keys<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<BTreeSet<common::PublicKey>, error::Error> {
    convert_response::<C, BTreeSet<common::PublicKey>>(
        RPC.vp().pos().consensus_key_set(client).await,
    )
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<bool, Error> {
    match address {
        Address::Established(_) => {
            // Established account exists if it has a VP
            let key = storage::Key::validity_predicate(address);
            query_has_storage_key(client, &key).await
        }
        Address::Implicit(_) | Address::Internal(_) => Ok(true),
    }
}

/// Query a conversion.
pub async fn query_conversion<C: crate::queries::Client + Sync>(
    client: &C,
    asset_type: AssetType,
) -> Option<(
    Address,
    MaspDenom,
    Epoch,
    masp_primitives::transaction::components::I128Sum,
    MerklePath<Node>,
)> {
    unwrap_client_response::<C, _>(
        RPC.shell().read_conversion(client, &asset_type).await,
    )
}

/// Query conversions
pub async fn query_conversions<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<
    BTreeMap<
        AssetType,
        (
            Address,
            Epoch,
            masp_primitives::transaction::components::I128Sum,
        ),
    >,
    error::Error,
> {
    convert_response::<C, _>(RPC.shell().read_conversions(client).await)
}

/// Query to read the tokens that earn masp rewards.
pub async fn query_masp_reward_tokens<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<BTreeMap<String, Address>, Error> {
    convert_response::<C, _>(RPC.shell().masp_reward_tokens(client).await)
}

/// Query a wasm code hash
pub async fn query_wasm_code_hash(
    context: &impl Namada,
    code_path: impl AsRef<str>,
) -> Result<Hash, error::Error> {
    let hash_key = Key::wasm_hash(code_path.as_ref());
    match query_storage_value_bytes(context.client(), &hash_key, None, false)
        .await?
        .0
    {
        Some(hash) => Ok(Hash::try_from(&hash[..]).expect("Invalid code hash")),
        None => {
            edisplay_line!(
                context.io(),
                "The corresponding wasm code of the code path {} doesn't \
                 exist on chain.",
                code_path.as_ref(),
            );
            Err(Error::from(QueryError::Wasm(
                code_path.as_ref().to_string(),
            )))
        }
    }
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<C, T>(
    client: &C,
    key: &storage::Key,
) -> Result<T, Error>
where
    T: BorshDeserialize,
    C: crate::queries::Client + Sync,
{
    // In case `T` is a unit (only thing that encodes to 0 bytes), we have to
    // use `storage_has_key` instead of `storage_value`, because `storage_value`
    // returns 0 bytes when the key is not found.
    let maybe_unit = T::try_from_slice(&[]);
    if let Ok(unit) = maybe_unit {
        return if convert_response::<C, _>(
            RPC.shell().storage_has_key(client, key).await,
        )? {
            Ok(unit)
        } else {
            Err(Error::from(QueryError::NoSuchKey(key.to_string())))
        };
    }

    let response = convert_response::<C, _>(
        RPC.shell()
            .storage_value(client, None, None, false, key)
            .await,
    )?;
    if response.data.is_empty() {
        return Err(Error::from(QueryError::General(format!(
            "No data found in {key}"
        ))));
    }
    T::try_from_slice(&response.data[..])
        .map_err(|err| Error::from(EncodingError::Decoding(err.to_string())))
}

/// Query a storage value and the proof without decoding.
pub async fn query_storage_value_bytes<C: crate::queries::Client + Sync>(
    client: &C,
    key: &storage::Key,
    height: Option<BlockHeight>,
    prove: bool,
) -> Result<(Option<Vec<u8>>, Option<ProofOps>), error::Error> {
    let data = None;
    let response = convert_response::<C, _>(
        RPC.shell()
            .storage_value(client, data, height, prove, key)
            .await,
    )?;
    Ok(if response.data.is_empty() {
        (None, response.proof)
    } else {
        (Some(response.data), response.proof)
    })
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<'a, 'b, N: Namada, T>(
    context: &'b N,
    key: &storage::Key,
) -> Result<Option<impl 'b + Iterator<Item = (storage::Key, T)>>, error::Error>
where
    T: BorshDeserialize,
{
    let values = convert_response::<N::Client, _>(
        RPC.shell()
            .storage_prefix(context.client(), None, None, false, key)
            .await,
    )?;
    let decode =
        |PrefixValue { key, value }: PrefixValue| match T::try_from_slice(
            &value[..],
        ) {
            Err(err) => {
                edisplay_line!(
                    context.io(),
                    "Skipping a value for key {}. Error in decoding: {}",
                    key,
                    err
                );
                None
            }
            Ok(value) => Some((key, value)),
        };
    Ok(if values.data.is_empty() {
        None
    } else {
        Some(values.data.into_iter().filter_map(decode))
    })
}

/// Query to check if the given storage key exists.
pub async fn query_has_storage_key<C: crate::queries::Client + Sync>(
    client: &C,
    key: &storage::Key,
) -> Result<bool, Error> {
    convert_response::<C, _>(RPC.shell().storage_has_key(client, key).await)
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
/// the current status of a transaction.
pub async fn query_tx_events<C: crate::queries::Client + Sync>(
    client: &C,
    tx_event_query: TxEventQuery<'_>,
) -> std::result::Result<Option<Event>, <C as crate::queries::Client>::Error> {
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
pub async fn dry_run_tx<N: Namada>(
    context: &N,
    tx_bytes: Vec<u8>,
) -> Result<namada_core::types::transaction::TxResult, Error> {
    let (data, height, prove) = (Some(tx_bytes), None, false);
    let result = convert_response::<N::Client, _>(
        RPC.shell()
            .dry_run_tx(context.client(), data, height, prove)
            .await,
    )?
    .data;
    let result_str = if result.is_accepted() {
        format!(
            "Transaction was successfully applied. Used {} gas.",
            result.gas_used
        )
    } else {
        format!(
            "Transaction was rejected by VPs: {}.\nChanged key: {}",
            serde_json::to_string_pretty(&result.vps_result.rejected_vps)
                .unwrap(),
            serde_json::to_string_pretty(&result.changed_keys).unwrap(),
        )
    };
    display_line!(context.io(), "Dry-run result: {result_str}");
    Ok(result)
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
    /// Live broadcast data
    Live {
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
    /// Result of inner tx (wasm), if any
    pub inner_tx: Option<TxResult>,
    /// Response additional information
    pub info: String,
    /// Response log
    pub log: String,
    /// Block height
    pub height: BlockHeight,
    /// Transaction height
    pub hash: String,
    /// Response code
    pub code: ResultCode,
    /// Gas used. If there's an `inner_tx`, its gas is equal to this value.
    pub gas_used: String,
}

/// Determines a result of an inner tx from [`TxResponse::inner_tx_result`].
pub enum InnerTxResult<'a> {
    /// Tx is applied and accepted by all VPs
    Success(&'a TxResult),
    /// Some VPs rejected the tx
    VpsRejected(&'a TxResult),
    /// Transaction failed in some other way
    OtherFailure,
}

impl TryFrom<Event> for TxResponse {
    type Error = String;

    fn try_from(event: Event) -> Result<Self, Self::Error> {
        fn missing_field_err(field: &str) -> String {
            format!("Field \"{field}\" not present in event")
        }

        let inner_tx = event
            .get("inner_tx")
            .map(|s| TxResult::from_str(s).unwrap());
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
        let height = BlockHeight::from_str(
            event
                .get("height")
                .ok_or_else(|| missing_field_err("height"))?,
        )
        .map_err(|e| e.to_string())?;
        let code = ResultCode::from_str(
            event.get("code").ok_or_else(|| missing_field_err("code"))?,
        )
        .map_err(|e| e.to_string())?;
        let gas_used = event
            .get("gas_used")
            .ok_or_else(|| missing_field_err("gas_used"))?
            .clone();

        Ok(TxResponse {
            inner_tx,
            info,
            hash,
            log,
            height,
            code,
            gas_used,
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

    /// Check the result of the inner tx. This should not be used with wrapper
    /// txs.
    pub fn inner_tx_result(&self) -> InnerTxResult<'_> {
        if let Some(tx) = self.inner_tx.as_ref() {
            if tx.is_accepted() {
                InnerTxResult::Success(tx)
            } else {
                InnerTxResult::VpsRejected(tx)
            }
        } else {
            InnerTxResult::OtherFailure
        }
    }
}

/// Lookup the full response accompanying the specified transaction event
// TODO: maybe remove this in favor of `query_tx_status`
pub async fn query_tx_response<C: crate::queries::Client + Sync>(
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
                    event.kind == tx_query.event_type()
                        && event.attributes.iter().any(|tag| {
                            &tag.key == "hash"
                                && tag.value == tx_query.tx_hash()
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
    let inner_tx = event_map
        .get("inner_tx")
        .map(|s| {
            TxResult::from_str(s).map_err(|_| {
                TError::parse("Error parsing TxResult".to_string())
            })
        })
        .transpose()?;
    let code = ResultCode::from_str(event_map["code"])
        .map_err(|_| TError::parse("Error parsing ResultCode".to_string()))?;
    let height = BlockHeight::from_str(event_map["height"])
        .map_err(|_| TError::parse("Error parsing BlockHeight".to_string()))?;
    let result = TxResponse {
        inner_tx,
        info: event_map["info"].to_string(),
        log: event_map["log"].to_string(),
        height,
        hash: event_map["hash"].to_string(),
        code,
        gas_used: event_map["gas_used"].to_string(),
    };
    Ok(result)
}

/// Get the PoS parameters
pub async fn get_pos_params<C: crate::queries::Client + Sync>(
    client: &C,
) -> Result<PosParams, error::Error> {
    convert_response::<C, _>(RPC.vp().pos().pos_params(client).await)
}

/// Get all validators in the given epoch
pub async fn get_all_validators<C: crate::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> Result<HashSet<Address>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_addresses(client, &Some(epoch))
            .await,
    )
}

/// Get the total staked tokens in the given epoch
pub async fn get_total_staked_tokens<C: crate::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp().pos().total_stake(client, &Some(epoch)).await,
    )
}

/// Get the given validator's stake at the given epoch
pub async fn get_validator_stake<C: crate::queries::Client + Sync>(
    client: &C,
    epoch: Epoch,
    validator: &Address,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_stake(client, validator, &Some(epoch))
            .await,
    )
    .map(|t| t.unwrap_or_default())
}

/// Query and return a validator's state
pub async fn get_validator_state<C: crate::queries::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<Option<ValidatorState>, error::Error> {
    convert_response::<C, Option<ValidatorState>>(
        RPC.vp()
            .pos()
            .validator_state(client, validator, &epoch)
            .await,
    )
}

/// Get the delegator's delegation
pub async fn get_delegators_delegation<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
) -> Result<HashSet<Address>, error::Error> {
    convert_response::<C, _>(
        RPC.vp().pos().delegation_validators(client, address).await,
    )
}

/// Get the delegator's delegation at some epoh
pub async fn get_delegators_delegation_at<C: crate::queries::Client + Sync>(
    client: &C,
    address: &Address,
    epoch: Epoch,
) -> Result<HashMap<Address, token::Amount>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .delegations(client, address, &Some(epoch))
            .await,
    )
}

/// Query proposal by Id
pub async fn query_proposal_by_id<C: crate::queries::Client + Sync>(
    client: &C,
    proposal_id: u64,
) -> Result<Option<StorageProposal>, Error> {
    convert_response::<C, _>(
        RPC.vp().gov().proposal_id(client, &proposal_id).await,
    )
}

/// Query and return validator's commission rate and max commission rate change
/// per epoch
pub async fn query_commission_rate<C: crate::queries::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<Option<CommissionPair>, Error> {
    convert_response::<C, Option<CommissionPair>>(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )
}

/// Query and return validator's metadata, including the commission rate and max
/// commission rate change
pub async fn query_metadata<C: crate::queries::Client + Sync>(
    client: &C,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<(Option<ValidatorMetaData>, Option<CommissionPair>), Error> {
    let metadata = convert_response::<C, Option<ValidatorMetaData>>(
        RPC.vp().pos().validator_metadata(client, validator).await,
    )?;
    let commission_info = convert_response::<C, Option<CommissionPair>>(
        RPC.vp()
            .pos()
            .validator_commission(client, validator, &epoch)
            .await,
    )?;
    Ok((metadata, commission_info))
}

/// Query and return the incoming redelegation epoch for a given pair of source
/// validator and delegator, if there is any.
pub async fn query_incoming_redelegations<C: crate::queries::Client + Sync>(
    client: &C,
    src_validator: &Address,
    delegator: &Address,
) -> Result<Option<Epoch>, Error> {
    convert_response::<C, Option<Epoch>>(
        RPC.vp()
            .pos()
            .validator_incoming_redelegation(client, src_validator, delegator)
            .await,
    )
}

/// Query a validator's bonds for a given epoch
pub async fn query_bond<C: crate::queries::Client + Sync>(
    client: &C,
    source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, token::Amount>(
        RPC.vp().pos().bond(client, source, validator, &epoch).await,
    )
}

/// Query a validator's bonds for a given epoch
pub async fn query_last_infraction_epoch<C: crate::queries::Client + Sync>(
    client: &C,
    validator: &Address,
) -> Result<Option<Epoch>, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .validator_last_infraction_epoch(client, validator)
            .await,
    )
}

/// Query the accunt substorage space of an address
pub async fn get_account_info<C: crate::queries::Client + Sync>(
    client: &C,
    owner: &Address,
) -> Result<Option<Account>, error::Error> {
    convert_response::<C, Option<Account>>(
        RPC.shell().account(client, owner).await,
    )
}

/// Query if the public_key is revealed
pub async fn is_public_key_revealed<C: crate::queries::Client + Sync>(
    client: &C,
    owner: &Address,
) -> Result<bool, error::Error> {
    convert_response::<C, bool>(RPC.shell().revealed(client, owner).await)
}

/// Query an account substorage at a specific index
pub async fn get_public_key_at<C: crate::queries::Client + Sync>(
    client: &C,
    owner: &Address,
    index: u8,
) -> Result<Option<common::PublicKey>, Error> {
    let account = convert_response::<C, Option<Account>>(
        RPC.shell().account(client, owner).await,
    )?;
    if let Some(account) = account {
        Ok(account.get_public_key_from_index(index))
    } else {
        Ok(None)
    }
}

/// Query a validator's unbonds for a given epoch
pub async fn query_and_print_unbonds(
    context: &impl Namada,
    source: &Address,
    validator: &Address,
) -> Result<(), error::Error> {
    let unbonds =
        query_unbond_with_slashing(context.client(), source, validator).await?;
    let current_epoch = query_epoch(context.client()).await?;

    let mut total_withdrawable = token::Amount::zero();
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
    if !total_withdrawable.is_zero() {
        display_line!(
            context.io(),
            "Total withdrawable now: {}.",
            total_withdrawable.to_string_native()
        );
    }
    if !not_yet_withdrawable.is_empty() {
        display_line!(context.io(), "Current epoch: {current_epoch}.")
    }
    for (withdraw_epoch, amount) in not_yet_withdrawable {
        display_line!(
            context.io(),
            "Amount {} withdrawable starting from epoch {withdraw_epoch}.",
            amount.to_string_native()
        );
    }
    Ok(())
}

/// Query withdrawable tokens in a validator account for a given epoch
pub async fn query_withdrawable_tokens<C: crate::queries::Client + Sync>(
    client: &C,
    bond_source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<token::Amount, error::Error> {
    convert_response::<C, token::Amount>(
        RPC.vp()
            .pos()
            .withdrawable_tokens(client, bond_source, validator, &epoch)
            .await,
    )
}

/// Query all unbonds for a validator, applying slashes
pub async fn query_unbond_with_slashing<C: crate::queries::Client + Sync>(
    client: &C,
    source: &Address,
    validator: &Address,
) -> Result<HashMap<(Epoch, Epoch), token::Amount>, error::Error> {
    convert_response::<C, HashMap<(Epoch, Epoch), token::Amount>>(
        RPC.vp()
            .pos()
            .unbond_with_slashing(client, source, validator)
            .await,
    )
}

/// Get the givernance parameters
pub async fn query_governance_parameters<C: crate::queries::Client + Sync>(
    client: &C,
) -> GovernanceParameters {
    unwrap_client_response::<C, _>(RPC.vp().gov().parameters(client).await)
}

/// Get the givernance parameters
pub async fn query_proposal_votes<C: crate::queries::Client + Sync>(
    client: &C,
    proposal_id: u64,
) -> Result<Vec<Vote>, error::Error> {
    convert_response::<C, Vec<Vote>>(
        RPC.vp().gov().proposal_id_votes(client, &proposal_id).await,
    )
}

/// Get the bond amount at the given epoch
pub async fn get_bond_amount_at<C: crate::queries::Client + Sync>(
    client: &C,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Result<token::Amount, error::Error> {
    let total_active = convert_response::<C, Amount>(
        RPC.vp()
            .pos()
            .bond_with_slashing(client, delegator, validator, &Some(epoch))
            .await,
    )?;
    Ok(total_active)
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs.
pub async fn bonds_and_unbonds<C: crate::queries::Client + Sync>(
    client: &C,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> Result<BondsAndUnbondsDetails, error::Error> {
    convert_response::<C, _>(
        RPC.vp()
            .pos()
            .bonds_and_unbonds(client, source, validator)
            .await,
    )
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs, enriched with extra information calculated from
/// the data.
pub async fn enriched_bonds_and_unbonds<C: crate::queries::Client + Sync>(
    client: &C,
    current_epoch: Epoch,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> Result<EnrichedBondsAndUnbondsDetails, error::Error> {
    convert_response::<C, _>(
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
pub async fn validate_amount<N: Namada>(
    context: &N,
    amount: InputAmount,
    token: &Address,
    force: bool,
) -> Result<token::DenominatedAmount, Error> {
    let input_amount = match amount {
        InputAmount::Unvalidated(amt) if amt.is_zero() => return Ok(amt),
        InputAmount::Unvalidated(amt) => amt.canonical(),
        InputAmount::Validated(amt) => return Ok(amt),
    };
    let denom = match convert_response::<N::Client, Option<Denomination>>(
        RPC.vp().token().denomination(context.client(), token).await,
    )? {
        Some(denom) => Ok(denom),
        None => {
            if force {
                display_line!(
                    context.io(),
                    "No denomination found for token: {token}, but --force \
                     was passed. Defaulting to the provided denomination."
                );
                Ok(input_amount.denom())
            } else {
                display_line!(
                    context.io(),
                    "No denomination found for token: {token}, the input \
                     arguments could not be parsed."
                );
                Err(Error::from(QueryError::General(format!(
                    "denomination for token {token}"
                ))))
            }
        }
    }?;
    if denom < input_amount.denom() && !force {
        display_line!(
            context.io(),
            "The input amount contained a higher precision than allowed by \
             {token}."
        );
        Err(Error::from(QueryError::General(format!(
            "the input amount. It contained a higher precision than allowed \
             by {token}"
        ))))
    } else {
        input_amount.increase_precision(denom).map_err(|_err| {
            display_line!(
                context.io(),
                "The amount provided requires more the 256 bits to represent."
            );
            Error::from(QueryError::General(
                "the amount provided. It requires more than 256 bits to \
                 represent"
                    .to_string(),
            ))
        })
    }
}

/// Wait for a first block and node to be synced.
pub async fn wait_until_node_is_synched(
    client: &(impl Client + Sync),
    io: &impl Io,
) -> Result<(), Error> {
    let height_one = Height::try_from(1_u64).unwrap();
    let try_count = Cell::new(1_u64);
    const MAX_TRIES: usize = 5;

    time::Sleep {
        strategy: time::ExponentialBackoff {
            base: 2,
            as_duration: time::Duration::from_secs,
        },
    }
    .retry(MAX_TRIES, || async {
        let node_status = client.status().await;
        match node_status {
            Ok(status) => {
                let latest_block_height = status.sync_info.latest_block_height;
                let is_catching_up = status.sync_info.catching_up;
                let is_at_least_height_one = latest_block_height >= height_one;
                if is_at_least_height_one && !is_catching_up {
                    return ControlFlow::Break(Ok(()));
                }
                display_line!(
                    io,
                    " Waiting for {} ({}/{} tries)...",
                    if is_at_least_height_one {
                        "a first block"
                    } else {
                        "node to sync"
                    },
                    try_count.get(),
                    MAX_TRIES,
                );
                try_count.set(try_count.get() + 1);
                ControlFlow::Continue(())
            }
            Err(e) => ControlFlow::Break(Err(Error::Query(
                QueryError::General(echo_error!(
                    io,
                    "Failed to query node status with error: {e}"
                )),
            ))),
        }
    })
    .await
    // maybe time out
    .map_err(|_| {
        edisplay_line!(
            io,
            "Node is still catching up, wait for it to finish syncing."
        );
        Error::Query(QueryError::CatchingUp)
    })?
}

/// Look up the denomination of a token in order to make a correctly denominated
/// amount.
pub async fn denominate_amount<C: Client + Sync>(
    client: &C,
    io: &impl Io,
    token: &Address,
    amount: token::Amount,
) -> DenominatedAmount {
    let denom = convert_response::<C, Option<Denomination>>(
        RPC.vp().token().denomination(client, token).await,
    )
    .unwrap_or_else(|t| {
        display_line!(io, "Error in querying for denomination: {t}");
        None
    })
    .unwrap_or_else(|| {
        display_line!(
            io,
            "No denomination found for token: {token}, defaulting to zero \
             decimal places"
        );
        0.into()
    });
    DenominatedAmount::new(amount, denom)
}

/// Look up the denomination of a token in order to format it
/// correctly as a string.
pub async fn format_denominated_amount(
    client: &(impl Client + Sync),
    io: &impl Io,
    token: &Address,
    amount: token::Amount,
) -> String {
    denominate_amount(client, io, token, amount)
        .await
        .to_string()
}

/// Look up the IBC denomination from a IbcToken.
pub async fn query_ibc_denom<N: Namada>(
    context: &N,
    token: impl AsRef<str>,
    owner: Option<&Address>,
) -> String {
    let hash = match Address::decode(token.as_ref()) {
        Ok(Address::Internal(InternalAddress::IbcToken(hash))) => {
            hash.to_string()
        }
        _ => return token.as_ref().to_string(),
    };

    if let Some(owner) = owner {
        let ibc_denom_key = ibc_denom_key(owner.to_string(), &hash);
        if let Ok(ibc_denom) =
            query_storage_value::<_, String>(context.client(), &ibc_denom_key)
                .await
        {
            return ibc_denom;
        }
    }

    // No owner is specified or the owner doesn't have the token
    let ibc_denom_prefix = ibc_denom_key_prefix(None);
    if let Ok(Some(ibc_denoms)) =
        query_storage_prefix::<_, String>(context, &ibc_denom_prefix).await
    {
        for (key, ibc_denom) in ibc_denoms {
            if let Some((_, token_hash)) = is_ibc_denom_key(&key) {
                if token_hash == hash {
                    return ibc_denom;
                }
            }
        }
    }

    token.as_ref().to_string()
}
