//! Queries router and handlers for PoS validity predicate

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::ledger::storage_api::collections::lazy_map;
use namada_core::ledger::storage_api::OptionExt;
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::{
    BondId, BondsAndUnbondsDetail, BondsAndUnbondsDetails, CommissionPair,
    Slash, ValidatorState, WeightedValidator,
};
use namada_proof_of_stake::{
    self, bond_amount, bond_handle, find_all_enqueued_slashes,
    find_all_slashes, find_delegation_validators, find_delegations,
    read_all_validator_addresses,
    read_below_capacity_validator_set_addresses_with_stake,
    read_consensus_validator_set_addresses_with_stake, read_pos_params,
    read_total_stake, read_validator_max_commission_rate_change,
    read_validator_stake, unbond_handle, validator_commission_rate_handle,
    validator_incoming_redelegations_handle, validator_slashes_handle,
    validator_state_handle,
};

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

// PoS validity predicate queries
router! {POS,
    ( "validator" ) = {
        ( "is_validator" / [addr: Address] ) -> bool = is_validator,

        ( "addresses" / [epoch: opt Epoch] )
            -> HashSet<Address> = validator_addresses,

        ( "stake" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<token::Amount> = validator_stake,

        ( "slashes" / [validator: Address] )
            -> Vec<Slash> = validator_slashes,

        ( "commission" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<CommissionPair> = validator_commission,

        ( "state" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<ValidatorState> = validator_state,

        ( "incoming_redelegation" / [src_validator: Address] / [delegator: Address] )
            -> Option<Epoch> = validator_incoming_redelegation,
    },

    ( "validator_set" ) = {
        ( "consensus" / [epoch: opt Epoch] )
            -> BTreeSet<WeightedValidator> = consensus_validator_set,

        ( "below_capacity" / [epoch: opt Epoch] )
            -> BTreeSet<WeightedValidator> = below_capacity_validator_set,

        // TODO: add "below_threshold"
    },

    ( "pos_params") -> PosParams = pos_params,

    ( "total_stake" / [epoch: opt Epoch] )
        -> token::Amount = total_stake,

    ( "delegations" / [owner: Address] )
        -> HashSet<Address> = delegation_validators,

    ( "delegations_at" / [owner: Address] / [epoch: opt Epoch] )
        -> HashMap<Address, token::Amount> = delegations,

    ( "bond_deltas" / [source: Address] / [validator: Address] )
        -> HashMap<Epoch, token::Change> = bond_deltas,

    ( "bond" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond,

    ( "bond_with_slashing" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond_with_slashing,

    ( "unbond" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond,

    ( "unbond_with_slashing" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond_with_slashing,

    ( "withdrawable_tokens" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = withdrawable_tokens,

    ( "bonds_and_unbonds" / [source: opt Address] / [validator: opt Address] )
        -> BondsAndUnbondsDetails = bonds_and_unbonds,

    ( "enqueued_slashes" )
        -> HashMap<Address, BTreeMap<Epoch, Vec<Slash>>> = enqueued_slashes,

    ( "all_slashes" ) -> HashMap<Address, Vec<Slash>> = slashes,

    ( "is_delegator" / [addr: Address ] / [epoch: opt Epoch] ) -> bool = is_delegator,

    ( "validator_by_tm_addr" / [tm_addr: String] )
        -> Option<Address> = validator_by_tm_addr,

}

/// Enriched bonds data with extra information calculated from the data queried
/// from the node.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct Enriched<T> {
    /// The queried data
    pub data: T,
    /// Sum of the bond amounts
    pub bonds_total: token::Amount,
    /// Sum of the bond slashed amounts
    pub bonds_total_slashed: token::Amount,
    /// Sum of the unbond amounts
    pub unbonds_total: token::Amount,
    /// Sum of the unbond slashed amounts
    pub unbonds_total_slashed: token::Amount,
    /// Sum ofthe withdrawable amounts
    pub total_withdrawable: token::Amount,
}

/// Bonds and unbonds with all details (slashes and rewards, if any) grouped by
/// their bond IDs enriched with extra information calculated from the data
/// queried from the node.
pub type EnrichedBondsAndUnbondsDetails =
    Enriched<HashMap<BondId, EnrichedBondsAndUnbondsDetail>>;

/// Bonds and unbonds with all details (slashes and rewards, if any) enriched
/// with extra information calculated from the data queried from the node.
pub type EnrichedBondsAndUnbondsDetail = Enriched<BondsAndUnbondsDetail>;

impl<T> Enriched<T> {
    /// The bonds amount reduced by slashes
    pub fn bonds_total_active(&self) -> token::Amount {
        self.bonds_total - self.bonds_total_slashed
    }

    /// The unbonds amount reduced by slashes
    pub fn unbonds_total_active(&self) -> token::Amount {
        self.unbonds_total - self.unbonds_total_slashed
    }
}

// Handlers that implement the functions via `trait StorageRead`:

/// Get the PoS parameters
fn pos_params<D, H>(ctx: RequestCtx<'_, D, H>) -> storage_api::Result<PosParams>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_pos_params(ctx.wl_storage)
}

/// Find if the given address belongs to a validator account.
fn is_validator<D, H>(
    ctx: RequestCtx<'_, D, H>,
    addr: Address,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::is_validator(ctx.wl_storage, &addr)
}

/// Find if the given address is a delegator
fn is_delegator<D, H>(
    ctx: RequestCtx<'_, D, H>,
    addr: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::is_delegator(ctx.wl_storage, &addr, epoch)
}

/// Get all the validator known addresses. These validators may be in any state,
/// e.g. consensus, below-capacity, inactive or jailed.
fn validator_addresses<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    read_all_validator_addresses(ctx.wl_storage, epoch)
}

/// Get the validator commission rate and max commission rate change per epoch
fn validator_commission<D, H>(
    ctx: RequestCtx<'_, D, H>,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<Option<CommissionPair>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    let commission_rate = validator_commission_rate_handle(&validator).get(
        ctx.wl_storage,
        epoch,
        &params,
    )?;
    let max_commission_change_per_epoch =
        read_validator_max_commission_rate_change(ctx.wl_storage, &validator)?;

    match (commission_rate, max_commission_change_per_epoch) {
        (Some(commission_rate), Some(max_commission_change_per_epoch)) => {
            Ok(Some(CommissionPair {
                commission_rate,
                max_commission_change_per_epoch,
            }))
        }
        _ => Ok(None),
    }
}

/// Get the validator state
fn validator_state<D, H>(
    ctx: RequestCtx<'_, D, H>,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<Option<ValidatorState>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    let state = validator_state_handle(&validator).get(
        ctx.wl_storage,
        epoch,
        &params,
    )?;
    Ok(state)
}

/// Get the total stake of a validator at the given epoch or current when
/// `None`. The total stake is a sum of validator's self-bonds and delegations
/// to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::zero())`.
fn validator_stake<D, H>(
    ctx: RequestCtx<'_, D, H>,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<Option<token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    if namada_proof_of_stake::is_validator(ctx.wl_storage, &validator)? {
        let stake =
            read_validator_stake(ctx.wl_storage, &params, &validator, epoch)?;
        Ok(Some(stake))
    } else {
        Ok(None)
    }
}

/// Get the incoming redelegation epoch for a source validator - delegator pair,
/// if there is any.
fn validator_incoming_redelegation<D, H>(
    ctx: RequestCtx<'_, D, H>,
    src_validator: Address,
    delegator: Address,
) -> storage_api::Result<Option<Epoch>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let handle = validator_incoming_redelegations_handle(&src_validator);
    handle.get(ctx.wl_storage, &delegator)
}

/// Get all the validator in the consensus set with their bonded stake.
fn consensus_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<BTreeSet<WeightedValidator>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    read_consensus_validator_set_addresses_with_stake(ctx.wl_storage, epoch)
}

/// Get all the validator in the below-capacity set with their bonded stake.
fn below_capacity_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<BTreeSet<WeightedValidator>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    read_below_capacity_validator_set_addresses_with_stake(
        ctx.wl_storage,
        epoch,
    )
}

/// Get the total stake in PoS system at the given epoch or current when `None`.
fn total_stake<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    read_total_stake(ctx.wl_storage, &params, epoch)
}

fn bond_deltas<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
) -> storage_api::Result<HashMap<Epoch, token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    bond_handle(&source, &validator).to_hashmap(ctx.wl_storage)
}

/// Find the sum of bond amount up the given epoch when `Some`, or up to the
/// pipeline length parameter offset otherwise
fn bond<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let params = read_pos_params(ctx.wl_storage)?;
    let epoch = epoch
        .unwrap_or(ctx.wl_storage.storage.last_epoch + params.pipeline_len);

    let handle = bond_handle(&source, &validator);
    handle
        .get_sum(ctx.wl_storage, epoch, &params)?
        .ok_or_err_msg("Cannot find bond")
}

fn bond_with_slashing<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let bond_id = BondId { source, validator };

    bond_amount(ctx.wl_storage, &bond_id, epoch)
}

fn unbond<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
) -> storage_api::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let handle = unbond_handle(&source, &validator);
    let iter = handle.iter(ctx.wl_storage)?;
    iter.map(|next_result| {
        next_result.map(
            |(
                lazy_map::NestedSubKey::Data {
                    key: withdraw_epoch,
                    nested_sub_key: lazy_map::SubKey::Data(bond_epoch),
                },
                amount,
            )| ((bond_epoch, withdraw_epoch), amount),
        )
    })
    .collect()
}

fn unbond_with_slashing<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
) -> storage_api::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // TODO slashes
    let handle = unbond_handle(&source, &validator);
    let iter = handle.iter(ctx.wl_storage)?;
    iter.map(|next_result| {
        next_result.map(
            |(
                lazy_map::NestedSubKey::Data {
                    key: withdraw_epoch,
                    nested_sub_key: lazy_map::SubKey::Data(bond_epoch),
                },
                amount,
            )| ((bond_epoch, withdraw_epoch), amount),
        )
    })
    .collect()
}

fn withdrawable_tokens<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);

    let handle = unbond_handle(&source, &validator);
    let mut total = token::Amount::zero();
    for result in handle.iter(ctx.wl_storage)? {
        let (
            lazy_map::NestedSubKey::Data {
                key: end,
                nested_sub_key: lazy_map::SubKey::Data(_start),
            },
            amount,
        ) = result?;
        if end <= epoch {
            total += amount;
        }
    }
    Ok(total)
}

fn bonds_and_unbonds<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Option<Address>,
    validator: Option<Address>,
) -> storage_api::Result<BondsAndUnbondsDetails>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::bonds_and_unbonds(ctx.wl_storage, source, validator)
}

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegation_validators<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
) -> storage_api::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    find_delegation_validators(ctx.wl_storage, &owner)
}

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegations<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashMap<Address, token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    find_delegations(ctx.wl_storage, &owner, &epoch)
}

/// Validator slashes
fn validator_slashes<D, H>(
    ctx: RequestCtx<'_, D, H>,
    validator: Address,
) -> storage_api::Result<Vec<Slash>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let slash_handle = validator_slashes_handle(&validator);
    slash_handle.iter(ctx.wl_storage)?.collect()
}

/// All slashes
fn slashes<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<HashMap<Address, Vec<Slash>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    find_all_slashes(ctx.wl_storage)
}

/// Enqueued slashes
fn enqueued_slashes<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<HashMap<Address, BTreeMap<Epoch, Vec<Slash>>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.wl_storage.storage.last_epoch;
    find_all_enqueued_slashes(ctx.wl_storage, current_epoch)
}

/// Native validator address by looking up the Tendermint address
fn validator_by_tm_addr<D, H>(
    ctx: RequestCtx<'_, D, H>,
    tm_addr: String,
) -> storage_api::Result<Option<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::find_validator_by_raw_hash(ctx.wl_storage, tm_addr)
}

/// Client-only methods for the router type are composed from router functions.
#[cfg(any(test, feature = "async-client"))]
pub mod client_only_methods {
    use super::*;
    use crate::ledger::queries::RPC;
    use crate::sdk::queries::Client;

    impl Pos {
        /// Get bonds and unbonds with all details (slashes and rewards, if any)
        /// grouped by their bond IDs, enriched with extra information
        /// calculated from the data.
        pub async fn enriched_bonds_and_unbonds<CLIENT>(
            &self,
            client: &CLIENT,
            current_epoch: Epoch,
            source: &Option<Address>,
            validator: &Option<Address>,
        ) -> Result<EnrichedBondsAndUnbondsDetails, <CLIENT as Client>::Error>
        where
            CLIENT: Client + Sync,
        {
            let data = RPC
                .vp()
                .pos()
                .bonds_and_unbonds(client, source, validator)
                .await?;
            Ok(enrich_bonds_and_unbonds(current_epoch, data))
        }
    }
}

/// Calculate extra information from the bonds and unbonds details.
fn enrich_bonds_and_unbonds(
    current_epoch: Epoch,
    bonds_and_unbonds: BondsAndUnbondsDetails,
) -> EnrichedBondsAndUnbondsDetails {
    let mut bonds_total: token::Amount = 0.into();
    let mut bonds_total_slashed: token::Amount = 0.into();
    let mut unbonds_total: token::Amount = 0.into();
    let mut unbonds_total_slashed: token::Amount = 0.into();
    let mut total_withdrawable: token::Amount = 0.into();

    let enriched_details: HashMap<BondId, EnrichedBondsAndUnbondsDetail> =
        bonds_and_unbonds
            .into_iter()
            .map(|(bond_id, detail)| {
                let mut bond_total: token::Amount = 0.into();
                let mut bond_total_slashed: token::Amount = 0.into();
                let mut unbond_total: token::Amount = 0.into();
                let mut unbond_total_slashed: token::Amount = 0.into();
                let mut withdrawable: token::Amount = 0.into();

                for bond in &detail.bonds {
                    bond_total += bond.amount;
                    bond_total_slashed +=
                        bond.slashed_amount.unwrap_or_default();
                }
                for unbond in &detail.unbonds {
                    unbond_total += unbond.amount;
                    unbond_total_slashed +=
                        unbond.slashed_amount.unwrap_or_default();

                    if current_epoch >= unbond.withdraw {
                        withdrawable += unbond.amount
                            - unbond.slashed_amount.unwrap_or_default()
                    }
                }

                bonds_total += bond_total;
                bonds_total_slashed += bond_total_slashed;
                unbonds_total += unbond_total;
                unbonds_total_slashed += unbond_total_slashed;
                total_withdrawable += withdrawable;

                let enriched_detail = EnrichedBondsAndUnbondsDetail {
                    data: detail,
                    bonds_total: bond_total,
                    bonds_total_slashed: bond_total_slashed,
                    unbonds_total: unbond_total,
                    unbonds_total_slashed: unbond_total_slashed,
                    total_withdrawable: withdrawable,
                };
                (bond_id, enriched_detail)
            })
            .collect();
    EnrichedBondsAndUnbondsDetails {
        data: enriched_details,
        bonds_total,
        bonds_total_slashed,
        unbonds_total,
        unbonds_total_slashed,
        total_withdrawable,
    }
}
