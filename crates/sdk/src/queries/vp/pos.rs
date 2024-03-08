//! Queries router and handlers for PoS validity predicate

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::address::Address;
use namada_core::key::common;
use namada_core::storage::Epoch;
use namada_core::token;
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::queries::{
    find_delegation_validators, find_delegations,
};
use namada_proof_of_stake::slashing::{
    find_all_enqueued_slashes, find_all_slashes,
};
use namada_proof_of_stake::storage::{
    bond_handle, read_all_validator_addresses,
    read_below_capacity_validator_set_addresses_with_stake,
    read_consensus_validator_set_addresses_with_stake, read_pos_params,
    read_total_stake, read_validator_avatar, read_validator_description,
    read_validator_discord_handle, read_validator_email,
    read_validator_last_slash_epoch, read_validator_max_commission_rate_change,
    read_validator_stake, read_validator_website, unbond_handle,
    validator_commission_rate_handle, validator_incoming_redelegations_handle,
    validator_slashes_handle, validator_state_handle,
};
use namada_proof_of_stake::types::{
    BondId, BondsAndUnbondsDetail, BondsAndUnbondsDetails, CommissionPair,
    Slash, ValidatorMetaData, ValidatorState, WeightedValidator,
};
use namada_proof_of_stake::{bond_amount, query_reward_tokens};
use namada_state::{DBIter, StorageHasher, DB};
use namada_storage::collections::lazy_map;
use namada_storage::OptionExt;

use crate::queries::types::RequestCtx;

// PoS validity predicate queries
router! {POS,
    ( "validator" ) = {
        ( "is_validator" / [addr: Address] ) -> bool = is_validator,

        ( "consensus_key" / [addr: Address] ) -> Option<common::PublicKey> = consensus_key,

        ( "addresses" / [epoch: opt Epoch] )
            -> HashSet<Address> = validator_addresses,

        ( "stake" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<token::Amount> = validator_stake,

        ( "slashes" / [validator: Address] )
            -> Vec<Slash> = validator_slashes,

        ( "commission" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<CommissionPair> = validator_commission,

        ( "metadata" / [validator: Address] )
            -> Option<ValidatorMetaData> = validator_metadata,

        ( "state" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<ValidatorState> = validator_state,

        ( "incoming_redelegation" / [src_validator: Address] / [delegator: Address] )
            -> Option<Epoch> = validator_incoming_redelegation,

        ( "last_infraction_epoch" / [validator: Address] )
            -> Option<Epoch> = validator_last_infraction_epoch,
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

    ( "rewards" / [validator: Address] / [source: opt Address] )
        -> token::Amount = rewards,

    ( "bond_with_slashing" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond_with_slashing,

    ( "unbond" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond,

    ( "unbond_with_slashing" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond_with_slashing,

    ( "withdrawable_tokens" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = withdrawable_tokens,

    // NOTE: The literal "to" between source and validator is needed because
    // they are both optional and have the same types so when only one is
    // specified, without the  separator it wouldn't be clear which one (and
    // would always parse as `source`)
    ( "bonds_and_unbonds" / [source: opt Address] / "to" / [validator: opt Address] )
        -> BondsAndUnbondsDetails = bonds_and_unbonds,

    ( "enqueued_slashes" )
        -> HashMap<Address, BTreeMap<Epoch, Vec<Slash>>> = enqueued_slashes,

    ( "all_slashes" ) -> HashMap<Address, Vec<Slash>> = slashes,

    ( "is_delegator" / [addr: Address ] / [epoch: opt Epoch] ) -> bool = is_delegator,

    ( "validator_by_tm_addr" / [tm_addr: String] )
        -> Option<Address> = validator_by_tm_addr,

    ( "consensus_keys" ) -> BTreeSet<common::PublicKey> = consensus_key_set,

    ( "has_bonds" / [source: Address] )
        -> bool = has_bonds,

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
    /// Sum of the withdrawable amounts
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
fn pos_params<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<PosParams>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_pos_params(ctx.state)
}

/// Find if the given address belongs to a validator account.
fn is_validator<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    addr: Address,
) -> namada_storage::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::is_validator(ctx.state, &addr)
}

/// Find a consensus key of a validator account.
fn consensus_key<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    addr: Address,
) -> namada_storage::Result<Option<common::PublicKey>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().last_epoch;
    namada_proof_of_stake::storage::get_consensus_key(
        ctx.state,
        &addr,
        current_epoch,
    )
}

/// Find if the given address is a delegator
fn is_delegator<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    addr: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::is_delegator(ctx.state, &addr, epoch)
}

/// Get all the validator known addresses. These validators may be in any state,
/// e.g. consensus, below-capacity, inactive or jailed.
fn validator_addresses<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    read_all_validator_addresses(ctx.state, epoch)
}

/// Get the validator commission rate and max commission rate change per epoch
fn validator_commission<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<Option<CommissionPair>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params(ctx.state)?;
    let commission_rate = validator_commission_rate_handle(&validator)
        .get(ctx.state, epoch, &params)?;
    let max_commission_change_per_epoch =
        read_validator_max_commission_rate_change(ctx.state, &validator)?;

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

/// Get the validator metadata
fn validator_metadata<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
) -> namada_storage::Result<Option<ValidatorMetaData>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let email = read_validator_email(ctx.state, &validator)?;
    let description = read_validator_description(ctx.state, &validator)?;
    let website = read_validator_website(ctx.state, &validator)?;
    let discord_handle = read_validator_discord_handle(ctx.state, &validator)?;
    let avatar = read_validator_avatar(ctx.state, &validator)?;

    // Email is the only required field for a validator in storage
    match email {
        Some(email) => Ok(Some(ValidatorMetaData {
            email,
            description,
            website,
            discord_handle,
            avatar,
        })),
        _ => Ok(None),
    }
}

/// Get the validator state
fn validator_state<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<Option<ValidatorState>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params(ctx.state)?;
    let state =
        validator_state_handle(&validator).get(ctx.state, epoch, &params)?;
    Ok(state)
}

/// Get the validator state
fn validator_last_infraction_epoch<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
) -> namada_storage::Result<Option<Epoch>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    read_validator_last_slash_epoch(ctx.state, &validator)
}

/// Get the total stake of a validator at the given epoch or current when
/// `None`. The total stake is a sum of validator's self-bonds and delegations
/// to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::zero())`.
fn validator_stake<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<Option<token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params(ctx.state)?;
    if namada_proof_of_stake::is_validator(ctx.state, &validator)? {
        let stake =
            read_validator_stake(ctx.state, &params, &validator, epoch)?;
        Ok(Some(stake))
    } else {
        Ok(None)
    }
}

/// Get the incoming redelegation epoch for a source validator - delegator pair,
/// if there is any.
fn validator_incoming_redelegation<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    src_validator: Address,
    delegator: Address,
) -> namada_storage::Result<Option<Epoch>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let handle = validator_incoming_redelegations_handle(&src_validator);
    handle.get(ctx.state, &delegator)
}

/// Get all the validator in the consensus set with their bonded stake.
fn consensus_validator_set<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<BTreeSet<WeightedValidator>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    read_consensus_validator_set_addresses_with_stake(ctx.state, epoch)
}

/// Get all the validator in the below-capacity set with their bonded stake.
fn below_capacity_validator_set<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<BTreeSet<WeightedValidator>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    read_below_capacity_validator_set_addresses_with_stake(ctx.state, epoch)
}

/// Get the total stake in PoS system at the given epoch or current when `None`.
fn total_stake<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let params = read_pos_params(ctx.state)?;
    read_total_stake(ctx.state, &params, epoch)
}

fn bond_deltas<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
) -> namada_storage::Result<HashMap<Epoch, token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    bond_handle(&source, &validator).to_hashmap(ctx.state)
}

/// Find the sum of bond amount up the given epoch when `Some`, or up to the
/// pipeline length parameter offset otherwise
fn bond<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let params = read_pos_params(ctx.state)?;
    let epoch =
        epoch.unwrap_or(ctx.state.in_mem().last_epoch + params.pipeline_len);

    let handle = bond_handle(&source, &validator);
    handle
        .get_sum(ctx.state, epoch, &params)?
        .ok_or_err_msg("Cannot find bond")
}

fn bond_with_slashing<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    let bond_id = BondId { source, validator };

    bond_amount(ctx.state, &bond_id, epoch)
}

fn unbond<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
) -> namada_storage::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let handle = unbond_handle(&source, &validator);
    let iter = handle.iter(ctx.state)?;
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

fn unbond_with_slashing<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
) -> namada_storage::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    // TODO slashes
    let handle = unbond_handle(&source, &validator);
    let iter = handle.iter(ctx.state)?;
    iter.map(|next_result| {
        next_result.map(
            |(
                lazy_map::NestedSubKey::Data {
                    key: bond_epoch,
                    nested_sub_key: lazy_map::SubKey::Data(withdraw_epoch),
                },
                amount,
            )| ((bond_epoch, withdraw_epoch), amount),
        )
    })
    .collect()
}

fn withdrawable_tokens<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);

    let handle = unbond_handle(&source, &validator);
    let mut total = token::Amount::zero();
    for result in handle.iter(ctx.state)? {
        let (
            lazy_map::NestedSubKey::Data {
                key: _start,
                nested_sub_key: lazy_map::SubKey::Data(withdrawable),
            },
            amount,
        ) = result?;
        if epoch >= withdrawable {
            total += amount;
        }
    }
    Ok(total)
}

fn rewards<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
    source: Option<Address>,
) -> namada_storage::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().last_epoch;
    query_reward_tokens(ctx.state, source.as_ref(), &validator, current_epoch)
}

fn bonds_and_unbonds<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Option<Address>,
    validator: Option<Address>,
) -> namada_storage::Result<BondsAndUnbondsDetails>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::queries::bonds_and_unbonds(
        ctx.state, source, validator,
    )
}

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegation_validators<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    owner: Address,
) -> namada_storage::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    find_delegation_validators(ctx.state, &owner)
}

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegations<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    owner: Address,
    epoch: Option<Epoch>,
) -> namada_storage::Result<HashMap<Address, token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.state.in_mem().last_epoch);
    find_delegations(ctx.state, &owner, &epoch)
}

/// Validator slashes
fn validator_slashes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    validator: Address,
) -> namada_storage::Result<Vec<Slash>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let slash_handle = validator_slashes_handle(&validator);
    slash_handle.iter(ctx.state)?.collect()
}

/// All slashes
fn slashes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<HashMap<Address, Vec<Slash>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    find_all_slashes(ctx.state)
}

/// Enqueued slashes
fn enqueued_slashes<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<HashMap<Address, BTreeMap<Epoch, Vec<Slash>>>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let current_epoch = ctx.state.in_mem().last_epoch;
    find_all_enqueued_slashes(ctx.state, current_epoch)
}

/// Native validator address by looking up the Tendermint address
fn validator_by_tm_addr<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    tm_addr: String,
) -> namada_storage::Result<Option<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::storage::find_validator_by_raw_hash(
        ctx.state, tm_addr,
    )
}

/// Native validator address by looking up the Tendermint address
fn consensus_key_set<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
) -> namada_storage::Result<BTreeSet<common::PublicKey>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::storage::get_consensus_key_set(ctx.state)
}

/// Find if the given source address has any bonds.
fn has_bonds<D, H, V, T>(
    ctx: RequestCtx<'_, D, H, V, T>,
    source: Address,
) -> namada_storage::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    namada_proof_of_stake::queries::has_bonds(ctx.state, &source)
}

/// Client-only methods for the router type are composed from router functions.
#[cfg(any(test, feature = "async-client"))]
pub mod client_only_methods {
    use super::*;
    use crate::queries::{Client, RPC};

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
