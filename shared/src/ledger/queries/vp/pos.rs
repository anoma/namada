use std::collections::{HashMap, HashSet};

use namada_core::ledger::storage_api::collections::lazy_map;
use namada_core::ledger::storage_api::OptionExt;
use namada_proof_of_stake::types::{
    BondId, BondsAndUnbondsDetails, CommissionPair, Slash, WeightedValidator,
};
use namada_proof_of_stake::{
    self, below_capacity_validator_set_handle, bond_amount, bond_handle,
    consensus_validator_set_handle, find_all_slashes,
    find_delegation_validators, find_delegations, read_all_validator_addresses,
    read_pos_params, read_total_stake,
    read_validator_max_commission_rate_change, read_validator_stake,
    unbond_handle, validator_commission_rate_handle, validator_slashes_handle,
};

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

type AmountPair = (token::Amount, token::Amount);

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
    },

    ( "validator_set" ) = {
        ( "consensus" / [epoch: opt Epoch] )
            -> HashSet<WeightedValidator> = consensus_validator_set,

        ( "below_capacity" / [epoch: opt Epoch] )
            -> HashSet<WeightedValidator> = below_capacity_validator_set,

        // TODO: add "below_threshold"
    },

    ( "total_stake" / [epoch: opt Epoch] )
        -> token::Amount = total_stake,

    ( "delegations" / [owner: Address] )
        -> HashSet<Address> = delegation_validators,

    ( "delegations_at" / [owner: Address] / [epoch: opt Epoch])
        -> HashMap<Address, token::Amount> = delegations_at,

    ( "bond_deltas" / [source: Address] / [validator: Address] )
        -> HashMap<Epoch, token::Change> = bond_deltas,

    ( "bond" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond,

    ( "bond_with_slashing" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> AmountPair = bond_with_slashing,

    ( "unbond" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond,

    ( "unbond_with_slashing" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond_with_slashing,

    ( "withdrawable_tokens" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = withdrawable_tokens,

    ( "bonds_and_unbonds" / [source: opt Address] / [validator: opt Address] )
        -> BondsAndUnbondsDetails = bonds_and_unbonds,

    ( "all_slashes" ) -> HashMap<Address, Vec<Slash>> = slashes,

    ( "is_delegator" / [addr: Address ] / [epoch: opt Epoch] ) -> bool = is_delegator,

}

// Handlers that implement the functions via `trait StorageRead`:

/// Find if the given address belongs to a validator account.
fn is_validator<D, H>(
    ctx: RequestCtx<'_, D, H>,
    addr: Address,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let params = namada_proof_of_stake::read_pos_params(ctx.wl_storage)?;
    namada_proof_of_stake::is_validator(
        ctx.wl_storage,
        &addr,
        &params,
        ctx.wl_storage.storage.block.epoch,
    )
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

/// Get the total stake of a validator at the given epoch or current when
/// `None`. The total stake is a sum of validator's self-bonds and delegations
/// to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::default())`.
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
    read_validator_stake(ctx.wl_storage, &params, &validator, epoch)
}

/// Get all the validator in the consensus set with their bonded stake.
fn consensus_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<WeightedValidator>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    consensus_validator_set_handle()
        .at(&epoch)
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _position,
                    },
                    address,
                )| {
                    WeightedValidator {
                        bonded_stake,
                        address,
                    }
                },
            )
        })
        .collect()
}

/// Get all the validator in the below-capacity set with their bonded stake.
fn below_capacity_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<WeightedValidator>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    below_capacity_validator_set_handle()
        .at(&epoch)
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _position,
                    },
                    address,
                )| {
                    WeightedValidator {
                        bonded_stake: bonded_stake.into(),
                        address,
                    }
                },
            )
        })
        .collect()
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
) -> storage_api::Result<HashMap<Epoch, token::Change>>
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
        .map(token::Amount::from_change)
        .ok_or_err_msg("Cannot find bond")
}

fn bond_with_slashing<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<AmountPair>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    let bond_id = BondId { source, validator };

    bond_amount(ctx.wl_storage, &params, &bond_id, epoch)
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
    let unbonds = handle
        .iter(ctx.wl_storage)?
        .map(|next_result| {
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
        .collect();
    unbonds
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
    let unbonds = handle
        .iter(ctx.wl_storage)?
        .map(|next_result| {
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
        .collect();
    unbonds
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
    let mut total = token::Amount::default();
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
fn delegations_at<D, H>(
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
