use std::collections::{BTreeMap, BTreeSet};

use namada_core::ledger::governance::storage::proposal::StorageProposal;
use namada_core::ledger::governance::utils::{Vote, VotePower};
use namada_core::types::address::Address;

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::{governance, storage_api};

// PoS validity predicate queries
router! {GOV,
    ( "proposal" / [id: u64 ] ) -> Option<StorageProposal> = proposal_id,
    ( "proposal" / [id: u64 ] / "vote" ) -> Vec<Vote>= proposal_id_votes,
    ( "delegate" ) -> BTreeSet<Address> = delegate_set,
    ( "delegator" / [delegate: Address] / "delegate" ) -> Option<Address> = delegate_for,
    ( "delegate" / [delegate: Address] / "delegations" ) -> BTreeMap<Address, VotePower> = delegations,
    ( "is_delegate" / [delegate: Address] ) -> bool = is_delegate,
}

/// Find if the given address belongs to a validator account.
fn proposal_id<D, H>(
    ctx: RequestCtx<'_, D, H>,
    id: u64,
) -> storage_api::Result<Option<StorageProposal>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_proposal_by_id(ctx.wl_storage, id)
}

/// Find if the given address belongs to a validator account.
fn proposal_id_votes<D, H>(
    ctx: RequestCtx<'_, D, H>,
    id: u64,
) -> storage_api::Result<Vec<Vote>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_proposal_votes(ctx.wl_storage, id)
}

/// Find the current delegate set
fn delegate_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
) -> storage_api::Result<BTreeSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::get_delegate_set(ctx.wl_storage)
}

/// Check if an address is a delegate
fn is_delegate<D, H>(
    ctx: RequestCtx<'_, D, H>,
    delegate: Address,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::is_delegate(ctx.wl_storage, delegate)
}

/// Get all delegations for a specific delegator
fn delegations<D, H>(
    ctx: RequestCtx<'_, D, H>,
    delegate: Address,
) -> storage_api::Result<BTreeMap<Address, VotePower>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut delations_with_voting_power = BTreeMap::new();
    let delegations =
        storage_api::governance::delegations(ctx.wl_storage, delegate.clone())?;
    for delegation in delegations {
        let bonds = namada_proof_of_stake::bonds_and_unbonds(
            ctx.wl_storage,
            Some(delegation.clone()),
            None,
        )?;
        let bonds_sum = bonds.iter().fold(
            VotePower::default(),
            |acc, (_, bonds_detail)| {
                acc + bonds_detail
                    .bonds
                    .iter()
                    .fold(VotePower::default(), |acc, bond_detail| {
                        acc + bond_detail.amount
                    })
            },
        );
        delations_with_voting_power.insert(delegation, bonds_sum);
    }

    Ok(delations_with_voting_power)
}

/// Get the delegate of a specific delegator
fn delegate_for<D, H>(
    ctx: RequestCtx<'_, D, H>,
    delegator: Address,
) -> storage_api::Result<Option<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    storage_api::governance::delegate_for(ctx.wl_storage, delegator)
}
