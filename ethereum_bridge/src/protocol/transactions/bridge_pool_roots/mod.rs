use std::collections::{HashMap, HashSet};

use eyre::Result;
use namada_core::ledger::storage::{DB, DBIter, Storage, StorageHasher};
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::Uint;
use namada_core::types::keccak::KeccakHash;
use namada_core::types::storage::BlockHeight;
use namada_core::types::transaction::TxResult;
use namada_core::types::vote_extensions::bridge_pool_roots;
use namada_core::types::vote_extensions::bridge_pool_roots::MultiSignedVext;
use namada_core::types::voting_power::FractionalVotingPower;

use crate::protocol::transactions::{ChangedKeys, utils, votes};
use crate::protocol::transactions::utils::GetVoters;
use crate::protocol::transactions::votes::{calculate_new, Votes};
use crate::protocol::transactions::votes::update::NewVotes;
use crate::storage::eth_bridge_queries::EthBridgeQueries;
use crate::storage::vote_tallies;
use crate::storage::vote_tallies::BridgePoolKeys;

/// Applies a tally of signatures on over the Ethereum
/// bridge pool root and nonce.
///
/// For roots + nonces which have been seen by a quorum of
/// validators, the signature is made available for bridge
/// pool proofs.
pub fn apply_derived_tx<D, H>(
    storage: &mut Storage<D, H>,
    sigs: bridge_pool_roots::MultiSignedVext,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if sigs.is_empty() {
        return Ok(TxResult::default());
    }
    tracing::info!(
        ethereum_events = events.len(),
        "Applying state updates derived from signatures of \
         the Ethereum bridge pool root and nonce."
    );
    let bp_root = parse_vexts(&storage, bridge_pool_roots);
    let voting_powers = utils::get_voting_powers(&storage, &bp_root);
    Ok(TxResult {
        changed_keys,
        ..Default::default()
    })
}

/// An Ethereum bridge pool root + nonce still awaiting
/// a quorum of backing signatures to make in on chain.
struct PendingQuorum {
    /// The root of bridge pool being signed off on.
    pub root: KeccakHash,
    /// The nonce of bridge pool being signed off on.
    pub nonce: Uint,
    /// The validators who have already signed off
    /// on this root + nonce
    pub seen_by: Votes,
}

impl GetVoters for PendingQuorum {
    fn get_voters(&self) -> HashSet<(Address, BlockHeight)> {
        self.seen_by.iter().cloned().collect()
    }
}

/// Convert a set of signatures over bridge pool roots (at a certain
/// height) + latest nonce into a set of [`PendingQuorum`].
fn parse_vexts<D, H>(storage: &Storage<D, H>, multisigned: MultiSignedVext) -> PendingQuorum
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let seen_by = multisigned.into_iter()
        .map(|signed| (signed.data.validator_addr, signed.data.block_height))
        .collect();
    let height = seen_by.values().next().unwrap();
    let root = storage.get_bridge_pool_root_at_height(height);
    PendingQuorum {
        root,
        seen_by,
        nonce: storage.get_bridge_pool_nonce(),
    }
}

fn apply_root_update<D, H>(
    storage: &mut Storage<D, H>,
    update: &PendingQuorum,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<(ChangedKeys, bool)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let bp_root_key: BridgePoolKeys = vote_tallies::Keys::from(&update.root);
    let (exists_in_storage, _) = storage.has_key(&bp_root_key.seen())?;
    let (vote_tracking, changed, confirmed) = if !exists_in_storage {
        tracing::debug!(%eth_msg_keys.prefix, "No validator has signed this bridge pool root before.");
        let vote_tracking = calculate_new(update.seen_by.clone(), voting_powers)?;
        let changed = bp_root_key.into_iter().collect();
        let confirmed = vote_tracking.seen;
        (vote_tracking, changed, confirmed)
    } else {
        tracing::debug!(
            %eth_msg_keys.prefix,
            "Signatures for this Bridge pool root already exist in storage",
        );
        let new_votes = NewVotes::new(update.seen_by.clone(), voting_powers)?;
        let (vote_tracking, changed) =
            votes::update::calculate(storage, &eth_msg_keys, new_votes)?;
        if changed.is_empty() {
            return Ok((changed, false));
        }
        let confirmed =
            vote_tracking.seen && changed.contains(&eth_msg_keys.seen());
        (vote_tracking, changed, confirmed)
    };

    votes::storage::write(
        storage,
        &bp_root_key,
        &update.root,
        &vote_tracking,
    )?;
    Ok((changed, confirmed))
}
