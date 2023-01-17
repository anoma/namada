use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::Result;
use namada_core::ledger::eth_bridge::storage::bridge_pool::{
    get_nonce_key, get_signed_root_key,
};
use namada_core::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::Uint;
use namada_core::types::keccak::KeccakHash;
use namada_core::types::storage::BlockHeight;
use namada_core::types::transaction::TxResult;
use namada_core::types::vote_extensions::bridge_pool_roots::MultiSignedVext;
use namada_core::types::voting_power::FractionalVotingPower;

use crate::protocol::transactions::utils::GetVoters;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{calculate_new, Votes};
use crate::protocol::transactions::{utils, votes, ChangedKeys};
use crate::storage::eth_bridge_queries::EthBridgeQueries;
use crate::storage::vote_tallies;
use crate::storage::vote_tallies::{BridgePoolNonce, BridgePoolRoot};

/// Applies a tally of signatures on over the Ethereum
/// bridge pool root and nonce.
///
/// For roots + nonces which have been seen by a quorum of
/// validators, the signature is made available for bridge
/// pool proofs.
pub fn apply_derived_tx<D, H>(
    storage: &mut Storage<D, H>,
    sigs: MultiSignedVext,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if sigs.is_empty() {
        return Ok(TxResult::default());
    }
    tracing::info!(
        bp_root_sigs = sigs.len(),
        "Applying state updates derived from signatures of the Ethereum \
         bridge pool root and nonce."
    );
    let bp_root = parse_vexts(storage, sigs);
    let voting_powers = utils::get_voting_powers(storage, &bp_root)?;

    // apply updates to the bridge pool root.
    let (mut changed, confirmed) = apply_update(
        storage,
        BridgePoolRoot::from(bp_root.root.clone()),
        bp_root.seen_by.clone(),
        &voting_powers,
    )?;

    // if the root is confirmed, update storage and add
    // relevant key to changed.
    if confirmed {
        storage
            .write(
                &get_signed_root_key(),
                bp_root
                    .root
                    .try_to_vec()
                    .expect("Serializing a Keccak hash should not fail."),
            )
            .expect(
                "Writing a signed bridge pool root to storage should not fail.",
            );
        changed.insert(get_signed_root_key());
    }

    // apply updates to the bridge pool nonce.
    let (mut nonce_changed, confirmed) = apply_update(
        storage,
        BridgePoolNonce::from(bp_root.nonce.clone()),
        bp_root.seen_by.clone(),
        &voting_powers,
    )?;
    // add newly changed keys
    changed.append(&mut nonce_changed);

    // if the nonce is confirmed, update storage and add
    // relevant key to changed.
    if confirmed {
        storage
            .write(
                &get_nonce_key(),
                bp_root
                    .nonce
                    .try_to_vec()
                    .expect("Serializing a Uint should not fail."),
            )
            .expect("Writing a signed bridge pool nonce should not fail");
        changed.insert(get_nonce_key());
    }
    Ok(TxResult {
        changed_keys: changed,
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
        self.seen_by.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

/// Convert a set of signatures over bridge pool roots (at a certain
/// height) + latest nonce into a set of [`PendingQuorum`].
fn parse_vexts<D, H>(
    storage: &Storage<D, H>,
    multisigned: MultiSignedVext,
) -> PendingQuorum
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let seen_by: Votes = multisigned
        .into_iter()
        .map(|signed| (signed.data.validator_addr, signed.data.block_height))
        .collect();
    let height = seen_by.values().next().unwrap();
    let root = storage.get_bridge_pool_root_at_height(*height);
    PendingQuorum {
        root,
        seen_by,
        nonce: storage.get_bridge_pool_nonce(),
    }
}

/// This vote updates the voting power backing a bridge pool root / nonce in
/// storage. If a quorum backs the root / nonce, a boolean is returned
/// indicating that it has been confirmed.
///
/// In all instances, the changed storage keys are returned.
fn apply_update<D, H, T>(
    storage: &mut Storage<D, H>,
    update: T,
    seen_by: Votes,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<(ChangedKeys, bool)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    T: Into<vote_tallies::Keys<T>> + BorshSerialize + BorshDeserialize + Clone,
{
    let bp_key = update.clone().into();
    let (exists_in_storage, _) = storage.has_key(&bp_key.seen())?;
    let (vote_tracking, changed, confirmed) = if !exists_in_storage {
        tracing::debug!(%bp_key.prefix, "No validator has signed this bridge pool update before.");
        let vote_tracking = calculate_new(seen_by, voting_powers)?;
        let changed = bp_key.into_iter().collect();
        let confirmed = vote_tracking.seen;
        (vote_tracking, changed, confirmed)
    } else {
        tracing::debug!(
            %bp_key.prefix,
            "Signatures for this Bridge pool update already exists in storage",
        );
        let new_votes = NewVotes::new(seen_by, voting_powers)?;
        let (vote_tracking, changed) =
            votes::update::calculate(storage, &bp_key, new_votes)?;
        if changed.is_empty() {
            return Ok((changed, false));
        }
        let confirmed = vote_tracking.seen && changed.contains(&bp_key.seen());
        (vote_tracking, changed, confirmed)
    };

    votes::storage::write(storage, &bp_key, &update, &vote_tracking)?;
    Ok((changed, confirmed))
}
