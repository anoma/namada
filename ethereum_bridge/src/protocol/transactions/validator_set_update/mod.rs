//! Code for handling validator set update protocol txs.

use std::collections::{HashMap, HashSet};

use eyre::Result;
use namada_core::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada_core::types::address::Address;
use namada_core::types::storage::BlockHeight;
#[allow(unused_imports)]
use namada_core::types::transaction::protocol::ProtocolTxType;
use namada_core::types::transaction::TxResult;
use namada_core::types::vote_extensions::validator_set_update;
use namada_core::types::voting_power::FractionalVotingPower;
use namada_proof_of_stake::pos_queries::PosQueries;

use super::ChangedKeys;
use crate::protocol::transactions::utils;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{self, Votes};
use crate::storage::vote_tallies;

impl utils::GetVoters for validator_set_update::VextDigest {
    #[inline]
    fn get_voters(&self) -> HashSet<(Address, BlockHeight)> {
        self.signatures.keys().cloned().collect()
    }
}

pub fn aggregate_votes<D, H>(
    storage: &mut Storage<D, H>,
    ext: validator_set_update::VextDigest,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if ext.signatures.is_empty() {
        tracing::debug!("Ignoring empty validator set update");
        return Ok(Default::default());
    }

    tracing::info!(
        num_votes = ext.signatures.len(),
        "Aggregating new votes for validator set update"
    );

    let voting_powers = utils::get_voting_powers(storage, &ext)?;
    let changed_keys = apply_update(storage, ext, voting_powers)?;

    Ok(TxResult {
        changed_keys,
        ..Default::default()
    })
}

// TODO: change Keys<T>: add (HashSet<Signature>, VotingPowersMap) as body;
// extend signatures set instead of voting powers map!
fn apply_update<D, H>(
    storage: &mut Storage<D, H>,
    ext: validator_set_update::VextDigest,
    voting_powers: HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<ChangedKeys>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = {
        // all votes we gathered are for the same epoch, so
        // we can just fetch the block height from the first
        // signature we iterate over, and calculate its cor-
        // responding epoch
        let height = ext
            .signatures
            .keys()
            .map(|(_, height)| *height)
            .by_ref()
            .next()
            .expect(
                "We have at least one signature present in this validator set \
                 update vote extension digest",
            );

        storage
            .get_epoch(height)
            .expect("The epoch of the given block height should be known")
    };

    let valset_upd_keys = vote_tallies::Keys::from(&epoch);
    let maybe_body = 'check_storage: {
        let Some(seen) = votes::storage::maybe_read_seen(storage, &valset_upd_keys)? else {
            break 'check_storage None;
        };
        if seen {
            tracing::debug!("Validator set update tally is already seen");
            return Ok(ChangedKeys::default());
        }
        let body: HashMap<_, _> =
            votes::storage::read_body(storage, &valset_upd_keys)?;
        Some(body)
    };

    let mut seen_by = Votes::default();
    for (address, block_height) in ext.signatures.into_keys() {
        if let Some(present) = seen_by.insert(address, block_height) {
            // TODO(namada#770): this shouldn't be happening in any case and we
            // should be refactoring to get rid of `BlockHeight`
            tracing::warn!(?present, "Duplicate vote in digest");
        }
    }

    let (tally, body, changed, confirmed) = if let Some(mut body) = maybe_body {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Validator set update votes already in storage",
        );
        let new_votes = NewVotes::new(seen_by, &voting_powers)?;
        let (tally, changed) =
            votes::update::calculate(storage, &valset_upd_keys, new_votes)?;
        if changed.is_empty() {
            return Ok(changed);
        }
        let confirmed = tally.seen && changed.contains(&valset_upd_keys.seen());
        body.extend(ext.voting_powers);
        (tally, body, changed, confirmed)
    } else {
        tracing::debug!(
            %valset_upd_keys.prefix,
            ?ext.voting_powers,
            "New validator set update vote aggregation started"
        );
        let tally = votes::calculate_new(seen_by, &voting_powers)?;
        let body: HashMap<_, _> = ext.voting_powers.into_iter().collect();
        let changed = valset_upd_keys.into_iter().collect();
        let confirmed = tally.seen;
        (tally, body, changed, confirmed)
    };

    tracing::debug!(
        ?tally,
        voting_powers = ?body,
        "Applying validator set update state changes"
    );
    votes::storage::write(storage, &valset_upd_keys, &body, &tally)?;

    if confirmed {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Acquired complete proof on validator set update"
        );
    }

    Ok(changed)
}
