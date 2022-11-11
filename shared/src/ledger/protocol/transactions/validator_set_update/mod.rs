//! Code for handling validator set update protocol txs.

use std::collections::{HashMap, HashSet};

use eyre::Result;

use super::ChangedKeys;
use crate::ledger::eth_bridge::storage::vote_tallies;
use crate::ledger::protocol::transactions::utils;
use crate::ledger::protocol::transactions::votes::{self, VoteInfo, Votes};
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, Storage, DB};
use crate::ledger::storage_api::queries::QueriesExt;
use crate::types::address::Address;
use crate::types::storage::BlockHeight;
#[allow(unused_imports)]
use crate::types::transaction::protocol::ProtocolTxType;
use crate::types::transaction::TxResult;
use crate::types::vote_extensions::validator_set_update;
use crate::types::voting_power::FractionalVotingPower;

impl utils::GetVoters for validator_set_update::VextDigest {
    #[inline]
    fn get_voters(&self) -> HashSet<(Address, BlockHeight)> {
        self.signatures.keys().cloned().collect()
    }
}

pub(crate) fn aggregate_votes<D, H>(
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
    let (exists_in_storage, _) = storage.has_key(&valset_upd_keys.seen())?;

    let mut seen_by = Votes::default();
    for (address, block_height) in ext.signatures.into_keys() {
        if let Some(present) = seen_by.insert(address, block_height) {
            // TODO(namada#770): this shouldn't be happening in any case and we
            // should be refactoring to get rid of `BlockHeight`
            tracing::warn!(?present, "Duplicate vote in digest");
        }
    }

    let (tally, changed, confirmed) = if !exists_in_storage {
        tracing::debug!(
            %valset_upd_keys.prefix,
            ?ext.voting_powers,
            "New validator set update vote aggregation started"
        );
        let tally = votes::calculate_new(seen_by, &voting_powers)?;
        let changed = valset_upd_keys.into_iter().collect();
        let confirmed = tally.seen;
        (tally, changed, confirmed)
    } else {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Validator set update votes already in storage",
        );
        let voters = VoteInfo::new(seen_by.clone(), &voting_powers);
        let (tally, changed) =
            votes::calculate_updated(storage, &valset_upd_keys, &voters)?;
        let confirmed = tally.seen && changed.contains(&valset_upd_keys.seen());
        (tally, changed, confirmed)
    };

    tracing::debug!(
        ?tally,
        ?ext.voting_powers,
        "Applying validator set update state changes"
    );
    votes::storage::write(
        storage,
        &valset_upd_keys,
        &ext.voting_powers,
        &tally,
    )?;

    if confirmed {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Acquired complete proof on validator set update"
        );
    }

    Ok(changed)
}
