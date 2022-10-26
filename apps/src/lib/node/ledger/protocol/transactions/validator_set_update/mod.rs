//! Code for handling
//! [`namada::types::transaction::protocol::ProtocolTxType::ValidatorSetUpdate`]
//! transactions.

use std::collections::{HashMap, HashSet};

use eyre::Result;
use namada::ledger::eth_bridge::storage::vote_tallies;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::types::address::Address;
use namada::types::storage::BlockHeight;
use namada::types::transaction::TxResult;
use namada::types::vote_extensions::validator_set_update;
use namada::types::voting_power::FractionalVotingPower;

use super::ChangedKeys;
use crate::node::ledger::protocol::transactions::utils;
use crate::node::ledger::shell::queries::QueriesExt;

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
    _voting_powers: HashMap<(Address, BlockHeight), FractionalVotingPower>,
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
    let _ = valset_upd_keys;

    tracing::warn!("Called apply_update() with no side effects");
    Ok(ChangedKeys::new())
}
