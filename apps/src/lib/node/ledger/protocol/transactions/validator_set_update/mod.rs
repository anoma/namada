//! Code for handling
//! [`namada::types::transaction::protocol::ProtocolTxType::ValidatorSetUpdate`]
//! transactions.

use eyre::Result;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::types::transaction::TxResult;
use namada::types::vote_extensions::validator_set_update;

use super::ChangedKeys;
use crate::node::ledger::protocol::transactions::utils;

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
    tracing::info!(
        num_votes = ext.signatures.len(),
        "Aggregating new votes for validator set update"
    );

    let voting_powers = utils::get_voting_powers(storage, &ext)?;
    let changed_keys = apply_updates(storage, updates, voting_powers)?;
}
