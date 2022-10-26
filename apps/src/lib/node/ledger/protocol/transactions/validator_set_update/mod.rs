//! Code for handling
//! [`namada::types::transaction::protocol::ProtocolTxType::ValidatorSetUpdate`]
//! transactions.

use eyre::Result;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::types::transaction::TxResult;
use namada::types::vote_extensions::validator_set_update;

pub(crate) fn aggregate_votes<D, H>(
    _storage: &mut Storage<D, H>,
    _ext: validator_set_update::VextDigest,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    tracing::warn!("Called aggregate_votes() with no side effects");
    Ok(TxResult::default())
}
