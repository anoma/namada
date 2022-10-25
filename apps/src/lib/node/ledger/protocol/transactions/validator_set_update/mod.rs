//! Code for handling
//! [`namada::types::transaction::protocol::ProtocolTxType::ValidatorSetUpdate`]
//! transactions.

use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};

pub(crate) fn aggregate_votes<D, H>(
    _storage: &mut Storage<D, H>,
    _ext: validator_set_update::VextDigest,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    todo!()
}
