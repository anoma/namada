//! Code for handling
//! [`namada::types::transaction::protocol::ProtocolTxType::ValidatorSetUpdate`]
//! transactions.

use std::collections::{HashMap, HashSet};

use eyre::Result;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::types::address::Address;
use namada::types::storage::BlockHeight;
use namada::types::transaction::TxResult;
use namada::types::vote_extensions::validator_set_update;
use namada::types::voting_power::FractionalVotingPower;

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
    let changed_keys = apply_updates(storage, ext, voting_powers)?;

    Ok(TxResult {
        changed_keys,
        ..Default::default()
    })
}

fn apply_updates<D, H>(
    _storage: &mut Storage<D, H>,
    _ext: validator_set_update::VextDigest,
    _voting_powers: HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<ChangedKeys>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    todo!()
}
