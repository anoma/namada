//! Extend Tendermint votes with validator set updates, to be relayed to
//! Namada's Ethereum bridge smart contracts.

use namada::ledger::pos::types::{Epoch, VotingPower};
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::types::vote_extensions::validator_set_update;

use super::*;
use crate::node::ledger::shell::Shell;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Validates a validator set update vote extension issued for the new
    /// epoch provided as an argument
    ///
    /// Checks that:
    ///  * The signing validator was active at the preceding epoch
    ///  * The validator correctly signed the extension
    ///  * The validator signed over the new epoch inside of the extension
    ///  * The voting powers are normalized to 2^32, and sorted in descending
    ///    order
    #[inline]
    #[allow(dead_code)]
    pub fn validate_valset_upd_vext(
        &self,
        ext: validator_set_update::SignedVext,
        new_epoch: Epoch,
    ) -> bool {
        self.validate_valset_upd_vext_and_get_it_back(ext, new_epoch)
            .is_ok()
    }

    /// This method behaves exactly like [`Self::validate_valset_upd_vext`],
    /// with the added bonus of returning the vote extension back, if it
    /// is valid.
    #[allow(dead_code)]
    pub fn validate_valset_upd_vext_and_get_it_back(
        &self,
        ext: validator_set_update::SignedVext,
        new_epoch: Epoch,
    ) -> std::result::Result<
        (VotingPower, validator_set_update::SignedVext),
        VoteExtensionError,
    > {
        if ext.data.epoch != new_epoch {
            let ext_epoch = ext.data.epoch;
            tracing::error!(
                "Validator set update vote extension issued for an epoch \
                 {ext_epoch} different from the expected epoch {new_epoch}"
            );
            return Err(VoteExtensionError::UnexpectedSequenceNumber);
        }
        todo!()
    }
}
