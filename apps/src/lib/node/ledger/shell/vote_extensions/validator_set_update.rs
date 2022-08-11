//! Extend Tendermint votes with validator set updates, to be relayed to
//! Namada's Ethereum bridge smart contracts.

use namada::ledger::pos::types::VotingPower;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::types::storage::Epoch;
use namada::types::vote_extensions::validator_set_update;

use super::*;
use crate::node::ledger::shell::queries::QueriesExt;
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
    ///  * The voting powers in the vote extension correspond to the voting
    ///    powers of the validators of the new epoch
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
    // TODO:
    // - verify if the voting powers in the vote extension are the same
    // as the ones in storage. we can't do this yet, because we need to map
    // ethereum addresses to namada validator addresses
    //
    // - verify signatures with a secp key, instead of an ed25519 key
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
        // get the public key associated with this validator
        let validator = &ext.data.validator_addr;
        let prev_epoch = Some(Epoch(new_epoch.0 - 1));
        let (voting_power, pk) = self
            .storage
            .get_validator_from_address(validator, prev_epoch)
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    %validator,
                    "Could not get public key from Storage for some validator, while validating validator set update vote extension"
                );
                VoteExtensionError::PubKeyNotInStorage
            })?;
        // verify the signature of the vote extension
        ext.verify(&pk)
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    %validator,
                    "Failed to verify the signature of a validator set update vote extension issued by some validator"
                );
                VoteExtensionError::VerifySigFailed
            })
            .map(|_| (voting_power, ext))
    }

    /// Takes an iterator over validator set update vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid validator set update vote extensions, or the reason why these
    /// are invalid, in the form of a [`VoteExtensionError`].
    #[inline]
    #[allow(dead_code)]
    pub fn validate_valset_upd_vext_list(
        &self,
        vote_extensions: impl IntoIterator<Item = validator_set_update::SignedVext>
        + 'static,
    ) -> impl Iterator<
        Item = std::result::Result<
            (VotingPower, validator_set_update::SignedVext),
            VoteExtensionError,
        >,
    > + '_ {
        vote_extensions.into_iter().map(|vote_extension| {
            self.validate_valset_upd_vext_and_get_it_back(
                vote_extension,
                // NOTE: assumes we are in the new epoch,
                // after the prev valset signed off the
                // set of the new epoch
                self.storage.get_current_epoch().0,
            )
        })
    }

    /// Takes a list of signed validator set update vote extensions,
    /// and filters out invalid instances.
    #[inline]
    #[allow(dead_code)]
    pub fn filter_invalid_valset_upd_vexts(
        &self,
        vote_extensions: impl IntoIterator<Item = validator_set_update::SignedVext>
        + 'static,
    ) -> impl Iterator<Item = (VotingPower, validator_set_update::SignedVext)> + '_
    {
        self.validate_valset_upd_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }

    /// Compresses a set of signed validator set update vote extensions into a
    /// single [`validator_set_update::VextDigest`], whilst filtering
    /// invalid [`validator_set_update::SignedVext`] instances in the
    /// process.
    #[allow(dead_code)]
    pub fn compress_valset_updates(
        &self,
        _vote_extensions: Vec<validator_set_update::SignedVext>,
    ) -> Option<validator_set_update::VextDigest> {
        todo!()
    }
}
