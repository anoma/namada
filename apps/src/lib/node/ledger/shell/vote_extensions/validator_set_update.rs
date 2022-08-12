//! Extend Tendermint votes with validator set updates, to be relayed to
//! Namada's Ethereum bridge smart contracts.

use std::collections::HashMap;

use namada::ledger::pos::types::VotingPower;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::types::storage::Epoch;
use namada::types::vote_extensions::validator_set_update;
use namada::types::voting_power::FractionalVotingPower;

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
                // NOTE: make sure we do not change epochs between
                // extending votes and deciding on the validator
                // set update through consensus. otherwise, this
                // is going to fail.
                //
                // as an alternative to using epochs, we can use
                // block heights as a nonce, that way we can
                // always retrieve the proper epoch from the
                // block height
                self.storage.get_current_epoch().0.next(),
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
        vote_extensions: Vec<validator_set_update::SignedVext>,
    ) -> Option<validator_set_update::VextDigest> {
        let total_voting_power = {
            let prev_valset_epoch = self.storage.get_current_epoch().0 - 1;
            u64::from(
                self.storage.get_total_voting_power(Some(prev_valset_epoch)),
            )
        };
        let mut voting_power = FractionalVotingPower::default();

        let mut voting_powers = None;
        let mut signatures = HashMap::new();

        for (validator_voting_power, mut vote_extension) in
            self.filter_invalid_valset_upd_vexts(vote_extensions)
        {
            if voting_powers.is_none() {
                voting_powers = Some(std::mem::take(
                    &mut vote_extension.data.voting_powers,
                ));
            }

            let validator_addr = vote_extension.data.validator_addr;

            // update voting power
            let validator_voting_power = u64::from(validator_voting_power);
            voting_power += FractionalVotingPower::new(
                validator_voting_power,
                total_voting_power,
            )
            .expect(
                "The voting power we obtain from storage should always be \
                 valid",
            );

            // register the signature of `validator_addr`
            let addr = validator_addr.clone();
            let sig = vote_extension.sig;

            if let Some(sig) = signatures.insert(addr, sig) {
                tracing::warn!(
                    ?sig,
                    ?validator_addr,
                    "Overwrote old signature from validator while \
                     constructing validator_set_update::VextDigest"
                );
            }
        }

        if voting_power <= FractionalVotingPower::TWO_THIRDS {
            tracing::error!(
                "Tendermint has decided on a block including validator set \
                 update vote extensions reflecting <= 2/3 of the total stake"
            );
            return None;
        }

        let voting_powers = voting_powers.expect(
            "We have enough voting power, so at least one validator set \
             update vote extension must have been validated.",
        );

        Some(validator_set_update::VextDigest {
            signatures,
            voting_powers,
        })
    }
}
