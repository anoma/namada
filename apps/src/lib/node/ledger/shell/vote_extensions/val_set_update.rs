//! Extend Tendermint votes with validator set updates, to be relayed to
//! Namada's Ethereum bridge smart contracts.

use std::collections::HashMap;

use namada::ledger::pos::types::VotingPower;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::types::storage::BlockHeight;
use namada::types::vote_extensions::validator_set_update;
#[cfg(feature = "abcipp")]
use namada::types::voting_power::FractionalVotingPower;

use super::*;
use crate::node::ledger::shell::queries::QueriesExt;
use crate::node::ledger::shell::Shell;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Validates a validator set update vote extension issued for the
    /// succeeding epoch of the block height provided as an argument.
    ///
    /// Checks that:
    ///  * The signing validator was active at the preceding epoch.
    ///  * The validator correctly signed the extension, with its Ethereum hot
    ///    key.
    ///  * The validator signed over the block height inside of the extension.
    ///  * The voting powers in the vote extension correspond to the voting
    ///    powers of the validators of the new epoch.
    ///  * The voting powers are normalized to `2^32`, and sorted in descending
    ///    order.
    #[inline]
    #[allow(dead_code)]
    pub fn validate_valset_upd_vext(
        &self,
        ext: validator_set_update::SignedVext,
        last_height: BlockHeight,
    ) -> bool {
        self.validate_valset_upd_vext_and_get_it_back(ext, last_height)
            .is_ok()
    }

    /// This method behaves exactly like [`Self::validate_valset_upd_vext`],
    /// with the added bonus of returning the vote extension back, if it
    /// is valid.
    // TODO:
    // - verify if the voting powers in the vote extension are the same
    // as the ones in storage. we can't do this yet, because we need to map
    // ethereum addresses to namada validator addresses
    //
    // - verify signatures with a secp key, instead of an ed25519 key
    pub fn validate_valset_upd_vext_and_get_it_back(
        &self,
        ext: validator_set_update::SignedVext,
        last_height: BlockHeight,
    ) -> std::result::Result<
        (VotingPower, validator_set_update::SignedVext),
        VoteExtensionError,
    > {
        #[cfg(feature = "abcipp")]
        if ext.data.block_height != last_height {
            tracing::error!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Validator set update vote extension issued for a block \
                 height different from the expected last height.",
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        #[cfg(not(feature = "abcipp"))]
        if ext.data.block_height > last_height {
            tracing::error!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Validator set update vote extension issued for a block \
                 height higher than the chain's last height.",
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        if last_height.0 == 0 {
            tracing::error!("Dropping vote extension issued at genesis");
            return Err(VoteExtensionError::IssuedAtGenesis);
        }
        // get the public key associated with this validator
        let validator = &ext.data.validator_addr;
        // NOTE(not(feature = "abciplus")): for ABCI++, we should pass
        // `last_height` here, instead of `ext.data.block_height`
        let ext_height_epoch = match self
            .storage
            .get_epoch(ext.data.block_height)
        {
            Some(epoch) => epoch,
            _ => {
                tracing::error!(
                    block_height = ?ext.data.block_height,
                    "The epoch of the validator set update vote extension's \
                     block height should always be known",
                );
                return Err(VoteExtensionError::UnexpectedEpoch);
            }
        };
        let (voting_power, pk) = self
            .storage
            .get_validator_from_address(validator, Some(ext_height_epoch))
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    %validator,
                    "Could not get public key from Storage for some validator, \
                     while validating validator set update vote extension"
                );
                VoteExtensionError::PubKeyNotInStorage
            })?;
        // verify the signature of the vote extension
        ext.verify(&pk)
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    %validator,
                    "Failed to verify the signature of a validator set update vote \
                     extension issued by some validator"
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
                self.storage.last_height,
            )
        })
    }

    /// Takes a list of signed validator set update vote extensions,
    /// and filters out invalid instances.
    #[inline]
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
    pub fn compress_valset_updates(
        &self,
        vote_extensions: Vec<validator_set_update::SignedVext>,
    ) -> Option<validator_set_update::VextDigest> {
        #[cfg(not(feature = "abcipp"))]
        if self.storage.last_height == BlockHeight(0) {
            return None;
        }

        #[cfg(feature = "abcipp")]
        let vexts_epoch =
            self.storage.get_epoch(self.storage.last_height).expect(
                "The epoch of the last block height should always be known",
            );

        #[cfg(feature = "abcipp")]
        let total_voting_power =
            u64::from(self.storage.get_total_voting_power(Some(vexts_epoch)));
        #[cfg(feature = "abcipp")]
        let mut voting_power = FractionalVotingPower::default();

        let mut voting_powers = None;
        let mut signatures = HashMap::new();

        for (_validator_voting_power, mut vote_extension) in
            self.filter_invalid_valset_upd_vexts(vote_extensions)
        {
            if voting_powers.is_none() {
                voting_powers = Some(std::mem::take(
                    &mut vote_extension.data.voting_powers,
                ));
            }

            let validator_addr = vote_extension.data.validator_addr;
            #[cfg(not(feature = "abcipp"))]
            let block_height = vote_extension.data.block_height;

            // update voting power
            #[cfg(feature = "abcipp")]
            {
                let validator_voting_power = u64::from(_validator_voting_power);
                voting_power += FractionalVotingPower::new(
                    validator_voting_power,
                    total_voting_power,
                )
                .expect(
                    "The voting power we obtain from storage should always be \
                     valid",
                );
            }

            // register the signature of `validator_addr`
            let addr = validator_addr.clone();
            let sig = vote_extension.sig;

            #[cfg(feature = "abcipp")]
            if let Some(sig) = signatures.insert(addr, sig) {
                tracing::warn!(
                    ?sig,
                    ?validator_addr,
                    "Overwrote old signature from validator while \
                     constructing validator_set_update::VextDigest"
                );
            }

            #[cfg(not(feature = "abcipp"))]
            if let Some(sig) = signatures.insert((addr, block_height), sig) {
                tracing::warn!(
                    ?sig,
                    ?validator_addr,
                    "Overwrote old signature from validator while \
                     constructing validator_set_update::VextDigest"
                );
            }
        }

        #[cfg(feature = "abcipp")]
        if voting_power <= FractionalVotingPower::TWO_THIRDS {
            tracing::error!(
                "Tendermint has decided on a block including validator set \
                 update vote extensions reflecting <= 2/3 of the total stake"
            );
            return None;
        }

        #[cfg(feature = "abcipp")]
        let voting_powers = voting_powers.expect(
            "We have enough voting power, so at least one validator set \
             update vote extension must have been validated.",
        );

        #[cfg(not(feature = "abcipp"))]
        let voting_powers = voting_powers.unwrap_or_default();

        Some(validator_set_update::VextDigest {
            signatures,
            voting_powers,
        })
    }
}

#[cfg(test)]
mod test_vote_extensions {
    use std::default::Default;

    #[cfg(feature = "abcipp")]
    #[cfg(feature = "abcipp")]
    use borsh::BorshSerialize;
    use namada::ledger::pos;
    use namada::ledger::pos::namada_proof_of_stake::PosBase;
    use namada::types::key::RefTo;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::ethereum_events;
    use namada::types::vote_extensions::validator_set_update;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::VoteExtension;

    #[cfg(feature = "abcipp")]
    use crate::facade::tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;
    #[cfg(feature = "abcipp")]
    use crate::facade::tower_abci::request;
    use crate::node::ledger::shell::queries::QueriesExt;
    use crate::node::ledger::shell::test_utils;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet;

    /// Test if a [`validator_set_update::Vext`] that incorrectly labels what
    /// block height it was included on in a vote extension is rejected if
    /// vote extensions are enabled. Else, it accepts.
    // TODO:
    // - sign with secp key
    // - add validator voting powers from storage
    #[test]
    fn test_reject_incorrect_block_height() {
        let (shell, _recv, _) = test_utils::setup();
        let validator_addr =
            shell.mode.get_validator_address().unwrap().clone();

        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");

        #[allow(clippy::redundant_clone)]
        let validator_set_update = Some(
            validator_set_update::Vext {
                // TODO: get voting powers from storage, associated with eth
                // addrs
                voting_powers: std::collections::HashMap::new(),
                validator_addr: validator_addr.clone(),
                // invalid height
                block_height: shell.storage.get_current_decision_height() + 1,
            }
            // TODO: sign with secp key
            .sign(protocol_key),
        );
        #[cfg(feature = "abcipp")]
        {
            let ethereum_events = ethereum_events::Vext::empty(
                shell.storage.get_current_decision_height(),
                validator_addr,
            )
            .sign(protocol_key);
            let req = request::VerifyVoteExtension {
                vote_extension: VoteExtension {
                    ethereum_events,
                    validator_set_update,
                }
                .try_to_vec()
                .expect("Test failed"),
                ..Default::default()
            };

            assert_eq!(
                shell.verify_vote_extension(req).status,
                i32::from(VerifyStatus::Reject)
            );
        }
        #[cfg(not(feature = "abcipp"))]
        {
            assert!(shell.validate_valset_upd_vext(
                validator_set_update.unwrap(),
                shell.storage.get_current_decision_height()
            ))
        }
    }

    /// Test that validator set update vote extensions signed by
    /// a non-validator are rejected
    #[test]
    fn test_valset_upd_must_be_signed_by_validator() {
        let (shell, _recv, _) = test_utils::setup();
        let (protocol_key, validator_addr) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_key, bertha_addr)
        };

        #[allow(clippy::redundant_clone)]
        let validator_set_update = Some(
            validator_set_update::Vext {
                // TODO: get voting powers from storage, associated with eth
                // addrs
                voting_powers: std::collections::HashMap::new(),
                block_height: shell.storage.get_current_decision_height(),
                validator_addr: validator_addr.clone(),
            }
            .sign(&protocol_key),
        );
        #[cfg(feature = "abcipp")]
        {
            let ethereum_events = ethereum_events::Vext::empty(
                shell.storage.get_current_decision_height(),
                validator_addr,
            )
            .sign(&protocol_key);
            let req = request::VerifyVoteExtension {
                vote_extension: VoteExtension {
                    ethereum_events,
                    validator_set_update,
                }
                .try_to_vec()
                .expect("Test failed"),
                ..Default::default()
            };
            assert_eq!(
                shell.verify_vote_extension(req).status,
                i32::from(VerifyStatus::Reject)
            );
        }
        #[cfg(not(feature = "abcipp"))]
        assert!(!shell.validate_valset_upd_vext(
            validator_set_update.unwrap(),
            shell.storage.get_current_decision_height()
        ));
    }

    /// Test the validation of a validator set update emitted for
    /// some epoch `E`. The test should pass even if the epoch
    /// changed to some epoch `E': E' > E`, resulting in a
    /// change to the validator set.
    #[test]
    fn test_validate_valset_upd_vexts() {
        let (mut shell, _recv, _) = test_utils::setup();
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let validator_addr = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let signed_height = shell.storage.get_current_decision_height();
        let vote_ext = validator_set_update::Vext {
            // TODO: get voting powers from storage, associated with eth
            // addrs
            voting_powers: std::collections::HashMap::new(),
            block_height: signed_height,
            validator_addr,
        }
        .sign(&protocol_key);

        // validators from the current epoch sign over validator
        // set of the next epoch
        assert_eq!(shell.storage.get_current_epoch().0.0, 0);

        // remove all validators of the next epoch
        let mut current_validators = shell.storage.read_validator_set();
        current_validators.data.insert(
            1,
            Some(pos::types::ValidatorSet {
                active: Default::default(),
                inactive: Default::default(),
            }),
        );
        shell.storage.write_validator_set(&current_validators);
        // we advance forward to the next epoch
        let mut req = FinalizeBlock::default();
        req.header.time = namada::types::time::DateTimeUtc::now();
        shell.storage.last_height =
            shell.storage.get_current_decision_height() + 11;
        shell.finalize_block(req).expect("Test failed");
        shell.commit();
        assert_eq!(shell.storage.get_current_epoch().0.0, 1);
        assert!(
            shell
                .storage
                .get_validator_from_protocol_pk(&protocol_key.ref_to(), None)
                .is_err()
        );
        let prev_epoch = shell.storage.get_current_epoch().0 - 1;
        assert!(
            shell
                .shell
                .storage
                .get_validator_from_protocol_pk(
                    &protocol_key.ref_to(),
                    Some(prev_epoch)
                )
                .is_ok()
        );

        assert!(shell.validate_valset_upd_vext(vote_ext, signed_height));
    }

    /// Test if a [`validator_set_update::Vext`] with an incorrect signature
    /// is rejected
    // TODO:
    // - sign with secp key
    // - add validator voting powers from storage
    #[test]
    fn test_reject_bad_signatures() {
        let (shell, _recv, _) = test_utils::setup();
        let validator_addr =
            shell.mode.get_validator_address().unwrap().clone();

        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");

        #[allow(clippy::redundant_clone)]
        let validator_set_update = {
            let mut ext = validator_set_update::Vext {
                // TODO: get voting powers from storage, associated with eth
                // addrs
                voting_powers: std::collections::HashMap::new(),
                block_height: shell.storage.get_current_decision_height(),
                validator_addr: validator_addr.clone(),
            }
            // TODO: sign with secp key
            .sign(protocol_key);
            ext.sig = test_utils::invalidate_signature(ext.sig);
            Some(ext)
        };
        #[cfg(feature = "abcipp")]
        {
            let ethereum_events = ethereum_events::Vext::empty(
                shell.storage.get_current_decision_height(),
                validator_addr,
            )
            .sign(protocol_key);
            let req = request::VerifyVoteExtension {
                vote_extension: VoteExtension {
                    ethereum_events,
                    validator_set_update: validator_set_update.clone(),
                }
                .try_to_vec()
                .expect("Test failed"),
                ..Default::default()
            };
            assert_eq!(
                shell.verify_vote_extension(req).status,
                i32::from(VerifyStatus::Reject)
            );
        }
        assert!(!shell.validate_valset_upd_vext(
            validator_set_update.unwrap(),
            shell.storage.get_current_decision_height()
        ));
    }

    /// Test if a [`validator_set_update::Vext`] is signed with a secp key
    /// that belongs to an active validator of some previous epoch
    #[test]
    fn test_secp_key_belongs_to_active_validator() {
        // TODO
    }
}
