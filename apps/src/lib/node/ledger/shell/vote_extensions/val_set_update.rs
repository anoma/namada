//! Extend Tendermint votes with validator set updates, to be relayed to
//! Namada's Ethereum bridge smart contracts.

use std::collections::HashMap;

use namada::ledger::pos::PosQueries;
use namada::state::{DBIter, StorageHasher, DB};
use namada::types::storage::Epoch;
use namada::types::token;
use namada::vote_ext::validator_set_update;

use super::*;
use crate::node::ledger::shell::Shell;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Validates a validator set update vote extension issued at the
    /// epoch provided as an argument.
    ///
    /// # Validation checks
    ///
    /// To validate a [`validator_set_update::SignedVext`], Namada nodes
    /// check if:
    ///
    ///  * The signing validator is a consensus validator during the epoch
    ///    `signing_epoch` inside the extension.
    ///  * A validator set update proof is not available yet for
    ///    `signing_epoch`.
    ///  * The validator correctly signed the extension, with its Ethereum hot
    ///    key.
    ///  * The validator signed over the epoch inside of the extension, whose
    ///    value should not be greater than `last_epoch`.
    ///  * The voting powers in the vote extension correspond to the voting
    ///    powers of the validators of `signing_epoch + 1`.
    ///  * The voting powers signed over were Ethereum ABI encoded, normalized
    ///    to `2^32`, and sorted in descending order.
    #[inline]
    #[allow(dead_code)]
    pub fn validate_valset_upd_vext(
        &self,
        ext: validator_set_update::SignedVext,
        signing_epoch: Epoch,
    ) -> bool {
        self.validate_valset_upd_vext_and_get_it_back(ext, signing_epoch)
            .is_ok()
    }

    /// This method behaves exactly like [`Self::validate_valset_upd_vext`],
    /// with the added bonus of returning the vote extension back, if it
    /// is valid.
    pub fn validate_valset_upd_vext_and_get_it_back(
        &self,
        ext: validator_set_update::SignedVext,
        last_epoch: Epoch,
    ) -> std::result::Result<
        (token::Amount, validator_set_update::SignedVext),
        VoteExtensionError,
    > {
        if self.wl_storage.storage.last_block.is_none() {
            tracing::debug!(
                "Dropping validator set update vote extension issued at \
                 genesis"
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        let signing_epoch = ext.data.signing_epoch;
        if signing_epoch > last_epoch {
            tracing::debug!(
                vext_epoch = ?signing_epoch,
                ?last_epoch,
                "Validator set update vote extension issued for an epoch \
                 greater than the last one.",
            );
            return Err(VoteExtensionError::UnexpectedEpoch);
        }
        if self
            .wl_storage
            .ethbridge_queries()
            .valset_upd_seen(signing_epoch.next())
        {
            let err = VoteExtensionError::ValsetUpdProofAvailable;
            tracing::debug!(
                proof_epoch = ?signing_epoch.next(),
                "{err}"
            );
            return Err(err);
        }
        // verify if the new epoch validators' voting powers in storage match
        // the voting powers in the vote extension
        for (eth_addr_book, namada_addr, namada_power) in self
            .wl_storage
            .ethbridge_queries()
            .get_consensus_eth_addresses(Some(signing_epoch.next()))
            .iter()
        {
            let &ext_power = match ext.data.voting_powers.get(&eth_addr_book) {
                Some(voting_power) => voting_power,
                _ => {
                    tracing::debug!(
                        ?eth_addr_book,
                        "Could not find expected Ethereum addresses in valset \
                         upd vote extension",
                    );
                    return Err(
                        VoteExtensionError::ValidatorMissingFromExtension,
                    );
                }
            };
            if namada_power != ext_power {
                tracing::debug!(
                    validator = %namada_addr,
                    expected = ?namada_power,
                    got = ?ext_power,
                    "Found unexpected voting power value in valset upd vote extension",
                );
                return Err(VoteExtensionError::DivergesFromStorage);
            }
        }
        // get the public key associated with this validator
        let validator = &ext.data.validator_addr;
        let (voting_power, _) = self
            .wl_storage
            .pos_queries()
            .get_validator_from_address(validator, Some(signing_epoch))
            .map_err(|err| {
                tracing::debug!(
                    ?err,
                    %validator,
                    "Could not get public key from Storage for some validator, \
                     while validating valset upd vote extension"
                );
                VoteExtensionError::PubKeyNotInStorage
            })?;
        let pk = self
            .wl_storage
            .pos_queries()
            .read_validator_eth_hot_key(validator, Some(signing_epoch))
            .expect("We should have this hot key in storage");
        // verify the signature of the vote extension
        ext.verify(&pk)
            .map_err(|err| {
                tracing::debug!(
                    ?err,
                    ?ext.sig,
                    ?pk,
                    %validator,
                    "Failed to verify the signature of a valset upd vote \
                     extension issued by some validator"
                );
                VoteExtensionError::VerifySigFailed
            })
            .map(|_| (voting_power, ext))
    }

    /// Takes an iterator over validator set update vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid validator set update vote extensions, or the reason why these
    /// are invalid, in the form of a `VoteExtensionError`.
    #[inline]
    pub fn validate_valset_upd_vext_list(
        &self,
        vote_extensions: impl IntoIterator<Item = validator_set_update::SignedVext>
        + 'static,
    ) -> impl Iterator<
        Item = std::result::Result<
            (token::Amount, validator_set_update::SignedVext),
            VoteExtensionError,
        >,
    > + '_ {
        vote_extensions.into_iter().map(|vote_extension| {
            self.validate_valset_upd_vext_and_get_it_back(
                vote_extension,
                self.wl_storage.storage.get_current_epoch().0,
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
    ) -> impl Iterator<Item = (token::Amount, validator_set_update::SignedVext)> + '_
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
        #[allow(clippy::question_mark)]
        if self.wl_storage.storage.last_block.is_none() {
            return None;
        }

        let mut voting_powers = None;
        let mut signatures = HashMap::new();

        for (
            _validator_voting_power,
            validator_set_update::SignedVext(mut vote_extension),
        ) in self.filter_invalid_valset_upd_vexts(vote_extensions)
        {
            if voting_powers.is_none() {
                voting_powers = Some(std::mem::take(
                    &mut vote_extension.data.voting_powers,
                ));
            }

            let validator_addr = vote_extension.data.validator_addr;
            let signing_epoch = vote_extension.data.signing_epoch;

            // register the signature of `validator_addr`
            let addr = validator_addr.clone();
            let sig = vote_extension.sig.clone();

            tracing::debug!(
                ?sig,
                ?signing_epoch,
                %validator_addr,
                "Inserting signature into validator_set_update::VextDigest"
            );
            if let Some(existing_sig) = signatures.insert(addr, sig) {
                tracing::warn!(
                    sig = ?vote_extension.sig,
                    ?existing_sig,
                    ?validator_addr,
                    ?signing_epoch,
                    "Overwrote old signature from validator while \
                     constructing validator_set_update::VextDigest - maybe \
                     private key of validator is being used by multiple nodes?"
                );
            }
        }

        let voting_powers = voting_powers.unwrap_or_default();

        Some(validator_set_update::VextDigest {
            signatures,
            voting_powers,
        })
    }
}

#[cfg(test)]
mod test_vote_extensions {
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake,
    };
    use namada::proof_of_stake::types::WeightedValidator;
    use namada::proof_of_stake::Epoch;
    use namada::state::collections::lazy_map::{NestedSubKey, SubKey};
    use namada::tendermint::abci::types::VoteInfo;
    use namada::types::key::RefTo;
    use namada::vote_ext::validator_set_update;
    use namada_sdk::eth_bridge::EthBridgeQueries;

    use crate::node::ledger::shell::test_utils::{self, get_pkh_from_address};
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet;

    /// Test if a [`validator_set_update::Vext`] that incorrectly labels what
    /// epoch it was included on in a vote extension is rejected
    #[test]
    fn test_reject_incorrect_epoch() {
        let (shell, _recv, _, _) = test_utils::setup();
        let validator_addr =
            shell.mode.get_validator_address().unwrap().clone();

        let eth_bridge_key =
            shell.mode.get_eth_bridge_keypair().expect("Test failed");

        let signing_epoch = shell.wl_storage.storage.get_current_epoch().0;
        let next_epoch = signing_epoch.next();

        let voting_powers = {
            shell
                .wl_storage
                .ethbridge_queries()
                .get_consensus_eth_addresses(Some(next_epoch))
                .iter()
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect()
        };
        #[allow(clippy::redundant_clone)]
        let validator_set_update = Some(
            validator_set_update::Vext {
                voting_powers,
                validator_addr: validator_addr.clone(),
                // invalid epoch
                signing_epoch: next_epoch,
            }
            .sign(eth_bridge_key),
        );
        assert!(!shell.validate_valset_upd_vext(
            validator_set_update.unwrap(),
            signing_epoch,
        ))
    }

    /// Test that validator set update vote extensions signed by
    /// a non-validator are rejected
    #[test]
    fn test_valset_upd_must_be_signed_by_validator() {
        let (shell, _recv, _, _) = test_utils::setup();
        let (eth_bridge_key, _protocol_key, validator_addr) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (test_utils::gen_secp256k1_keypair(), bertha_key, bertha_addr)
        };
        let signing_epoch = shell.wl_storage.storage.get_current_epoch().0;
        let voting_powers = {
            let next_epoch = signing_epoch.next();
            shell
                .wl_storage
                .ethbridge_queries()
                .get_consensus_eth_addresses(Some(next_epoch))
                .iter()
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect()
        };
        #[allow(clippy::redundant_clone)]
        let validator_set_update = Some(
            validator_set_update::Vext {
                voting_powers,
                signing_epoch,
                validator_addr: validator_addr.clone(),
            }
            .sign(&eth_bridge_key),
        );
        assert!(!shell.validate_valset_upd_vext(
            validator_set_update.unwrap(),
            signing_epoch,
        ));
    }

    /// Test the validation of a validator set update emitted for
    /// some epoch `E`. The test should pass even if the epoch
    /// changed to some epoch `E': E' > E`, resulting in a
    /// change to the validator set.
    #[test]
    fn test_validate_valset_upd_vexts() {
        let (mut shell, _recv, _, _oracle_control_recv) = test_utils::setup();
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let eth_bridge_key = shell
            .mode
            .get_eth_bridge_keypair()
            .expect("Test failed")
            .clone();
        let validator_addr = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let signing_epoch = shell.wl_storage.storage.get_current_epoch().0;
        let voting_powers = {
            let next_epoch = signing_epoch.next();
            shell
                .wl_storage
                .ethbridge_queries()
                .get_consensus_eth_addresses(Some(next_epoch))
                .iter()
                .map(|(eth_addr_book, _, voting_power)| {
                    (eth_addr_book, voting_power)
                })
                .collect()
        };
        let vote_ext = validator_set_update::Vext {
            voting_powers,
            signing_epoch,
            validator_addr,
        }
        .sign(&eth_bridge_key);

        // validators from the current epoch sign over validator
        // set of the next epoch
        assert_eq!(shell.wl_storage.storage.get_current_epoch().0.0, 0);

        // remove all validators of the next epoch
        let validators_handle = consensus_validator_set_handle().at(&1.into());
        let consensus_in_mem = validators_handle
            .iter(&shell.wl_storage)
            .expect("Test failed")
            .map(|val| {
                let (
                    NestedSubKey::Data {
                        key: stake,
                        nested_sub_key: SubKey::Data(position),
                    },
                    ..,
                ) = val.expect("Test failed");
                (stake, position)
            })
            .collect::<Vec<_>>();
        for (val_stake, val_position) in consensus_in_mem.into_iter() {
            validators_handle
                .at(&val_stake)
                .remove(&mut shell.wl_storage, &val_position)
                .expect("Test failed");
        }
        // we advance forward to the next epoch
        let params = shell.wl_storage.pos_queries().get_pos_params();
        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );
        let votes = vec![VoteInfo {
            validator: crate::facade::tendermint::abci::types::Validator {
                address: pkh1,
                power: (u128::try_from(val1.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
            },
             sig_info: crate::facade::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        let req = FinalizeBlock {
            proposer_address: pkh1.to_vec(),
            votes,
            ..Default::default()
        };
        assert_eq!(shell.start_new_epoch(Some(req)).0, 1);
        assert!(
            shell
                .wl_storage
                .pos_queries()
                .get_validator_from_protocol_pk(&protocol_key.ref_to(), None)
                .is_err()
        );
        let prev_epoch = shell.wl_storage.storage.get_current_epoch().0 - 1;
        assert!(
            shell
                .shell
                .wl_storage
                .pos_queries()
                .get_validator_from_protocol_pk(
                    &protocol_key.ref_to(),
                    Some(prev_epoch)
                )
                .is_ok()
        );

        assert!(shell.validate_valset_upd_vext(vote_ext, signing_epoch));
    }

    /// Test if a [`validator_set_update::Vext`] with an incorrect signature
    /// is rejected
    #[test]
    fn test_reject_bad_signatures() {
        let (shell, _recv, _, _) = test_utils::setup();
        let validator_addr =
            shell.mode.get_validator_address().unwrap().clone();

        let eth_bridge_key =
            shell.mode.get_eth_bridge_keypair().expect("Test failed");

        let signing_epoch = shell.wl_storage.storage.get_current_epoch().0;
        #[allow(clippy::redundant_clone)]
        let validator_set_update = {
            let voting_powers = {
                let next_epoch = signing_epoch.next();
                shell
                    .wl_storage
                    .ethbridge_queries()
                    .get_consensus_eth_addresses(Some(next_epoch))
                    .iter()
                    .map(|(eth_addr_book, _, voting_power)| {
                        (eth_addr_book, voting_power)
                    })
                    .collect()
            };
            let mut ext = validator_set_update::Vext {
                voting_powers,
                signing_epoch,
                validator_addr: validator_addr.clone(),
            }
            .sign(eth_bridge_key);
            ext.0.sig = test_utils::invalidate_signature(ext.0.sig);
            Some(ext)
        };
        assert!(!shell.validate_valset_upd_vext(
            validator_set_update.unwrap(),
            signing_epoch,
        ));
    }

    /// Test if a [`validator_set_update::Vext`] is signed with a secp key
    /// that belongs to a consensus validator of some previous epoch
    #[test]
    #[ignore]
    fn test_secp_key_belongs_to_consensus_validator() {
        // TODO: we need to prove ownership of validator keys
        // https://github.com/anoma/namada/issues/106
    }
}
