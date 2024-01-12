//! Extend Tendermint votes with signatures of the Ethereum
//! bridge pool root and nonce seen by a quorum of validators.
use itertools::Itertools;
use namada::ledger::pos::PosQueries;
use namada::state::{DBIter, StorageHasher, DB};
use namada::tx::Signed;
use namada::types::keccak::keccak_hash;
use namada::types::storage::BlockHeight;
use namada::types::token;

use super::*;
use crate::node::ledger::shell::Shell;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Validates a vote extension issued at the provided
    /// block height signing over the latest Ethereum bridge
    /// pool root and nonce.
    ///
    /// Checks that at epoch of the provided height:
    ///  * The inner Namada address corresponds to a consensus validator.
    ///  * Check that the root and nonce are correct.
    ///  * The validator correctly signed the extension.
    ///  * The validator signed over the correct height inside of the extension.
    ///  * Check that the inner signature is valid.
    #[inline]
    #[allow(dead_code)]
    pub fn validate_bp_roots_vext(
        &self,
        ext: Signed<bridge_pool_roots::Vext>,
        height: BlockHeight,
    ) -> bool {
        self.validate_bp_roots_vext_and_get_it_back(ext, height)
            .is_ok()
    }

    /// This method behaves exactly like [`Self::validate_bp_roots_vext`],
    /// with the added bonus of returning the vote extension back, if it
    /// is valid.
    pub fn validate_bp_roots_vext_and_get_it_back(
        &self,
        ext: Signed<bridge_pool_roots::Vext>,
        last_height: BlockHeight,
    ) -> std::result::Result<
        (token::Amount, Signed<bridge_pool_roots::Vext>),
        VoteExtensionError,
    > {
        // NOTE: for ABCI++, we should pass
        // `last_height` here, instead of `ext.data.block_height`
        let ext_height_epoch = match self
            .wl_storage
            .pos_queries()
            .get_epoch(ext.data.block_height)
        {
            Some(epoch) => epoch,
            _ => {
                tracing::debug!(
                    block_height = ?ext.data.block_height,
                    "The epoch of the Bridge pool root's vote extension's \
                     block height should always be known",
                );
                return Err(VoteExtensionError::UnexpectedEpoch);
            }
        };
        if !self
            .wl_storage
            .ethbridge_queries()
            .is_bridge_active_at(ext_height_epoch)
        {
            tracing::debug!(
                vext_epoch = ?ext_height_epoch,
                "The Ethereum bridge was not enabled when the pool
                 root's vote extension was cast",
            );
            return Err(VoteExtensionError::EthereumBridgeInactive);
        }

        if ext.data.block_height > last_height {
            tracing::debug!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Bridge pool root's vote extension issued for a block height \
                 higher than the chain's last height."
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        if ext.data.block_height.0 == 0 {
            tracing::debug!("Dropping vote extension issued at genesis");
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }

        // get the public key associated with this validator
        let validator = &ext.data.validator_addr;
        let (voting_power, pk) = self
            .wl_storage
            .pos_queries()
            .get_validator_from_address(validator, Some(ext_height_epoch))
            .map_err(|err| {
                tracing::debug!(
                    ?err,
                    %validator,
                    "Could not get public key from Storage for some validator, \
                     while validating Bridge pool root's vote extension"
                );
                VoteExtensionError::PubKeyNotInStorage
            })?;
        // verify the signature of the vote extension
        ext.verify(&pk).map_err(|err| {
            tracing::debug!(
                ?err,
                ?ext.sig,
                ?pk,
                %validator,
                "Failed to verify the signature of an Bridge pool root's vote \
                 extension issued by some validator"
            );
            VoteExtensionError::VerifySigFailed
        })?;

        let bp_root = self
            .wl_storage
            .ethbridge_queries()
            .get_bridge_pool_root_at_height(ext.data.block_height)
            .expect("We asserted that the queried height is correct")
            .0;
        let nonce = self
            .wl_storage
            .ethbridge_queries()
            .get_bridge_pool_nonce_at_height(ext.data.block_height)
            .to_bytes();
        let signed = Signed::<_, SignableEthMessage>::new_from(
            keccak_hash([bp_root, nonce].concat()),
            ext.data.sig.clone(),
        );
        let pk = self
            .wl_storage
            .pos_queries()
            .read_validator_eth_hot_key(validator, Some(ext_height_epoch))
            .expect("A validator should have an Ethereum hot key in storage.");
        signed
            .verify(&pk)
            .map_err(|err| {
                tracing::debug!(
                    ?err,
                    ?signed.sig,
                    ?pk,
                    %validator,
                    "Failed to verify the signature of an Bridge pool root \
                    issued by some validator."
                );
                VoteExtensionError::InvalidBPRootSig
            })
            .map(|_| (voting_power, ext))
    }

    /// Takes an iterator over Bridge pool root vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid Bridge pool root vote extensions, or the reason why these
    /// are invalid, in the form of a `VoteExtensionError`.
    #[inline]
    pub fn validate_bp_roots_vext_list<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<bridge_pool_roots::Vext>>
        + 'iter,
    ) -> impl Iterator<
        Item = std::result::Result<
            (token::Amount, Signed<bridge_pool_roots::Vext>),
            VoteExtensionError,
        >,
    > + 'iter {
        vote_extensions.into_iter().map(|vote_extension| {
            self.validate_bp_roots_vext_and_get_it_back(
                vote_extension,
                self.wl_storage.storage.get_last_block_height(),
            )
        })
    }

    /// Takes a list of signed Bridge pool root vote extensions,
    /// and filters out invalid instances. This also de-duplicates
    /// the iterator to be unique per validator address.
    #[inline]
    pub fn filter_invalid_bp_roots_vexts<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<bridge_pool_roots::Vext>>
        + 'iter,
    ) -> impl Iterator<Item = (token::Amount, Signed<bridge_pool_roots::Vext>)> + 'iter
    {
        self.validate_bp_roots_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
            .dedup_by(|(_, ext_1), (_, ext_2)| {
                ext_1.data.validator_addr == ext_2.data.validator_addr
            })
    }
}

#[cfg(test)]
mod test_bp_vote_extensions {
    use namada::ethereum_bridge::storage::bridge_pool::get_key_from_hash;
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake,
    };
    use namada::proof_of_stake::types::{
        Position as ValidatorPosition, WeightedValidator,
    };
    use namada::proof_of_stake::{become_validator, BecomeValidator, Epoch};
    use namada::state::StorageWrite;
    use namada::tendermint::abci::types::VoteInfo;
    use namada::tx::{SignableEthMessage, Signed};
    use namada::types::ethereum_events::Uint;
    use namada::types::keccak::{keccak_hash, KeccakHash};
    use namada::types::key::*;
    use namada::types::storage::BlockHeight;
    use namada::types::token;
    use namada::vote_ext::bridge_pool_roots;
    use namada_sdk::eth_bridge::EthBridgeQueries;

    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet::defaults::{bertha_address, bertha_keypair};

    /// Make Bertha a validator.
    fn add_validator(shell: &mut TestShell) {
        // We make a change so that there Bertha is
        // a validator in the next epoch
        let validators_handle = consensus_validator_set_handle();
        validators_handle
            .at(&1.into())
            .at(&token::Amount::native_whole(100))
            .insert(
                &mut shell.wl_storage,
                ValidatorPosition(1),
                bertha_address(),
            )
            .expect("Test failed");

        // change pipeline length to 1
        let mut params = shell.wl_storage.pos_queries().get_pos_params();
        params.owned.pipeline_len = 1;

        let consensus_key = gen_keypair();
        let protocol_key = bertha_keypair();
        let hot_key = gen_secp256k1_keypair();
        let cold_key = gen_secp256k1_keypair();

        become_validator(
            &mut shell.wl_storage,
            BecomeValidator {
                params: &params,
                address: &bertha_address(),
                consensus_key: &consensus_key.ref_to(),
                protocol_key: &protocol_key.ref_to(),
                eth_hot_key: &hot_key.ref_to(),
                eth_cold_key: &cold_key.ref_to(),
                current_epoch: 0.into(),
                commission_rate: Default::default(),
                max_commission_rate_change: Default::default(),
                metadata: Default::default(),
                offset_opt: None,
            },
        )
        .expect("Test failed");

        // we advance forward to the next epoch
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

        // Check that Bertha's vote extensions pass validation.
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(&hot_key, to_sign).sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: bertha_address(),
            sig,
        }
        .sign(&bertha_keypair());
        shell.wl_storage.storage.block.height =
            shell.wl_storage.storage.get_last_block_height();
        shell.commit();
        assert!(shell.validate_bp_roots_vext(
            vote_ext.0,
            shell.wl_storage.storage.get_last_block_height()
        ));
    }

    /// Test that the function crafting the bridge pool root
    /// vext creates the expected payload. Check that this
    /// payload passes validation.
    #[test]
    fn test_happy_flow() {
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(1u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        shell.wl_storage.storage.block.height =
            shell.wl_storage.storage.get_last_block_height();
        shell.commit();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert_eq!(
            vote_ext.0,
            shell.extend_vote_with_bp_roots().expect("Test failed")
        );
        assert!(shell.validate_bp_roots_vext(
            vote_ext.0,
            shell.wl_storage.storage.get_last_block_height(),
        ))
    }

    /// Test that we de-duplicate the bridge pool vexts
    /// in a block proposal by validator address.
    #[test]
    fn test_vexts_are_de_duped() {
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(1u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        shell.wl_storage.storage.block.height =
            shell.wl_storage.storage.get_last_block_height();
        shell.commit();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        let valid = shell
            .filter_invalid_bp_roots_vexts(vec![
                vote_ext.0.clone(),
                vote_ext.0.clone(),
            ])
            .map(|(_, vext)| vext)
            .collect::<Vec<_>>();
        assert_eq!(valid, vec![vote_ext.0]);
    }

    /// Test that Bridge pool roots signed by a non-validator are rejected
    /// even if the vext is signed by a validator
    #[test]
    fn test_bp_roots_must_be_signed_by_validator() {
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(1u64);
        let signing_key = gen_keypair();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        shell.wl_storage.storage.block.height =
            shell.wl_storage.storage.get_last_block_height();
        shell.commit();
        let to_sign = get_bp_bytes_to_sign();
        let sig =
            Signed::<_, SignableEthMessage>::new(&signing_key, to_sign).sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(!shell.validate_bp_roots_vext(
            bp_root.0,
            shell.get_current_decision_height(),
        ))
    }

    /// Test that Bridge pool root vext and inner signature
    /// are from the same validator.
    #[test]
    fn test_bp_root_sigs_from_same_validator() {
        let (mut shell, _broadcaster, _, _oracle_control_recv) =
            setup_at_height(3u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        add_validator(&mut shell);
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(&bertha_keypair());
        assert!(!shell.validate_bp_roots_vext(
            bp_root.0,
            shell.wl_storage.storage.get_last_block_height()
        ))
    }

    fn reject_incorrect_block_number(height: BlockHeight, shell: &TestShell) {
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: height,
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        assert!(!shell.validate_bp_roots_vext(
            bp_root.0,
            shell.wl_storage.storage.get_last_block_height()
        ))
    }

    /// Test that an [`bridge_pool_roots::Vext`] that labels its included
    /// block height as greater than the latest block height is rejected.
    #[test]
    fn test_block_height_too_high() {
        let (shell, _, _, _) = setup_at_height(3u64);
        reject_incorrect_block_number(
            shell.wl_storage.storage.get_last_block_height() + 1,
            &shell,
        );
    }

    /// Test if we reject Bridge pool roots vote extensions
    /// issued at genesis.
    #[test]
    fn test_reject_genesis_vexts() {
        let (shell, _, _, _) = setup();
        reject_incorrect_block_number(0.into(), &shell);
    }

    /// Test that a bridge pool root vext is rejected
    /// if the nonce is incorrect.
    #[test]
    fn test_incorrect_nonce() {
        let (shell, _, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(!shell.validate_bp_roots_vext(
            bp_root.0,
            shell.wl_storage.storage.get_last_block_height()
        ))
    }

    /// Test that a bridge pool root vext is rejected
    /// if the root is incorrect.
    #[test]
    fn test_incorrect_root() {
        let (shell, _, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(!shell.validate_bp_roots_vext(
            bp_root.0,
            shell.wl_storage.storage.get_last_block_height()
        ))
    }

    /// Test that we can verify vext from several block heights
    /// prior.
    #[test]
    fn test_vext_for_old_height() {
        let (mut shell, _recv, _, _oracle_control_recv) = setup_at_height(1u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        shell.wl_storage.storage.block.height = 2.into();
        let key = get_key_from_hash(&KeccakHash([1; 32]));
        let height = shell.wl_storage.storage.block.height;
        shell.wl_storage.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .wl_storage
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(2.into())
                .unwrap(),
            KeccakHash([1; 32])
        );
        shell.wl_storage.storage.block.height = 3.into();
        shell.wl_storage.delete(&key).expect("Test failed");
        let key = get_key_from_hash(&KeccakHash([2; 32]));
        let height = shell.wl_storage.storage.block.height;
        shell.wl_storage.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .wl_storage
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(3.into())
                .unwrap(),
            KeccakHash([2; 32])
        );
        let to_sign = keccak_hash([[1; 32], Uint::from(0).to_bytes()].concat());
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: 2.into(),
            validator_addr: address.clone(),
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(shell.validate_bp_roots_vext(
            bp_root.0,
            shell.get_current_decision_height()
        ));
        let to_sign = keccak_hash([[2; 32], Uint::from(0).to_bytes()].concat());
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: 3.into(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(shell.validate_bp_roots_vext(
            bp_root.0,
            shell.get_current_decision_height()
        ));
    }

    /// Test that if the wrong block height is given for the provided root,
    /// we reject.
    #[test]
    fn test_wrong_height_for_root() {
        let (mut shell, _recv, _, _oracle_control_recv) = setup_at_height(1u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        shell.wl_storage.storage.block.height = 2.into();
        let key = get_key_from_hash(&KeccakHash([1; 32]));
        let height = shell.wl_storage.storage.block.height;
        shell.wl_storage.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .wl_storage
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(2.into())
                .unwrap(),
            KeccakHash([1; 32])
        );
        shell.wl_storage.storage.block.height = 3.into();
        shell.wl_storage.delete(&key).expect("Test failed");
        let key = get_key_from_hash(&KeccakHash([2; 32]));
        let height = shell.wl_storage.storage.block.height;
        shell.wl_storage.write(&key, height).expect("Test failed");
        shell.commit();
        assert_eq!(
            shell
                .wl_storage
                .ethbridge_queries()
                .get_bridge_pool_root_at_height(3.into())
                .unwrap(),
            KeccakHash([2; 32])
        );
        let to_sign = keccak_hash([[1; 32], Uint::from(0).to_bytes()].concat());
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: 3.into(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(!shell.validate_bp_roots_vext(
            bp_root.0,
            shell.get_current_decision_height()
        ));
    }
}
