//! Extend Tendermint votes with signatures of the Ethereum
//! bridge pool root and nonce seen by a quorum of validators.

use namada::ledger::pos::PosQueries;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
use namada::proto::{Signable, Signed};
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
    ///  * The Tendermint address corresponds to an active validator.
    ///  * The validator correctly signed the extension.
    ///  * The validator signed over the correct height inside of the extension.
    ///  * Check that the inner signature is valid.
    #[inline]
    #[allow(dead_code)]
    pub fn validate_bp_roots_vext(
        &self,
        ext: Signed<bridge_pool_roots::Vext>,
        last_height: BlockHeight,
    ) -> bool {
        self.validate_bp_roots_vext_and_get_it_back(ext, last_height)
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
        #[cfg(feature = "abcipp")]
        if ext.data.block_height != last_height {
            tracing::error!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Bridge pool root's vote extension issued for a block height \
                 different from the expected last height."
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        #[cfg(not(feature = "abcipp"))]
        if ext.data.block_height > last_height {
            tracing::error!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Bridge pool root's vote extension issued for a block height \
                 higher than the chain's last height."
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        if last_height.0 == 0 {
            tracing::error!("Dropping vote extension issued at genesis");
            return Err(VoteExtensionError::IssuedAtGenesis);
        }

        let validator = &ext.data.validator_addr;
        // get the public key associated with this validator
        //
        // NOTE(not(feature = "abciplus")): for ABCI++, we should pass
        // `last_height` here, instead of `ext.data.block_height`
        let ext_height_epoch =
            match self.storage.get_epoch(ext.data.block_height) {
                Some(epoch) => epoch,
                _ => {
                    tracing::error!(
                        block_height = ?ext.data.block_height,
                        "The epoch of the Bridge pool root's vote extension's \
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
                     while validating Bridge pool root's vote extension"
                );
                VoteExtensionError::PubKeyNotInStorage
            })?;
        // verify the signature of the vote extension
        ext.verify(&pk).map_err(|err| {
            tracing::error!(
                ?err,
                ?ext.sig,
                ?pk,
                %validator,
                "Failed to verify the signature of an Bridge pool root's vote \
                 extension issued by some validator"
            );
            VoteExtensionError::VerifySigFailed
        })?;

        let bp_root: KeccakHash = self
            .storage
            .block
            .tree
            .sub_root(&StoreType::BridgePool)
            .into();
        let nonce = Uint::try_from_slice(
            &self
                .storage
                .read(&get_nonce_key())
                .expect("Reading Bridge pool nonce shouldn't fail.")
                .0
                .expect("Reading Bridge pool nonce shouldn't fail."),
        )
        .expect("Deserializing Bridge pool nonce shouldn't fail.")
        .encode()
        .into_inner();
        let signed = [bp_root.encode().into_inner(), nonce].concat();
        let epoched_pk = self
            .storage
            .read_validator_eth_hot_key(validator)
            .expect("A validator should have an Ethereum hot key in storage.");
        let pk = epoched_pk
            .get(ext_height_epoch)
            .expect("We should have an Ethereum hot key for the given epoch");
        common::SigScheme::verify_signature_raw(
            pk,
            SignedKeccakAbi::as_signable(&signed).as_ref(),
            &ext.data.sig,
        )
        .map_err(|err| {
            tracing::error!(
                ?err,
                ?ext.data.sig,
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
    /// valid Brige pool root vote extensions, or the reason why these
    /// are invalid, in the form of a [`VoteExtensionError`].
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
                self.storage.last_height,
            )
        })
    }

    /// Takes a list of signed Bridge pool root vote extensions,
    /// and filters out invalid instances.
    #[inline]
    pub fn filter_invalid_bp_roots_vexts<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<bridge_pool_roots::Vext>>
        + 'iter,
    ) -> impl Iterator<Item = (token::Amount, Signed<bridge_pool_roots::Vext>)> + 'iter
    {
        self.validate_bp_roots_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }
}

#[cfg(test)]
mod test_vote_extensions {
    use borsh::BorshSerialize;
    use namada::ledger::pos;
    use namada::ledger::pos::namada_proof_of_stake::PosBase;
    use namada::ledger::pos::{
        PosQueries, ValidatorConsensusKeys, WeightedValidator,
    };
    use namada::proof_of_stake::types::ValidatorEthKey;
    use namada::proto::{Signed, SignedKeccakAbi};
    use namada::types::eth_abi::Encode;
    use namada::types::ethereum_events::Uint;
    use namada::types::keccak::KeccakHash;
    use namada::types::key::*;
    use namada::types::storage::BlockHeight;
    use namada::types::vote_extensions::bridge_pool_roots;

    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet::defaults::{bertha_address, bertha_keypair};

    /// Make Bertha a validator.
    fn add_validator(shell: &mut TestShell) {
        // We make a change so that there Bertha is
        // a validator in the next epoch
        let mut current_validators = shell.storage.read_validator_set();
        let mut vals = current_validators
            .get(0)
            .expect("Test failed")
            .active
            .clone();
        vals.insert(WeightedValidator {
            bonded_stake: 100,
            address: bertha_address(),
        });
        current_validators.data.insert(
            1,
            Some(pos::types::ValidatorSet {
                active: vals,
                inactive: Default::default(),
            }),
        );
        shell.storage.write_validator_set(&current_validators);

        // register Bertha's protocol key
        let pk_key = protocol_pk_key(&bertha_address());
        shell
            .storage
            .write(
                &pk_key,
                bertha_keypair()
                    .ref_to()
                    .try_to_vec()
                    .expect("Test failed."),
            )
            .expect("Test failed.");

        // change pipeline length to 1
        let mut params = shell.storage.read_pos_params();
        params.pipeline_len = 1;

        // register Bertha's consensus key
        let consensus_key = gen_keypair();
        shell.storage.write_validator_consensus_key(
            &bertha_address(),
            &ValidatorConsensusKeys::init(consensus_key.ref_to(), 0, &params),
        );

        // register Bertha's ethereum keys.
        let hot_key = gen_secp256k1_keypair();
        let cold_key = gen_secp256k1_keypair();
        shell.storage.write_validator_eth_hot_key(
            &bertha_address(),
            &ValidatorEthKey::init(hot_key.ref_to(), 0, &params),
        );
        shell.storage.write_validator_eth_cold_key(
            &bertha_address(),
            &ValidatorEthKey::init(cold_key.ref_to(), 0, &params),
        );

        // we advance forward to the next epoch
        let mut req = FinalizeBlock::default();
        req.header.time = namada::types::time::DateTimeUtc::now();
        shell.storage.last_height = BlockHeight(15);
        shell.finalize_block(req).expect("Test failed");
        shell.commit();
        assert_eq!(shell.storage.get_current_epoch().0.0, 1);

        // Check that Bertha's vote extensions pass validation.
        let to_sign = [
            KeccakHash([0; 32]).encode().into_inner(),
            Uint::from(0).encode().into_inner(),
        ]
        .concat();
        let sig =
            Signed::<Vec<u8>, SignedKeccakAbi>::new(&hot_key, to_sign).sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.storage.get_current_decision_height(),
            validator_addr: bertha_address(),
            sig,
        }
        .sign(&bertha_keypair());

        assert!(shell.validate_bp_roots_vext(
            vote_ext,
            shell.storage.get_current_decision_height(),
        ));
    }

    /// Test that the function crafting the bridge pool root
    /// vext creates the expected payload. Check that this
    /// payload passes validation.
    #[test]
    fn test_happy_flow() {
        let (mut shell, _, _) = setup_at_height(3u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let to_sign = [
            KeccakHash([0; 32]).encode().into_inner(),
            Uint::from(0).encode().into_inner(),
        ]
        .concat();
        let sig = Signed::<Vec<u8>, SignedKeccakAbi>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.storage.last_height,
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert_eq!(vote_ext, shell.extend_vote_with_bp_roots());
        assert!(shell.validate_bp_roots_vext(
            vote_ext,
            shell.storage.get_current_decision_height()
        ))
    }

    /// Test that Bridge pool roots signed by a non-validator are rejected
    /// even if the vext is signed by a validator
    #[test]
    fn test_bp_roots_must_be_signed_by_validator() {
        let (shell, _, _) = setup_at_height(3u64);
        let signing_key = gen_keypair();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let to_sign =
            [&*KeccakHash([0; 32]).encode(), &*Uint::from(0).encode()].concat();
        let sig =
            Signed::<Vec<u8>, SignedKeccakAbi>::new(&signing_key, to_sign).sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.storage.get_current_decision_height(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(!shell.validate_bp_roots_vext(
            bp_root,
            shell.storage.get_current_decision_height(),
        ))
    }

    /// Test that Bridge pool root vext and inner signature
    /// are from the same validator.
    #[test]
    fn test_bp_root_sigs_from_same_validator() {
        let (mut shell, _broadcaster, _) = setup_at_height(3u64);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        add_validator(&mut shell);
        let to_sign = [
            KeccakHash([0; 32]).encode().into_inner(),
            Uint::from(0).encode().into_inner(),
        ]
        .concat();
        let sig = Signed::<Vec<u8>, SignedKeccakAbi>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.storage.get_current_decision_height(),
            validator_addr: address,
            sig,
        }
        .sign(&bertha_keypair());
        assert!(!shell.validate_bp_roots_vext(
            bp_root,
            shell.storage.get_current_decision_height(),
        ))
    }

    /// Test that an [`bridge_pool_roots::Vext`] that labels its included
    /// block height as greater than the latest block height is rejected.
    #[test]
    fn reject_incorrect_block_number() {
        let (shell, _, _) = setup_at_height(3u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = [
            KeccakHash([0; 32]).encode().into_inner(),
            Uint::from(0).encode().into_inner(),
        ]
        .concat();
        let sig = Signed::<Vec<u8>, SignedKeccakAbi>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.storage.last_height + 1,
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        assert!(
            !shell.validate_bp_roots_vext(bp_root, shell.storage.last_height)
        )
    }

    /// Test if we reject Bridge pool roots vote extensions
    /// issued at genesis.
    #[test]
    fn test_reject_genesis_vexts() {
        let (shell, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = [
            KeccakHash([0; 32]).encode().into_inner(),
            Uint::from(0).encode().into_inner(),
        ]
        .concat();
        let sig = Signed::<Vec<u8>, SignedKeccakAbi>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: 0.into(),
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            !shell.validate_bp_roots_vext(bp_root, shell.storage.last_height)
        )
    }

    /// Test that a bridge pool root vext is rejected
    /// if the nonce is incorrect.
    #[test]
    fn test_incorrect_nonce() {
        let (shell, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = [
            KeccakHash([0; 32]).encode().into_inner(),
            Uint::from(10).encode().into_inner(),
        ]
        .concat();
        let sig = Signed::<Vec<u8>, SignedKeccakAbi>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.storage.last_height,
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            !shell.validate_bp_roots_vext(bp_root, shell.storage.last_height)
        )
    }

    /// Test that a bridge pool root vext is rejected
    /// if the root is incorrect.
    #[test]
    fn test_incorrect_root() {
        let (shell, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let to_sign = [
            KeccakHash([1; 32]).encode().into_inner(),
            Uint::from(0).encode().into_inner(),
        ]
        .concat();
        let sig = Signed::<Vec<u8>, SignedKeccakAbi>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let bp_root = bridge_pool_roots::Vext {
            block_height: shell.storage.last_height,
            validator_addr: address,
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(
            !shell.validate_bp_roots_vext(bp_root, shell.storage.last_height)
        )
    }
}
