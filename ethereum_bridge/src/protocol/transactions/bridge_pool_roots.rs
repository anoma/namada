use std::collections::{HashMap, HashSet};

use eyre::Result;
use namada_core::ledger::eth_bridge::storage::bridge_pool::get_signed_root_key;
use namada_core::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada_core::types::address::Address;
use namada_core::types::storage::BlockHeight;
use namada_core::types::transaction::TxResult;
use namada_core::types::vote_extensions::bridge_pool_roots::MultiSignedVext;
use namada_core::types::voting_power::FractionalVotingPower;
use namada_proof_of_stake::pos_queries::PosQueries;

use crate::protocol::transactions::utils::GetVoters;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{calculate_new, Votes};
use crate::protocol::transactions::{utils, votes, ChangedKeys};
use crate::storage::eth_bridge_queries::EthBridgeQueries;
use crate::storage::proof::EthereumProof;
use crate::storage::vote_tallies::{self, BridgePoolRoot};

/// Applies a tally of signatures on over the Ethereum
/// bridge pool root and nonce. Note that every signature
/// passed into this function will be for the same
/// root and nonce.
///
/// For roots + nonces which have been seen by a quorum of
/// validators, the signature is made available for bridge
/// pool proofs.
pub fn apply_derived_tx<D, H>(
    storage: &mut Storage<D, H>,
    vext: MultiSignedVext,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if vext.is_empty() {
        return Ok(TxResult::default());
    }
    tracing::info!(
        bp_root_sigs = vext.len(),
        "Applying state updates derived from signatures of the Ethereum \
         bridge pool root and nonce."
    );
    let voting_powers = utils::get_voting_powers(storage, &vext)?;
    let (partial_proof, seen_by) = parse_vexts(storage, vext);

    // apply updates to the bridge pool root.
    let (mut changed, confirmed) =
        apply_update(storage, partial_proof.clone(), seen_by, &voting_powers)?;

    // if the root is confirmed, update storage and add
    // relevant key to changed.
    if confirmed {
        let proof_bytes = storage
            .read(&vote_tallies::Keys::from(&partial_proof).body())?
            .0
            .expect("This key should be populated.");
        storage.write(&get_signed_root_key(), proof_bytes).expect(
            "Writing a signed bridge pool root to storage should not fail.",
        );
        changed.insert(get_signed_root_key());
    }

    Ok(TxResult {
        changed_keys: changed,
        ..Default::default()
    })
}

impl GetVoters for MultiSignedVext {
    fn get_voters(&self, _: BlockHeight) -> HashSet<(Address, BlockHeight)> {
        self.iter()
            .map(|signed| {
                (signed.data.validator_addr.clone(), signed.data.block_height)
            })
            .collect()
    }
}

/// Convert a set of signatures over bridge pool roots and nonces (at a certain
/// height) into a partial proof and a new set of votes.
fn parse_vexts<D, H>(
    storage: &Storage<D, H>,
    multisigned: MultiSignedVext,
) -> (BridgePoolRoot, Votes)
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let height = multisigned.iter().next().unwrap().data.block_height;
    let epoch = storage.get_epoch(height);
    let root = storage.get_bridge_pool_root_at_height(height);
    let nonce = storage.get_bridge_pool_nonce_at_height(height);
    let mut partial_proof = EthereumProof::new((root, nonce));
    partial_proof.attach_signature_batch(multisigned.clone().into_iter().map(
        |signed| {
            (
                storage.get_eth_addr_book(&signed.data.validator_addr, epoch),
                signed.data.sig,
            )
        },
    ));

    let seen_by: Votes = multisigned
        .into_iter()
        .map(|signed| (signed.data.validator_addr, signed.data.block_height))
        .collect();
    (BridgePoolRoot(partial_proof), seen_by)
}

/// This vote updates the voting power backing a bridge pool root / nonce in
/// storage. If a quorum backs the root / nonce, a boolean is returned
/// indicating that it has been confirmed.
///
/// In all instances, the changed storage keys are returned.
fn apply_update<D, H>(
    storage: &mut Storage<D, H>,
    mut update: BridgePoolRoot,
    seen_by: Votes,
    voting_powers: &HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<(ChangedKeys, bool)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let bp_key = vote_tallies::Keys::from(&update);
    let partial_proof = votes::storage::read_body(storage, &bp_key);
    let (vote_tracking, changed, confirmed) = if let Ok(partial) = partial_proof
    {
        tracing::debug!(
            %bp_key.prefix,
            "Signatures for this Bridge pool update already exists in storage",
        );
        update.0.attach_signature_batch(partial.0.signatures);
        let new_votes = NewVotes::new(seen_by, voting_powers)?;
        let (vote_tracking, changed) =
            votes::update::calculate(storage, &bp_key, new_votes)?;
        if changed.is_empty() {
            return Ok((changed, false));
        }
        let confirmed = vote_tracking.seen && changed.contains(&bp_key.seen());
        (vote_tracking, changed, confirmed)
    } else {
        tracing::debug!(%bp_key.prefix, "No validator has signed this bridge pool update before.");
        let vote_tracking = calculate_new(seen_by, voting_powers)?;
        let changed = bp_key.into_iter().collect();
        let confirmed = vote_tracking.seen;
        (vote_tracking, changed, confirmed)
    };

    votes::storage::write(storage, &bp_key, &update, &vote_tracking)?;
    Ok((changed, confirmed))
}

#[cfg(test)]
mod test_apply_bp_roots_to_storage {
    use std::collections::BTreeSet;

    use borsh::{BorshDeserialize, BorshSerialize};
    use namada_core::ledger::eth_bridge::storage::bridge_pool::{
        get_key_from_hash, get_nonce_key,
    };
    use namada_core::ledger::storage::testing::TestStorage;
    use namada_core::proto::{SignableEthBytes, Signed};
    use namada_core::types::address;
    use namada_core::types::ethereum_events::Uint;
    use namada_core::types::keccak::KeccakHash;
    use namada_core::types::storage::Key;
    use namada_core::types::vote_extensions::bridge_pool_roots;

    use super::*;
    use crate::{bridge_pool_vp, test_utils};

    /// The data needed to run a test.
    struct TestPackage {
        /// Two validators
        validators: [Address; 3],
        /// The validator keys.
        keys: HashMap<Address, test_utils::TestValidatorKeys>,
        /// Storage.
        storage: TestStorage,
    }

    /// Setup storage for tests.
    ///
    ///  * Creates three validators with equal voting power.
    ///  * Makes sure that a bridge pool nonce and root key are initialized.
    ///  * Commits a bridge pool merkle tree at height 100.
    fn setup() -> TestPackage {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let validator_c = address::testing::established_address_4();
        let (mut storage, keys) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), 100_u64.into()),
                (validator_b.clone(), 100_u64.into()),
                (validator_c.clone(), 40_u64.into()),
            ]),
        );
        bridge_pool_vp::init_storage(&mut storage);
        test_utils::commit_bridge_pool_root_at_height(
            &mut storage,
            &KeccakHash([1; 32]),
            100.into(),
        );
        storage
            .block
            .tree
            .update(&get_key_from_hash(&KeccakHash([1; 32])), [0])
            .expect("Test failed");
        storage
            .write(
                &get_nonce_key(),
                Uint::from(42).try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
        TestPackage {
            validators: [validator_a, validator_b, validator_c],
            keys,
            storage,
        }
    }

    #[test]
    /// Test that applying a tx changes the expected keys
    /// if a quorum is not present.
    ///
    /// There are two code paths to test: If the key existed in
    /// storage previously or not.
    fn test_update_changed_keys_not_quorum() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();
        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(
                hot_key,
                to_sign.clone(),
            )
            .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut storage, vext.into()).expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from(BridgePoolRoot(
            EthereumProof::new((root, nonce)),
        ));
        let expected: BTreeSet<Key> = bp_root_key.into_iter().collect();
        assert_eq!(expected, changed_keys);

        let hot_key = &keys[&validators[2]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[2].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[2]].protocol);

        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut storage, vext.into()).expect("Test failed");

        let expected: BTreeSet<Key> =
            [bp_root_key.seen_by(), bp_root_key.voting_power()]
                .into_iter()
                .collect();
        assert_eq!(expected, changed_keys);
    }

    #[test]
    /// Test that applying a tx changes the expected keys
    /// if a quorum is present and the tallies were not
    /// present in storage.
    fn test_update_changed_keys_quorum_not_in_storage() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();
        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut vexts: MultiSignedVext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(
                hot_key,
                to_sign.clone(),
            )
            .sig,
        }
        .sign(&keys[&validators[0]].protocol)
        .into();
        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        vexts.insert(vext);
        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut storage, vexts).expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from(BridgePoolRoot(
            EthereumProof::new((root, nonce)),
        ));

        let mut expected: BTreeSet<Key> = bp_root_key.into_iter().collect();
        expected.insert(get_signed_root_key());
        assert_eq!(expected, changed_keys);
    }

    #[test]
    /// Test that applying a tx changes the expected keys
    /// if quorum is present and a partial tally already existed
    /// in storage.
    fn test_update_changed_keys_quorum_in_storage() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();
        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(
                hot_key,
                to_sign.clone(),
            )
            .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut storage, vext.into()).expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from(BridgePoolRoot(
            EthereumProof::new((root, nonce)),
        ));
        let expected: BTreeSet<Key> = [
            bp_root_key.seen(),
            bp_root_key.seen_by(),
            bp_root_key.voting_power(),
            get_signed_root_key(),
        ]
        .into_iter()
        .collect();
        assert_eq!(expected, changed_keys);
    }

    #[test]
    /// Test that the voting power key is updated correctly.
    fn test_voting_power() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();
        let bp_root_key = vote_tallies::Keys::from(BridgePoolRoot(
            EthereumProof::new((root, nonce)),
        ));

        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(
                hot_key,
                to_sign.clone(),
            )
            .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");
        let voting_power = <(u64, u64)>::try_from_slice(
            storage
                .read(&bp_root_key.voting_power())
                .expect("Test failed")
                .0
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert_eq!(voting_power, (5, 12));

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");
        let voting_power = <(u64, u64)>::try_from_slice(
            storage
                .read(&bp_root_key.voting_power())
                .expect("Test failed")
                .0
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert_eq!(voting_power, (5, 6));
    }

    #[test]
    /// Test that the seen storage key is updated correctly.
    fn test_seen() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();
        let hot_key = &keys[&validators[0]].eth_bridge;

        let bp_root_key = vote_tallies::Keys::from(BridgePoolRoot(
            EthereumProof::new((root, nonce)),
        ));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(
                hot_key,
                to_sign.clone(),
            )
            .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");

        let seen: bool = BorshDeserialize::try_from_slice(
            storage
                .read(&bp_root_key.seen())
                .expect("Test failed")
                .0
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert!(!seen);

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");

        let seen: bool = BorshDeserialize::try_from_slice(
            storage
                .read(&bp_root_key.seen())
                .expect("Test failed")
                .0
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert!(seen);
    }

    #[test]
    /// Test that the seen by keys is updated correctly.
    fn test_seen_by() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();
        let hot_key = &keys[&validators[0]].eth_bridge;

        let bp_root_key = vote_tallies::Keys::from(BridgePoolRoot(
            EthereumProof::new((root, nonce)),
        ));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(
                hot_key,
                to_sign.clone(),
            )
            .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");

        let expected = Votes::from([(validators[0].clone(), 100.into())]);
        let seen_by: Votes = BorshDeserialize::try_from_slice(
            storage
                .read(&bp_root_key.seen_by())
                .expect("Test failed")
                .0
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert_eq!(seen_by, expected);

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");

        let expected = Votes::from([
            (validators[0].clone(), 100.into()),
            (validators[1].clone(), 100.into()),
        ]);
        let seen_by: Votes = BorshDeserialize::try_from_slice(
            storage
                .read(&bp_root_key.seen_by())
                .expect("Test failed")
                .0
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert_eq!(seen_by, expected);
    }

    #[test]
    /// Test that the root and nonce are stored correctly.
    fn test_body() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();
        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut expected = BridgePoolRoot(EthereumProof::new((root, nonce)));
        let bp_root_key = vote_tallies::Keys::from(&expected);

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        };
        expected.0.attach_signature(
            validators[0].clone(),
            100.into(),
            vext.sig.clone(),
        );
        let vext = vext.sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut storage, vext.into()).expect("Test failed");

        let proof: EthereumProof<(KeccakHash, Uint)> =
            BorshDeserialize::try_from_slice(
                storage
                    .read(&bp_root_key.body())
                    .expect("Test failed")
                    .0
                    .expect("Test failed")
                    .as_slice(),
            )
            .expect("Test failed");
        assert_eq!(proof.data, expected.0.data);
        assert_eq!(proof.signatures, expected.0.signatures);
    }

    #[test]
    /// Test that we update the bridge pool storage once a quorum
    /// backs the new nonce and root.
    fn test_quorum() {
        let TestPackage {
            validators,
            keys,
            mut storage,
        } = setup();
        let root = storage.get_bridge_pool_root();
        let nonce = storage.get_bridge_pool_nonce();
        let to_sign = [root.0, nonce.clone().to_bytes()].concat();

        assert!(
            storage
                .read(&get_signed_root_key())
                .expect("Test failed")
                .0
                .is_none()
        );

        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut vexts: MultiSignedVext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(
                hot_key,
                to_sign.clone(),
            )
            .sig,
        }
        .sign(&keys[&validators[0]].protocol)
        .into();

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<Vec<u8>, SignableEthBytes>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        vexts.insert(vext);
        let sigs: Vec<_> = vexts
            .iter()
            .map(|s| {
                (
                    (s.data.validator_addr.clone(), s.data.block_height),
                    s.data.sig.clone(),
                )
            })
            .collect();

        _ = apply_derived_tx(&mut storage, vexts).expect("Test failed");
        let proof: EthereumProof<(KeccakHash, Uint)> =
            BorshDeserialize::try_from_slice(
                storage
                    .read(&get_signed_root_key())
                    .expect("Test failed")
                    .0
                    .expect("Test failed")
                    .as_slice(),
            )
            .expect("Test failed");
        let mut expected = EthereumProof::new((root, nonce));
        expected.attach_signature_batch(sigs);
        assert_eq!(proof.signatures, expected.signatures);
        assert_eq!(proof.data, expected.data);
    }
}
