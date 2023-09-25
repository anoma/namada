use std::collections::{HashMap, HashSet};

use eyre::Result;
use namada_core::ledger::eth_bridge::storage::bridge_pool::get_signed_root_key;
use namada_core::ledger::storage::{DBIter, StorageHasher, WlStorage, DB};
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::address::Address;
use namada_core::types::storage::BlockHeight;
use namada_core::types::token::Amount;
use namada_core::types::transaction::TxResult;
use namada_core::types::vote_extensions::bridge_pool_roots::MultiSignedVext;
use namada_proof_of_stake::pos_queries::PosQueries;

use crate::protocol::transactions::utils::GetVoters;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{calculate_new, Votes};
use crate::protocol::transactions::{utils, votes, ChangedKeys};
use crate::storage::eth_bridge_queries::EthBridgeQueries;
use crate::storage::proof::BridgePoolRootProof;
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
    wl_storage: &mut WlStorage<D, H>,
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
    let voting_powers = utils::get_voting_powers(wl_storage, &vext)?;
    let root_height = vext.iter().next().unwrap().data.block_height;
    let (partial_proof, seen_by) = parse_vexts(wl_storage, vext);

    // return immediately if a complete proof has already been acquired
    let bp_key = vote_tallies::Keys::from((&partial_proof, root_height));
    let seen =
        votes::storage::maybe_read_seen(wl_storage, &bp_key)?.unwrap_or(false);
    if seen {
        tracing::debug!(
            ?root_height,
            ?partial_proof,
            "Bridge pool root tally is already complete"
        );
        return Ok(TxResult::default());
    }

    // apply updates to the bridge pool root.
    let (mut changed, confirmed_update) = apply_update(
        wl_storage,
        bp_key,
        partial_proof,
        seen_by,
        &voting_powers,
    )?;

    // if the root is confirmed, update storage and add
    // relevant key to changed.
    if let Some(proof) = confirmed_update {
        let signed_root_key = get_signed_root_key();
        let should_write_root = wl_storage
            .read::<(BridgePoolRoot, BlockHeight)>(&signed_root_key)
            .expect(
                "Reading a signed Bridge pool root from storage should not \
                 fail",
            )
            .map(|(_, existing_root_height)| {
                // only write the newly confirmed signed root if
                // it is more recent than the existing root in
                // storage
                existing_root_height < root_height
            })
            .unwrap_or({
                // if no signed root was present in storage, write the new one
                true
            });
        if should_write_root {
            tracing::debug!(
                ?root_height,
                "New Bridge pool root proof acquired"
            );
            wl_storage
                .write(&signed_root_key, (proof, root_height))
                .expect(
                    "Writing a signed Bridge pool root to storage should not \
                     fail.",
                );
            changed.insert(get_signed_root_key());
        } else {
            tracing::debug!(
                ?root_height,
                "Discarding outdated Bridge pool root proof"
            );
        }
    }

    Ok(TxResult {
        changed_keys: changed,
        ..Default::default()
    })
}

impl GetVoters for &MultiSignedVext {
    fn get_voters(self) -> HashSet<(Address, BlockHeight)> {
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
    wl_storage: &WlStorage<D, H>,
    multisigned: MultiSignedVext,
) -> (BridgePoolRoot, Votes)
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let height = multisigned.iter().next().unwrap().data.block_height;
    let epoch = wl_storage.pos_queries().get_epoch(height);
    let root = wl_storage
        .ethbridge_queries()
        .get_bridge_pool_root_at_height(height)
        .expect("A BP root should be available at the given height");
    let nonce = wl_storage
        .ethbridge_queries()
        .get_bridge_pool_nonce_at_height(height);
    let mut partial_proof = BridgePoolRootProof::new((root, nonce));
    partial_proof.attach_signature_batch(multisigned.clone().into_iter().map(
        |signed| {
            (
                wl_storage
                    .ethbridge_queries()
                    .get_eth_addr_book(&signed.data.validator_addr, epoch)
                    .unwrap(),
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
    wl_storage: &mut WlStorage<D, H>,
    bp_key: vote_tallies::Keys<BridgePoolRoot>,
    mut update: BridgePoolRoot,
    seen_by: Votes,
    voting_powers: &HashMap<(Address, BlockHeight), Amount>,
) -> Result<(ChangedKeys, Option<BridgePoolRoot>)>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let partial_proof = votes::storage::read_body(wl_storage, &bp_key);
    let (vote_tracking, changed, confirmed, already_present) = if let Ok(
        partial,
    ) =
        partial_proof
    {
        tracing::debug!(
            %bp_key.prefix,
            "Signatures for this Bridge pool update already exists in storage",
        );
        update.0.attach_signature_batch(partial.0.signatures);
        let new_votes = NewVotes::new(seen_by, voting_powers)?;
        let (vote_tracking, changed) =
            votes::update::calculate(wl_storage, &bp_key, new_votes)?;
        if changed.is_empty() {
            return Ok((changed, None));
        }
        let confirmed = vote_tracking.seen && changed.contains(&bp_key.seen());
        (vote_tracking, changed, confirmed, true)
    } else {
        tracing::debug!(%bp_key.prefix, "No validator has signed this bridge pool update before.");
        let vote_tracking = calculate_new(wl_storage, seen_by, voting_powers)?;
        let changed = bp_key.into_iter().collect();
        let confirmed = vote_tracking.seen;
        (vote_tracking, changed, confirmed, false)
    };

    votes::storage::write(
        wl_storage,
        &bp_key,
        &update,
        &vote_tracking,
        already_present,
    )?;
    Ok((changed, confirmed.then_some(update)))
}

#[cfg(test)]
mod test_apply_bp_roots_to_storage {
    use std::collections::BTreeSet;

    use assert_matches::assert_matches;
    use borsh::{BorshDeserialize, BorshSerialize};
    use namada_core::ledger::eth_bridge::storage::bridge_pool::{
        get_key_from_hash, get_nonce_key,
    };
    use namada_core::ledger::storage::testing::TestWlStorage;
    use namada_core::ledger::storage_api::StorageRead;
    use namada_core::proto::{SignableEthMessage, Signed};
    use namada_core::types::address;
    use namada_core::types::ethereum_events::Uint;
    use namada_core::types::keccak::{keccak_hash, KeccakHash};
    use namada_core::types::storage::Key;
    use namada_core::types::vote_extensions::bridge_pool_roots;
    use namada_core::types::voting_power::FractionalVotingPower;
    use namada_proof_of_stake::parameters::PosParams;
    use namada_proof_of_stake::write_pos_params;

    use super::*;
    use crate::protocol::transactions::votes::{
        EpochedVotingPower, EpochedVotingPowerExt,
    };
    use crate::{bridge_pool_vp, test_utils};

    /// The data needed to run a test.
    struct TestPackage {
        /// Two validators
        validators: [Address; 3],
        /// The validator keys.
        keys: HashMap<Address, test_utils::TestValidatorKeys>,
        /// Storage.
        wl_storage: TestWlStorage,
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
        let (mut wl_storage, keys) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b.clone(), Amount::native_whole(100)),
                (validator_c.clone(), Amount::native_whole(40)),
            ]),
        );
        bridge_pool_vp::init_storage(&mut wl_storage);
        test_utils::commit_bridge_pool_root_at_height(
            &mut wl_storage.storage,
            &KeccakHash([1; 32]),
            99.into(),
        );
        test_utils::commit_bridge_pool_root_at_height(
            &mut wl_storage.storage,
            &KeccakHash([1; 32]),
            100.into(),
        );
        let value = BlockHeight(101).try_to_vec().expect("Test failed");
        wl_storage
            .storage
            .block
            .tree
            .update(&get_key_from_hash(&KeccakHash([1; 32])), value)
            .expect("Test failed");
        wl_storage
            .write_bytes(
                &get_nonce_key(),
                Uint::from(42).try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
        TestPackage {
            validators: [validator_a, validator_b, validator_c],
            keys,
            wl_storage,
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
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut wl_storage, vext.into())
                .expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));
        let expected: BTreeSet<Key> = bp_root_key.into_iter().collect();
        assert_eq!(expected, changed_keys);

        let hot_key = &keys[&validators[2]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[2].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[2]].protocol);

        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut wl_storage, vext.into())
                .expect("Test failed");

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
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut vexts: MultiSignedVext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol)
        .into();
        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        vexts.insert(vext);
        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut wl_storage, vexts).expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
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
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        let TxResult { changed_keys, .. } =
            apply_derived_tx(&mut wl_storage, vext.into())
                .expect("Test failed");
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
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
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));

        let hot_key = &keys[&validators[0]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");
        let voting_power = wl_storage
            .read::<EpochedVotingPower>(&bp_root_key.voting_power())
            .expect("Test failed")
            .expect("Test failed")
            .fractional_stake(&wl_storage);
        assert_eq!(
            voting_power,
            FractionalVotingPower::new_u64(5, 12).unwrap()
        );

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");
        let voting_power = wl_storage
            .read::<EpochedVotingPower>(&bp_root_key.voting_power())
            .expect("Test failed")
            .expect("Test failed")
            .fractional_stake(&wl_storage);
        assert_eq!(voting_power, FractionalVotingPower::new_u64(5, 6).unwrap());
    }

    #[test]
    /// Test that the seen storage key is updated correctly.
    fn test_seen() {
        let TestPackage {
            validators,
            keys,
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;

        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");

        let seen: bool = BorshDeserialize::try_from_slice(
            wl_storage
                .read_bytes(&bp_root_key.seen())
                .expect("Test failed")
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert!(!seen);

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");

        let seen: bool = BorshDeserialize::try_from_slice(
            wl_storage
                .read_bytes(&bp_root_key.seen())
                .expect("Test failed")
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
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;

        let bp_root_key = vote_tallies::Keys::from((
            &BridgePoolRoot(BridgePoolRootProof::new((root, nonce))),
            100.into(),
        ));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");

        let expected = Votes::from([(validators[0].clone(), 100.into())]);
        let seen_by: Votes = BorshDeserialize::try_from_slice(
            wl_storage
                .read_bytes(&bp_root_key.seen_by())
                .expect("Test failed")
                .expect("Test failed")
                .as_slice(),
        )
        .expect("Test failed");
        assert_eq!(seen_by, expected);

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");

        let expected = Votes::from([
            (validators[0].clone(), 100.into()),
            (validators[1].clone(), 100.into()),
        ]);
        let seen_by: Votes = BorshDeserialize::try_from_slice(
            wl_storage
                .read_bytes(&bp_root_key.seen_by())
                .expect("Test failed")
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
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut expected =
            BridgePoolRoot(BridgePoolRootProof::new((root, nonce)));
        let bp_root_key = vote_tallies::Keys::from((&expected, 100.into()));

        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        };
        expected.0.attach_signature(
            wl_storage
                .ethbridge_queries()
                .get_eth_addr_book(
                    &validators[0],
                    wl_storage.pos_queries().get_epoch(100.into()),
                )
                .expect("Test failed"),
            vext.sig.clone(),
        );
        let vext = vext.sign(&keys[&validators[0]].protocol);
        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");

        let proof: BridgePoolRootProof = BorshDeserialize::try_from_slice(
            wl_storage
                .read_bytes(&bp_root_key.body())
                .expect("Test failed")
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
            mut wl_storage,
        } = setup();
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());

        assert!(
            wl_storage
                .read_bytes(&get_signed_root_key())
                .expect("Test failed")
                .is_none()
        );

        let hot_key = &keys[&validators[0]].eth_bridge;
        let mut vexts: MultiSignedVext = bridge_pool_roots::Vext {
            validator_addr: validators[0].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign.clone())
                .sig,
        }
        .sign(&keys[&validators[0]].protocol)
        .into();

        let hot_key = &keys[&validators[1]].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validators[1].clone(),
            block_height: 100.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validators[1]].protocol);

        vexts.insert(vext);
        let epoch = wl_storage.pos_queries().get_epoch(100.into());
        let sigs: Vec<_> = vexts
            .iter()
            .map(|s| {
                (
                    wl_storage
                        .ethbridge_queries()
                        .get_eth_addr_book(&s.data.validator_addr, epoch)
                        .expect("Test failed"),
                    s.data.sig.clone(),
                )
            })
            .collect();

        _ = apply_derived_tx(&mut wl_storage, vexts).expect("Test failed");
        let (proof, _): (BridgePoolRootProof, BlockHeight) =
            BorshDeserialize::try_from_slice(
                wl_storage
                    .read_bytes(&get_signed_root_key())
                    .expect("Test failed")
                    .expect("Test failed")
                    .as_slice(),
            )
            .expect("Test failed");
        let mut expected = BridgePoolRootProof::new((root, nonce));
        expected.attach_signature_batch(sigs);
        assert_eq!(proof.signatures, expected.signatures);
        assert_eq!(proof.data, expected.data);
    }

    /// Test that when we acquire a complete BP roots proof,
    /// the block height stored in storage is that of the
    /// tree root that was decided.
    #[test]
    fn test_bp_roots_across_epoch_boundaries() {
        // the validators that will vote in the tally
        let validator_1 = address::testing::established_address_1();
        let validator_1_stake = Amount::native_whole(100);

        let validator_2 = address::testing::established_address_2();
        let validator_2_stake = Amount::native_whole(100);

        let validator_3 = address::testing::established_address_3();
        let validator_3_stake = Amount::native_whole(100);

        // start epoch 0 with validator 1
        let (mut wl_storage, keys) = test_utils::setup_storage_with_validators(
            HashMap::from([(validator_1.clone(), validator_1_stake)]),
        );

        // update the pos params
        let params = PosParams {
            pipeline_len: 1,
            ..Default::default()
        };
        write_pos_params(&mut wl_storage, params).expect("Test failed");

        // insert validators 2 and 3 at epoch 1
        test_utils::append_validators_to_storage(
            &mut wl_storage,
            HashMap::from([
                (validator_2.clone(), validator_2_stake),
                (validator_3.clone(), validator_3_stake),
            ]),
        );

        // query validators to make sure they were inserted correctly
        macro_rules! query_validators {
            () => {
                |epoch: u64| {
                    wl_storage
                        .pos_queries()
                        .get_consensus_validators(Some(epoch.into()))
                        .iter()
                        .map(|validator| {
                            (validator.address, validator.bonded_stake)
                        })
                        .collect::<HashMap<_, _>>()
                }
            };
        }
        let query_validators = query_validators!();
        let epoch_0_validators = query_validators(0);
        let epoch_1_validators = query_validators(1);
        _ = query_validators;
        assert_eq!(
            epoch_0_validators,
            HashMap::from([(validator_1.clone(), validator_1_stake)])
        );
        assert_eq!(
            wl_storage
                .pos_queries()
                .get_total_voting_power(Some(0.into())),
            validator_1_stake,
        );
        assert_eq!(
            epoch_1_validators,
            HashMap::from([
                (validator_1.clone(), validator_1_stake),
                (validator_2, validator_2_stake),
                (validator_3, validator_3_stake),
            ])
        );
        assert_eq!(
            wl_storage
                .pos_queries()
                .get_total_voting_power(Some(1.into())),
            validator_1_stake + validator_2_stake + validator_3_stake,
        );

        // set up the bridge pool's storage
        bridge_pool_vp::init_storage(&mut wl_storage);
        test_utils::commit_bridge_pool_root_at_height(
            &mut wl_storage.storage,
            &KeccakHash([1; 32]),
            3.into(),
        );

        // construct proof
        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let hot_key = &keys[&validator_1].eth_bridge;
        let vext = bridge_pool_roots::Vext {
            validator_addr: validator_1.clone(),
            block_height: 3.into(),
            sig: Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig,
        }
        .sign(&keys[&validator_1].protocol);

        _ = apply_derived_tx(&mut wl_storage, vext.into())
            .expect("Test failed");

        // query validator set of the proof
        // (should be the one from epoch 0)
        let (_, root_height) = wl_storage
            .ethbridge_queries()
            .get_signed_bridge_pool_root()
            .expect("Test failed");
        let root_epoch = wl_storage
            .pos_queries()
            .get_epoch(root_height)
            .expect("Test failed");

        let query_validators = query_validators!();
        let root_epoch_validators = query_validators(root_epoch.0);
        assert_eq!(epoch_0_validators, root_epoch_validators);
    }

    #[test]
    /// Test that a signed root is not overwritten in storage
    /// if a signed root is decided that had been signed at a
    /// less recent block height.
    fn test_more_recent_signed_root_not_overwritten() {
        let TestPackage {
            validators,
            keys,
            mut wl_storage,
        } = setup();

        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());

        macro_rules! decide_at_height {
            ($block_height:expr) => {
                let hot_key = &keys[&validators[0]].eth_bridge;
                let vext = bridge_pool_roots::Vext {
                    validator_addr: validators[0].clone(),
                    block_height: $block_height.into(),
                    sig: Signed::<_, SignableEthMessage>::new(
                        hot_key,
                        to_sign.clone(),
                    )
                    .sig,
                }
                .sign(&keys[&validators[0]].protocol);
                _ = apply_derived_tx(&mut wl_storage, vext.into())
                    .expect("Test failed");
                let hot_key = &keys[&validators[1]].eth_bridge;
                let vext = bridge_pool_roots::Vext {
                    validator_addr: validators[1].clone(),
                    block_height: $block_height.into(),
                    sig: Signed::<_, SignableEthMessage>::new(
                        hot_key,
                        to_sign.clone(),
                    )
                    .sig,
                }
                .sign(&keys[&validators[1]].protocol);
                _ = apply_derived_tx(&mut wl_storage, vext.into())
                    .expect("Test failed");
            };
        }

        // decide bridge pool root signed at block height 100
        decide_at_height!(100);

        // check the signed root in storage
        let root_in_storage = wl_storage
            .read::<(BridgePoolRoot, BlockHeight)>(&get_signed_root_key())
            .expect("Test failed - storage read failed")
            .expect("Test failed - no signed root in storage");
        assert_matches!(
            root_in_storage,
            (BridgePoolRoot(r), BlockHeight(100))
                if r.data.0 == root && r.data.1 == nonce
        );

        // decide bridge pool root signed at block height 99
        decide_at_height!(99);

        // check the signed root in storage is unchanged
        let root_in_storage = wl_storage
            .read::<(BridgePoolRoot, BlockHeight)>(&get_signed_root_key())
            .expect("Test failed - storage read failed")
            .expect("Test failed - no signed root in storage");
        assert_matches!(
            root_in_storage,
            (BridgePoolRoot(r), BlockHeight(100))
                if r.data.0 == root && r.data.1 == nonce
        );
    }
}
