//! Code for handling validator set update protocol txs.

use std::collections::{HashMap, HashSet};

use eyre::Result;
use namada_core::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use namada_core::types::address::Address;
use namada_core::types::storage::BlockHeight;
#[allow(unused_imports)]
use namada_core::types::transaction::protocol::ProtocolTxType;
use namada_core::types::transaction::TxResult;
use namada_core::types::vote_extensions::validator_set_update;
use namada_core::types::voting_power::FractionalVotingPower;

use super::ChangedKeys;
use crate::protocol::transactions::utils;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{self, Votes};
use crate::storage::proof::EthereumProof;
use crate::storage::vote_tallies;

impl utils::GetVoters for validator_set_update::VextDigest {
    #[inline]
    fn get_voters(
        &self,
        epoch_start_height: BlockHeight,
    ) -> HashSet<(Address, BlockHeight)> {
        // votes were cast the the 2nd block height of the current epoch
        let epoch_2nd_height = epoch_start_height + 1;
        self.signatures
            .keys()
            .cloned()
            .zip(std::iter::repeat(epoch_2nd_height))
            .collect()
    }
}

pub fn aggregate_votes<D, H>(
    storage: &mut Storage<D, H>,
    ext: validator_set_update::VextDigest,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if ext.signatures.is_empty() {
        tracing::debug!("Ignoring empty validator set update");
        return Ok(Default::default());
    }

    tracing::info!(
        num_votes = ext.signatures.len(),
        "Aggregating new votes for validator set update"
    );

    let voting_powers = utils::get_voting_powers(storage, &ext)?;
    let changed_keys = apply_update(storage, ext, voting_powers)?;

    Ok(TxResult {
        changed_keys,
        ..Default::default()
    })
}

fn apply_update<D, H>(
    storage: &mut Storage<D, H>,
    ext: validator_set_update::VextDigest,
    voting_powers: HashMap<(Address, BlockHeight), FractionalVotingPower>,
) -> Result<ChangedKeys>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let next_epoch = {
        // proofs should be written to the sub-key space of the next epoch.
        // this way, we do, for instance, an RPC call to `E=2` to query a
        // validator set proof for epoch 2 signed by validators of epoch 1.
        storage.get_current_epoch().0.next()
    };
    let epoch_start_height = storage
        .block
        .pred_epochs
        .first_block_heights()
        .last()
        .copied()
        .expect("The block height of the current epoch should be known");

    let valset_upd_keys = vote_tallies::Keys::from(&next_epoch);
    let maybe_proof = 'check_storage: {
        let Some(seen) = votes::storage::maybe_read_seen(storage, &valset_upd_keys)? else {
            break 'check_storage None;
        };
        if seen {
            tracing::debug!("Validator set update tally is already seen");
            return Ok(ChangedKeys::default());
        }
        let proof = votes::storage::read_body(storage, &valset_upd_keys)?;
        Some(proof)
    };

    let mut seen_by = Votes::default();
    for address in ext.signatures.keys().cloned() {
        if let Some(present) = seen_by.insert(address, epoch_start_height) {
            // TODO(namada#770): this shouldn't be happening in any case and we
            // should be refactoring to get rid of `BlockHeight`
            tracing::warn!(?present, "Duplicate vote in digest");
        }
    }

    let (tally, proof, changed, confirmed) = if let Some(mut proof) =
        maybe_proof
    {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Validator set update votes already in storage",
        );
        let new_votes = NewVotes::new(seen_by, &voting_powers)?;
        let (tally, changed) =
            votes::update::calculate(storage, &valset_upd_keys, new_votes)?;
        if changed.is_empty() {
            return Ok(changed);
        }
        let confirmed = tally.seen && changed.contains(&valset_upd_keys.seen());
        proof.attach_signature_batch(
            ext.signatures
                .into_iter()
                .map(|(addr, sig)| ((addr, epoch_start_height), sig)),
        );
        (tally, proof, changed, confirmed)
    } else {
        tracing::debug!(
            %valset_upd_keys.prefix,
            ?ext.voting_powers,
            "New validator set update vote aggregation started"
        );
        let tally = votes::calculate_new(seen_by, &voting_powers)?;
        let mut proof = EthereumProof::new(ext.voting_powers);
        proof.attach_signature_batch(
            ext.signatures
                .into_iter()
                .map(|(addr, sig)| ((addr, epoch_start_height), sig)),
        );
        let changed = valset_upd_keys.into_iter().collect();
        let confirmed = tally.seen;
        (tally, proof, changed, confirmed)
    };

    tracing::debug!(
        ?tally,
        ?proof,
        "Applying validator set update state changes"
    );
    votes::storage::write(storage, &valset_upd_keys, &proof, &tally)?;

    if confirmed {
        tracing::debug!(
            %valset_upd_keys.prefix,
            "Acquired complete proof on validator set update"
        );
    }

    Ok(changed)
}

#[cfg(test)]
mod test_valset_upd_state_changes {
    use namada_core::types::address;
    use namada_core::types::vote_extensions::validator_set_update::VotingPowersMap;
    use namada_core::types::voting_power::FractionalVotingPower;
    use namada_proof_of_stake::pos_queries::PosQueries;

    use super::*;
    use crate::test_utils;

    /// Test that if a validator set update becomes "seen", then
    /// it should have a complete proof backing it up in storage.
    #[test]
    fn test_seen_has_complete_proof() {
        let (mut storage, keys) = test_utils::setup_default_storage();

        let last_height = storage.last_height;
        let signing_epoch = storage
            .get_epoch(last_height)
            .expect("The epoch of the last block height should be known");

        let tx_result = aggregate_votes(
            &mut storage,
            validator_set_update::VextDigest::singleton(
                validator_set_update::Vext {
                    voting_powers: VotingPowersMap::new(),
                    validator_addr: address::testing::established_address_1(),
                    signing_epoch,
                }
                .sign(
                    &keys
                        .get(&address::testing::established_address_1())
                        .expect("Test failed")
                        .eth_bridge,
                ),
            ),
        )
        .expect("Test failed");

        // let's make sure we updated storage
        assert!(!tx_result.changed_keys.is_empty());

        let valset_upd_keys = vote_tallies::Keys::from(&signing_epoch.next());

        assert!(tx_result.changed_keys.contains(&valset_upd_keys.body()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen_by()));
        assert!(
            tx_result
                .changed_keys
                .contains(&valset_upd_keys.voting_power())
        );

        // check if the valset upd is marked as "seen"
        let tally = votes::storage::read(&storage, &valset_upd_keys)
            .expect("Test failed");
        assert!(tally.seen);

        // read the proof in storage and make sure its signature is
        // from the configured validator
        let proof = votes::storage::read_body(&storage, &valset_upd_keys)
            .expect("Test failed");
        assert_eq!(proof.data, VotingPowersMap::new());

        let mut proof_sigs: Vec<_> = proof.signatures.into_keys().collect();
        assert_eq!(proof_sigs.len(), 1);

        let (addr, height) = proof_sigs.pop().expect("Test failed");
        let epoch_start_height = storage
            .block
            .pred_epochs
            .first_block_heights()
            .last()
            .copied()
            .expect("The block height of the current epoch should be known");
        assert_eq!(height, epoch_start_height,);
        assert_eq!(addr, address::testing::established_address_1());

        // since only one validator is configured, we should
        // have reached a complete proof
        let total_voting_power =
            storage.get_total_voting_power(Some(signing_epoch)).into();
        let validator_voting_power: u64 = storage
            .get_validator_from_address(&addr, Some(signing_epoch))
            .expect("Test failed")
            .0
            .into();
        let voting_power = FractionalVotingPower::new(
            validator_voting_power,
            total_voting_power,
        )
        .expect("Test failed");

        assert!(voting_power > FractionalVotingPower::TWO_THIRDS);
    }

    /// Test that if a validator set update is not "seen" yet, then
    /// it should never have a complete proof backing it up in storage.
    #[test]
    fn test_not_seen_has_incomplete_proof() {
        let (mut storage, keys) =
            test_utils::setup_storage_with_validators(HashMap::from_iter([
                // the first validator has exactly 2/3 of the total stake
                (address::testing::established_address_1(), 50_000_u64.into()),
                (address::testing::established_address_2(), 25_000_u64.into()),
            ]));

        let last_height = storage.last_height;
        let signing_epoch = storage
            .get_epoch(last_height)
            .expect("The epoch of the last block height should be known");

        let tx_result = aggregate_votes(
            &mut storage,
            validator_set_update::VextDigest::singleton(
                validator_set_update::Vext {
                    voting_powers: VotingPowersMap::new(),
                    validator_addr: address::testing::established_address_1(),
                    signing_epoch,
                }
                .sign(
                    &keys
                        .get(&address::testing::established_address_1())
                        .expect("Test failed")
                        .eth_bridge,
                ),
            ),
        )
        .expect("Test failed");

        // let's make sure we updated storage
        assert!(!tx_result.changed_keys.is_empty());

        let valset_upd_keys = vote_tallies::Keys::from(&signing_epoch.next());

        assert!(tx_result.changed_keys.contains(&valset_upd_keys.body()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen_by()));
        assert!(
            tx_result
                .changed_keys
                .contains(&valset_upd_keys.voting_power())
        );

        // assert the validator set update is not "seen" yet
        let tally = votes::storage::read(&storage, &valset_upd_keys)
            .expect("Test failed");
        assert!(!tally.seen);

        // read the proof in storage and make sure its signature is
        // from the configured validator
        let proof = votes::storage::read_body(&storage, &valset_upd_keys)
            .expect("Test failed");
        assert_eq!(proof.data, VotingPowersMap::new());

        let mut proof_sigs: Vec<_> = proof.signatures.into_keys().collect();
        assert_eq!(proof_sigs.len(), 1);

        let (addr, height) = proof_sigs.pop().expect("Test failed");
        let epoch_start_height = storage
            .block
            .pred_epochs
            .first_block_heights()
            .last()
            .copied()
            .expect("The block height of the current epoch should be known");
        assert_eq!(height, epoch_start_height,);
        assert_eq!(addr, address::testing::established_address_1());

        // make sure we do not have a complete proof yet
        let total_voting_power =
            storage.get_total_voting_power(Some(signing_epoch)).into();
        let validator_voting_power: u64 = storage
            .get_validator_from_address(&addr, Some(signing_epoch))
            .expect("Test failed")
            .0
            .into();
        let voting_power = FractionalVotingPower::new(
            validator_voting_power,
            total_voting_power,
        )
        .expect("Test failed");

        assert!(voting_power <= FractionalVotingPower::TWO_THIRDS);
    }
}
