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
use namada_proof_of_stake::pos_queries::PosQueries;

use super::ChangedKeys;
use crate::protocol::transactions::utils;
use crate::protocol::transactions::votes::update::NewVotes;
use crate::protocol::transactions::votes::{self, Votes};
use crate::storage::proof::EthereumProof;
use crate::storage::vote_tallies;

impl utils::GetVoters for validator_set_update::VextDigest {
    #[inline]
    fn get_voters(&self) -> HashSet<(Address, BlockHeight)> {
        self.signatures.keys().cloned().collect()
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
    let epoch = {
        // all votes we gathered are for the same epoch, so
        // we can just fetch the block height from the first
        // signature we iterate over, and calculate its cor-
        // responding epoch
        let height = ext
            .signatures
            .keys()
            .map(|(_, height)| *height)
            .by_ref()
            .next()
            .expect(
                "We have at least one signature present in this validator set \
                 update vote extension digest",
            );

        storage
            .get_epoch(height)
            .expect("The epoch of the given block height should be known")
    };

    let valset_upd_keys = vote_tallies::Keys::from(&epoch);
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
    for (address, block_height) in ext.signatures.keys().cloned() {
        if let Some(present) = seen_by.insert(address, block_height) {
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
        proof.attach_signature_batch(ext.signatures);
        (tally, proof, changed, confirmed)
    } else {
        tracing::debug!(
            %valset_upd_keys.prefix,
            ?ext.voting_powers,
            "New validator set update vote aggregation started"
        );
        let tally = votes::calculate_new(seen_by, &voting_powers)?;
        let mut proof = EthereumProof::new(ext.voting_powers);
        proof.attach_signature_batch(ext.signatures);
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
    use namada_core::types::vote_extensions::validator_set_update::VotingPowersMap;
    use namada_core::types::{address, key};

    use super::*;
    use crate::test_utils;

    /// Test that if a validator set update becomes "seen", then
    /// it should have a complete proof backing it up in storage.
    #[test]
    fn test_seen_has_complete_proof() {
        let mut storage = test_utils::setup_default_storage();
        let sk = key::testing::keypair_1();

        let last_height = storage.last_height;
        let tx_result = aggregate_votes(
            &mut storage,
            validator_set_update::VextDigest::singleton(
                validator_set_update::Vext {
                    voting_powers: VotingPowersMap::new(),
                    validator_addr: address::testing::established_address_1(),
                    block_height: last_height,
                }
                .sign(&sk),
            ),
        )
        .expect("Test failed");

        // let's make sure we changed storage
        assert!(!tx_result.changed_keys.is_empty());

        let epoch = storage
            .get_epoch(last_height)
            .expect("The epoch of the last block height should be known");
        let valset_upd_keys = vote_tallies::Keys::from(&epoch);

        assert!(tx_result.changed_keys.contains(&valset_upd_keys.body()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen()));
        assert!(tx_result.changed_keys.contains(&valset_upd_keys.seen_by()));
        assert!(
            tx_result
                .changed_keys
                .contains(&valset_upd_keys.voting_power())
        );

        // check if the event is seen
        let tally = votes::storage::read(&storage, &valset_upd_keys)
            .expect("Test failed");
        assert!(tally.seen);

        // since only one validator is configured, we should
        // have reached a complete proof

        // TODO: check that we have >2/3 voting power behind proof
    }
}
