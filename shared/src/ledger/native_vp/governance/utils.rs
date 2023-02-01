//! Governance utility functions

use std::collections::HashMap;
use std::str::FromStr;

use borsh::BorshDeserialize;
use namada_proof_of_stake::PosReadOnly;
use thiserror::Error;

use crate::ledger::governance::storage as gov_storage;
use crate::ledger::pos::BondId;
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::governance::{ProposalVote, TallyResult, VotePower};
use crate::types::storage::{Epoch, Key};
use crate::types::token;

/// Proposal structure holding votes information necessary to compute the
/// outcome
#[derive(Debug)]
pub struct Votes {
    /// Map from validators who votes yay to their total stake amount
    pub yay_validators: HashMap<Address, VotePower>,
    /// Map from delegation who votes yay to their bond amount
    pub yay_delegators: HashMap<Address, HashMap<Address, VotePower>>,
    /// Map from delegation who votes nay to their bond amount
    pub nay_delegators: HashMap<Address, HashMap<Address, VotePower>>,
}

/// Proposal errors
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid validator set deserialization
    #[error("Invalid validator set")]
    InvalidValidatorSet,
    /// Invalid proposal field deserialization
    #[error("Invalid proposal {0}")]
    InvalidProposal(u64),
}

/// Proposal event definition
pub struct ProposalEvent {
    /// Proposal event type
    pub event_type: String,
    /// Proposal event attributes
    pub attributes: HashMap<String, String>,
}

impl ProposalEvent {
    /// Create a proposal event
    pub fn new(
        event_type: String,
        tally: TallyResult,
        id: u64,
        has_proposal_code: bool,
        proposal_code_exit_status: bool,
    ) -> Self {
        let attributes = HashMap::from([
            ("tally_result".to_string(), tally.to_string()),
            ("proposal_id".to_string(), id.to_string()),
            (
                "has_proposal_code".to_string(),
                (!has_proposal_code as u64).to_string(),
            ),
            (
                "proposal_code_exit_status".to_string(),
                (!proposal_code_exit_status as u64).to_string(),
            ),
        ]);
        Self {
            event_type,
            attributes,
        }
    }
}

/// Return a proposal result - accepted only when the result is `Ok(true)`.
pub fn compute_tally<D, H>(
    storage: &Storage<D, H>,
    epoch: Epoch,
    votes: Votes,
) -> storage_api::Result<bool>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let total_stake: VotePower = storage.total_stake(epoch)?.into();
    println!("total_stake: {:#?} for epoch {:?}", total_stake, epoch);

    let Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    } = votes;

    let mut total_yay_staked_tokens = VotePower::from(0_u64);
    for (_, amount) in yay_validators.clone().into_iter() {
        total_yay_staked_tokens += amount;
    }

    // YAY: Add delegator amount whose validator didn't vote / voted nay
    for (_, vote_map) in yay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if !yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens += vote_power;
            }
        }
    }

    // NAY: Remove delegator amount whose validator validator vote yay
    for (_, vote_map) in nay_delegators.iter() {
        for (validator_address, vote_power) in vote_map.iter() {
            if yay_validators.contains_key(validator_address) {
                total_yay_staked_tokens -= vote_power;
            }
        }
    }

    Ok(3 * total_yay_staked_tokens >= 2 * total_stake)
}

/// Prepare Votes structure to compute proposal tally
pub fn get_proposal_votes<D, H>(
    storage: &Storage<D, H>,
    epoch: Epoch,
    proposal_id: u64,
) -> storage_api::Result<Votes>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let validators = storage.validator_addresses(epoch)?;
    println!("validators: {:#?}", validators);

    let vote_prefix_key =
        gov_storage::get_proposal_vote_prefix_key(proposal_id);
    let (vote_iter, _) = storage.iter_prefix(&vote_prefix_key);

    let mut yay_validators = HashMap::new();
    let mut yay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();
    let mut nay_delegators: HashMap<Address, HashMap<Address, VotePower>> =
        HashMap::new();

    for (key, vote_bytes, _) in vote_iter {
        let vote_key = Key::from_str(key.as_str()).ok();
        let vote = ProposalVote::try_from_slice(&vote_bytes[..]).ok();
        match (vote_key, vote) {
            (Some(key), Some(vote)) => {
                let voter_address = gov_storage::get_voter_address(&key);
                match voter_address {
                    Some(voter_address) => {
                        if vote.is_yay() && validators.contains(voter_address) {
                            let amount: VotePower = storage
                                .validator_stake(voter_address, epoch)?
                                .into();
                            yay_validators
                                .insert(voter_address.clone(), amount);
                        } else if !validators.contains(voter_address) {
                            let validator_address =
                                gov_storage::get_vote_delegation_address(&key);
                            match validator_address {
                                Some(validator) => {
                                    let bond_id = BondId {
                                        source: voter_address.clone(),
                                        validator: validator.clone(),
                                    };
                                    let amount =
                                        storage.bond_amount(&bond_id, epoch)?;
                                    if amount != token::Amount::default() {
                                        if vote.is_yay() {
                                            let entry = yay_delegators
                                                .entry(voter_address.to_owned())
                                                .or_default();
                                            entry.insert(
                                                validator.to_owned(),
                                                VotePower::from(amount),
                                            );
                                        } else {
                                            let entry = nay_delegators
                                                .entry(voter_address.to_owned())
                                                .or_default();
                                            entry.insert(
                                                validator.to_owned(),
                                                VotePower::from(amount),
                                            );
                                        }
                                    }
                                }
                                None => continue,
                            }
                        }
                    }
                    None => continue,
                }
            }
            _ => continue,
        }
    }

    Ok(Votes {
        yay_validators,
        yay_delegators,
        nay_delegators,
    })
}

/// Calculate the valid voting window for validator given a proposal epoch
/// details
pub fn is_valid_validator_voting_period(
    current_epoch: Epoch,
    voting_start_epoch: Epoch,
    voting_end_epoch: Epoch,
) -> bool {
    voting_start_epoch < voting_end_epoch
        && current_epoch * 3 <= voting_start_epoch + voting_end_epoch * 2
}

/// Check if an accepted proposal is being executed
pub fn is_proposal_accepted<S>(
    storage: &S,
    tx_data: &[u8],
) -> storage_api::Result<bool>
where
    S: storage_api::StorageRead,
{
    let proposal_id = u64::try_from_slice(tx_data).ok();
    match proposal_id {
        Some(id) => {
            let proposal_execution_key =
                gov_storage::get_proposal_execution_key(id);
            storage.has_key(&proposal_execution_key)
        }
        None => Ok(false),
    }
}

#[cfg(any(test, feature = "testing"))]
/// Helpers for testing governance.
pub mod testing {
    // adapted from eth-bridge-integration namada_ethereum_bridge test_utils
    // module
    use std::collections::{BTreeSet, HashMap};

    use borsh::BorshSerialize;
    use namada_core::types::key::{
        protocol_pk_key, RefTo, SecretKey, SigScheme,
    };
    use namada_proof_of_stake::{PosBase, PosParams};
    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    use super::*;
    use crate::core::types::key;
    use crate::ledger::storage::testing::TestStorage;
    use crate::proof_of_stake::epoched::Epoched;
    use crate::proof_of_stake::types::{
        ValidatorConsensusKeys, ValidatorSet, WeightedValidator,
    };

    /// Validator keys used for testing purposes.
    pub struct TestValidatorKeys {
        /// Consensus keypair.
        pub consensus: key::common::SecretKey,
        /// Protocol keypair.
        pub protocol: key::common::SecretKey,
    }

    /// Set up [`TestStorage`] to have the given validators at epoch 0. Assumes
    /// storage has already been set up by test shell.
    pub fn setup_storage_with_validators(
        storage: &mut TestStorage,
        active_validators: HashMap<Address, token::Amount>,
    ) -> HashMap<Address, TestValidatorKeys> {
        // write validator set
        let validator_set = ValidatorSet {
            active: active_validators
                .iter()
                .map(|(address, bonded_stake)| WeightedValidator {
                    bonded_stake: u64::from(*bonded_stake),
                    address: address.clone(),
                })
                .collect(),
            inactive: BTreeSet::default(),
        };
        let params = PosParams::default();
        let validator_sets = Epoched::init(validator_set, 0, &params);
        storage.write_validator_set(&validator_sets);

        // write validator keys
        let mut all_keys = HashMap::new();
        for validator in active_validators.into_keys() {
            let keys = setup_storage_validator(storage, &validator);
            all_keys.insert(validator, keys);
        }

        all_keys
    }

    /// Generate a random [`key::ed25519`] keypair.
    pub fn gen_ed25519_keypair() -> key::common::SecretKey {
        let mut rng: ThreadRng = thread_rng();
        key::ed25519::SigScheme::generate(&mut rng)
            .try_to_sk()
            .unwrap()
    }

    /// Set up a single validator in [`TestStorage`] with some
    /// arbitrary keys.
    pub fn setup_storage_validator(
        storage: &mut TestStorage,
        validator: &Address,
    ) -> TestValidatorKeys {
        // register protocol key
        let protocol_key = gen_ed25519_keypair();
        storage
            .write(
                &protocol_pk_key(validator),
                protocol_key.ref_to().try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // register consensus key
        let consensus_key = gen_ed25519_keypair();
        storage.write_validator_consensus_key(
            validator,
            &ValidatorConsensusKeys::init_at_genesis(consensus_key.ref_to(), 0),
        );
        TestValidatorKeys {
            consensus: consensus_key,
            protocol: protocol_key,
        }
    }
}
