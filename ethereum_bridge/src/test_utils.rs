//! Test utilies for the Ethereum bridge crate.

use std::collections::{BTreeSet, HashMap};

use borsh::BorshSerialize;
use namada_core::ledger::storage::testing::TestStorage;
use namada_core::types::address::{self, Address};
use namada_core::types::key::{
    self, protocol_pk_key, RefTo, SecretKey, SigScheme,
};
use namada_core::types::token;
use namada_proof_of_stake::epoched::Epoched;
use namada_proof_of_stake::types::{
    ValidatorConsensusKeys, ValidatorEthKey, ValidatorSet, WeightedValidator,
};
use namada_proof_of_stake::PosBase;
use rand::prelude::ThreadRng;
use rand::thread_rng;

/// Validator keys used for testing purposes.
pub struct TestValidatorKeys {
    /// Consensus keypair.
    pub consensus: key::common::SecretKey,
    /// Protocol keypair.
    pub protocol: key::common::SecretKey,
    /// Ethereum hot keypair.
    pub eth_bridge: key::common::SecretKey,
    /// Ethereum cold keypair.
    pub eth_gov: key::common::SecretKey,
}

/// Set up a [`TestStorage`] initialized at genesis with a single
/// validator.
///
/// The validator's address is [`address::testing::established_address_1`].
#[inline]
pub fn setup_default_storage()
-> (TestStorage, HashMap<Address, TestValidatorKeys>) {
    setup_storage_with_validators(HashMap::from_iter([(
        address::testing::established_address_1(),
        100_u64.into(),
    )]))
}

/// Set up a [`TestStorage`] initialized at genesis with the given
/// validators.
pub fn setup_storage_with_validators(
    active_validators: HashMap<Address, token::Amount>,
) -> (TestStorage, HashMap<Address, TestValidatorKeys>) {
    // set last height to a reasonable value;
    // it should allow vote extensions to be cast
    let mut storage = TestStorage {
        last_height: 3.into(),
        ..TestStorage::default()
    };

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
    let validator_sets = Epoched::init_at_genesis(validator_set, 0);
    storage.write_validator_set(&validator_sets);

    // write validator keys
    let mut all_keys = HashMap::new();
    for validator in active_validators.into_keys() {
        let keys = setup_storage_validator(&mut storage, &validator);
        all_keys.insert(validator, keys);
    }

    (storage, all_keys)
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

    // register ethereum keys
    let hot_key = gen_secp256k1_keypair();
    let cold_key = gen_secp256k1_keypair();
    storage.write_validator_eth_hot_key(
        validator,
        &ValidatorEthKey::init_at_genesis(hot_key.ref_to(), 0),
    );
    storage.write_validator_eth_cold_key(
        validator,
        &ValidatorEthKey::init_at_genesis(cold_key.ref_to(), 0),
    );

    TestValidatorKeys {
        consensus: consensus_key,
        protocol: protocol_key,
        eth_bridge: hot_key,
        eth_gov: cold_key,
    }
}

/// Generate a random [`key::secp256k1`] keypair.
pub fn gen_secp256k1_keypair() -> key::common::SecretKey {
    let mut rng: ThreadRng = thread_rng();
    key::secp256k1::SigScheme::generate(&mut rng)
        .try_to_sk()
        .unwrap()
}

/// Generate a random [`key::ed25519`] keypair.
pub fn gen_ed25519_keypair() -> key::common::SecretKey {
    let mut rng: ThreadRng = thread_rng();
    key::ed25519::SigScheme::generate(&mut rng)
        .try_to_sk()
        .unwrap()
}
