//! Test utilies for the Ethereum bridge crate.

use std::collections::{BTreeSet, HashSet};

use borsh::BorshSerialize;
use namada_core::ledger::storage::mockdb::MockDB;
use namada_core::ledger::storage::testing::TestStorage;
use namada_core::ledger::storage::traits::Sha256Hasher;
use namada_core::ledger::storage::Storage;
use namada_core::types::address::{self, Address};
use namada_core::types::key::{
    self, protocol_pk_key, RefTo, SecretKey, SigScheme,
};
use namada_proof_of_stake::epoched::Epoched;
use namada_proof_of_stake::parameters::PosParams;
use namada_proof_of_stake::types::{
    ValidatorConsensusKeys, ValidatorEthKey, ValidatorSet, WeightedValidator,
};
use namada_proof_of_stake::PosBase;
use rand::prelude::ThreadRng;
use rand::thread_rng;

/// Set up a [`TestStorage`] initialized at genesis with validators of equal
/// power.
pub fn setup_storage_with_validators(
    active_validators: HashSet<Address>,
) -> Storage<MockDB, Sha256Hasher> {
    let mut storage = TestStorage::default();
    let validator_set = ValidatorSet {
        active: active_validators
            .into_iter()
            .map(|address| WeightedValidator {
                bonded_stake: 100_u64,
                address,
            })
            .collect(),
        inactive: BTreeSet::default(),
    };
    let validator_sets = Epoched::init_at_genesis(validator_set, 1);
    storage.write_validator_set(&validator_sets);
    storage
}

/// Set up a [`TestStorage`] initialized at genesis with some default
/// validators.
pub fn setup_default_storage() -> Storage<MockDB, Sha256Hasher> {
    let sole_validator = address::testing::established_address_1();

    let mut storage = setup_storage_with_validators(HashSet::from_iter([
        sole_validator.clone(),
    ]));

    // register protocol key
    storage
        .write(
            &protocol_pk_key(&sole_validator),
            key::testing::keypair_1()
                .ref_to()
                .try_to_vec()
                .expect("Test failed"),
        )
        .expect("Test failed");

    // change pipeline length to 1
    let params = PosParams {
        pipeline_len: 1,
        ..PosParams::default()
    };

    // register consensus key
    let consensus_key = key::testing::keypair_1();
    storage.write_validator_consensus_key(
        &sole_validator,
        &ValidatorConsensusKeys::init(consensus_key.ref_to(), 0, &params),
    );

    // register ethereum keys
    let hot_key = gen_secp256k1_keypair();
    let cold_key = gen_secp256k1_keypair();
    storage.write_validator_eth_hot_key(
        &sole_validator,
        &ValidatorEthKey::init(hot_key.ref_to(), 0, &params),
    );
    storage.write_validator_eth_cold_key(
        &sole_validator,
        &ValidatorEthKey::init(cold_key.ref_to(), 0, &params),
    );

    storage
}

/// Generate a random secp256k1 keypair.
pub fn gen_secp256k1_keypair() -> key::common::SecretKey {
    let mut rng: ThreadRng = thread_rng();
    key::secp256k1::SigScheme::generate(&mut rng)
        .try_to_sk()
        .unwrap()
}
