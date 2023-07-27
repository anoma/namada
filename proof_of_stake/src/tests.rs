//! PoS system tests

mod state_machine;

use std::cmp::min;
use std::collections::{BTreeMap, HashSet};
use std::ops::Range;

use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::collections::lazy_map::{
    self, NestedMap,
};
use namada_core::ledger::storage_api::collections::LazyCollection;
use namada_core::ledger::storage_api::token::{credit_tokens, read_balance};
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::address::testing::{
    address_from_simple_seed, arb_established_address, established_address_1,
    established_address_2, established_address_3,
};
use namada_core::types::address::{Address, EstablishedAddressGen};
use namada_core::types::dec::Dec;
use namada_core::types::key::common::{PublicKey, SecretKey};
use namada_core::types::key::testing::{
    arb_common_keypair, common_sk_from_simple_seed,
};
use namada_core::types::key::RefTo;
use namada_core::types::storage::{BlockHeight, Epoch, Key};
use namada_core::types::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_core::types::uint::{Uint, I256};
use namada_core::types::{address, key, token};
use proptest::prelude::*;
use proptest::test_runner::Config;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use crate::parameters::testing::arb_pos_params;
use crate::parameters::PosParams;
use crate::types::{
    into_tm_voting_power, BondDetails, BondId, BondsAndUnbondsDetails,
    ConsensusValidator, EagerRedelegatedBondsMap, GenesisValidator, Position,
    RedelegatedBonds, Redelegation, ReverseOrdTokenAmount, Slash, SlashType,
    UnbondDetails, ValidatorSetUpdate, ValidatorState, WeightedValidator,
};
use crate::{
    apply_list_slashes, become_validator, below_capacity_validator_set_handle,
    bond_handle, bond_tokens, bonds_and_unbonds, compute_modified_redelegation,
    compute_new_redelegated_unbonds, compute_recent_total_unbonded,
    compute_redelegated_bonds_balance, compute_remainder_redelegation,
    compute_slashable_amount, compute_total_unbonded,
    consensus_validator_set_handle, copy_validator_sets_and_positions,
    delegator_redelegated_bonds_handle, find_bonds_to_remove,
    find_validator_by_raw_hash, fold_and_slash_redelegated_bonds,
    fold_redelegated_bonds_map, get_num_consensus_validators, has_redelegation,
    init_genesis, insert_validator_into_validator_set, is_validator,
    merge_outgoing_redelegations, merge_redelegated_bonds_map, process_slashes,
    purge_validator_sets_for_old_epoch,
    read_below_capacity_validator_set_addresses_with_stake,
    read_below_threshold_validator_set_addresses,
    read_consensus_validator_set_addresses_with_stake, read_total_stake,
    read_validator_deltas_value, read_validator_stake, slash,
    slash_redelegation, slash_validator, slash_validator_redelegation,
    staking_token_address, store_total_consensus_stake, total_bonded_handle,
    total_deltas_handle, unbond_handle, unbond_records_handle, unbond_tokens,
    unjail_validator, update_validator_deltas, update_validator_set,
    validator_consensus_key_handle, validator_deltas_handle,
    validator_outgoing_redelegations_handle, validator_set_update_tendermint,
    validator_slashes_handle, validator_state_handle,
    validator_total_redelegated_bonded_handle,
    validator_total_redelegated_unbonded_handle, withdraw_tokens,
    write_validator_address_raw_hash, BecomeValidator,
    FoldRedelegatedBondsResult, ModifiedRedelegation, STORE_VALIDATOR_SETS_LEN,
};

proptest! {
    // Generate arb valid input for `test_init_genesis_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_init_genesis(

    (pos_params, genesis_validators) in arb_params_and_genesis_validators(Some(5), 1..10),
    start_epoch in (0_u64..1000).prop_map(Epoch),

    ) {
        test_init_genesis_aux(pos_params, start_epoch, genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_bonds_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_bonds(

    (pos_params, genesis_validators) in arb_params_and_genesis_validators(Some(5), 1..3),

    ) {
        test_bonds_aux(pos_params, genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_become_validator_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_become_validator(

    (pos_params, genesis_validators) in arb_params_and_genesis_validators(Some(5), 1..3),
    new_validator in arb_established_address().prop_map(Address::Established),
    new_validator_consensus_key in arb_common_keypair(),

    ) {
        test_become_validator_aux(pos_params, new_validator,
            new_validator_consensus_key, genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_slashes_with_unbonding_aux`
    #![proptest_config(Config {
        cases: 5,
        .. Config::default()
    })]
    #[test]
    fn test_slashes_with_unbonding(
        (params, genesis_validators, unbond_delay)
            in test_slashes_with_unbonding_params()
    ) {
        test_slashes_with_unbonding_aux(
            params, genesis_validators, unbond_delay)
    }
}

fn arb_params_and_genesis_validators(
    num_max_validator_slots: Option<u64>,
    val_size: Range<usize>,
) -> impl Strategy<Value = (PosParams, Vec<GenesisValidator>)> {
    let params = arb_pos_params(num_max_validator_slots);
    params.prop_flat_map(move |params| {
        let validators = arb_genesis_validators(
            val_size.clone(),
            Some(params.validator_stake_threshold),
        );
        (Just(params), validators)
    })
}

fn test_slashes_with_unbonding_params()
-> impl Strategy<Value = (PosParams, Vec<GenesisValidator>, u64)> {
    let params = arb_pos_params(Some(5));
    params.prop_flat_map(|params| {
        let unbond_delay = 0..(params.slash_processing_epoch_offset() * 2);
        // Must have at least 4 validators so we can slash one and the cubic
        // slash rate will be less than 100%
        let validators = arb_genesis_validators(4..10, None);
        (Just(params), validators, unbond_delay)
    })
}

/// Test genesis initialization
fn test_init_genesis_aux(
    params: PosParams,
    start_epoch: Epoch,
    mut validators: Vec<GenesisValidator>,
) {
    println!(
        "Test inputs: {params:?}, {start_epoch}, genesis validators: \
         {validators:#?}"
    );
    let mut s = TestWlStorage::default();
    s.storage.block.epoch = start_epoch;

    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));
    init_genesis(&mut s, &params, validators.clone().into_iter(), start_epoch)
        .unwrap();

    let mut bond_details = bonds_and_unbonds(&s, None, None).unwrap();
    assert!(bond_details.iter().all(|(_id, details)| {
        details.unbonds.is_empty() && details.slashes.is_empty()
    }));

    for (i, validator) in validators.into_iter().enumerate() {
        let addr = &validator.address;
        let self_bonds = bond_details
            .remove(&BondId {
                source: addr.clone(),
                validator: addr.clone(),
            })
            .unwrap();
        assert_eq!(self_bonds.bonds.len(), 1);
        assert_eq!(
            self_bonds.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens,
                slashed_amount: None,
            }
        );

        let state = validator_state_handle(&validator.address)
            .get(&s, start_epoch, &params)
            .unwrap();
        if (i as u64) < params.max_validator_slots
            && validator.tokens >= params.validator_stake_threshold
        {
            // should be in consensus set
            let handle = consensus_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
            assert_eq!(state, Some(ValidatorState::Consensus));
        } else if validator.tokens >= params.validator_stake_threshold {
            // Should be in below-capacity set if its tokens are greater than
            // `validator_stake_threshold`
            let handle = below_capacity_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens.into()).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
            assert_eq!(state, Some(ValidatorState::BelowCapacity));
        } else {
            // Should be in below-threshold
            let bt_addresses =
                read_below_threshold_validator_set_addresses(&s, start_epoch)
                    .unwrap();
            assert!(
                bt_addresses
                    .into_iter()
                    .any(|addr| { addr == validator.address })
            );
            assert_eq!(state, Some(ValidatorState::BelowThreshold));
        }
    }
}

/// Test bonding
/// NOTE: copy validator sets each time we advance the epoch
fn test_bonds_aux(params: PosParams, validators: Vec<GenesisValidator>) {
    // This can be useful for debugging:
    // params.pipeline_len = 2;
    // params.unbonding_len = 4;
    println!("\nTest inputs: {params:?}, genesis validators: {validators:#?}");
    let mut s = TestWlStorage::default();

    // Genesis
    let start_epoch = s.storage.block.epoch;
    let mut current_epoch = s.storage.block.epoch;
    init_genesis(
        &mut s,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    s.commit_block().unwrap();

    // Advance to epoch 1
    current_epoch = advance_epoch(&mut s, &params);
    let self_bond_epoch = current_epoch;

    let validator = validators.first().unwrap();

    // Read some data before submitting bond
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let staking_token = staking_token_address(&s);
    let pos_balance_pre = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token,
            &super::ADDRESS,
        ))
        .unwrap()
        .unwrap_or_default();
    let total_stake_before =
        read_total_stake(&s, &params, pipeline_epoch).unwrap();

    // Self-bond
    let amount_self_bond = token::Amount::from_uint(100_500_000, 0).unwrap();
    credit_tokens(&mut s, &staking_token, &validator.address, amount_self_bond)
        .unwrap();
    bond_tokens(
        &mut s,
        None,
        &validator.address,
        amount_self_bond,
        current_epoch,
    )
    .unwrap();

    // Check the bond delta
    let self_bond = bond_handle(&validator.address, &validator.address);
    let delta = self_bond.get_delta_val(&s, pipeline_epoch).unwrap();
    assert_eq!(delta, Some(amount_self_bond.change()));

    // Check the validator in the validator set
    let set =
        read_consensus_validator_set_addresses_with_stake(&s, pipeline_epoch)
            .unwrap();
    assert!(set.into_iter().any(
        |WeightedValidator {
             bonded_stake,
             address,
         }| {
            address == validator.address
                && bonded_stake == validator.tokens + amount_self_bond
        }
    ));

    let val_deltas =
        read_validator_deltas_value(&s, &validator.address, &pipeline_epoch)
            .unwrap();
    assert_eq!(val_deltas, Some(amount_self_bond.change()));

    let total_deltas_handle = total_deltas_handle();
    assert_eq!(
        current_epoch,
        total_deltas_handle.get_last_update(&s).unwrap().unwrap()
    );
    let total_stake_after =
        read_total_stake(&s, &params, pipeline_epoch).unwrap();
    assert_eq!(total_stake_before + amount_self_bond, total_stake_after);

    // Check bond details after self-bond
    let self_bond_id = BondId {
        source: validator.address.clone(),
        validator: validator.address.clone(),
    };
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        let details = bond_details.get(&self_bond_id).unwrap();
        assert_eq!(
            details.bonds.len(),
            2,
            "Contains genesis and newly added self-bond"
        );
        dbg!(&details.bonds);
        assert_eq!(
            details.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens,
                slashed_amount: None
            },
        );
        assert_eq!(
            details.bonds[1],
            BondDetails {
                start: pipeline_epoch,
                amount: amount_self_bond,
                slashed_amount: None
            },
        );
    };
    // Try to call it with different combinations of owner/validator args
    check_bond_details(0, bonds_and_unbonds(&s, None, None).unwrap());
    check_bond_details(
        1,
        bonds_and_unbonds(&s, Some(validator.address.clone()), None).unwrap(),
    );
    check_bond_details(
        2,
        bonds_and_unbonds(&s, None, Some(validator.address.clone())).unwrap(),
    );
    check_bond_details(
        3,
        bonds_and_unbonds(
            &s,
            Some(validator.address.clone()),
            Some(validator.address.clone()),
        )
        .unwrap(),
    );

    // Get a non-validating account with tokens
    let delegator = address::testing::gen_implicit_address();
    let amount_del = token::Amount::from_uint(201_000_000, 0).unwrap();
    credit_tokens(&mut s, &staking_token, &delegator, amount_del).unwrap();
    let balance_key = token::balance_key(&staking_token, &delegator);
    let balance = s
        .read::<token::Amount>(&balance_key)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(balance, amount_del);

    // Advance to epoch 3
    advance_epoch(&mut s, &params);
    current_epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Delegation
    let delegation_epoch = current_epoch;
    bond_tokens(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount_del,
        current_epoch,
    )
    .unwrap();
    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        pipeline_epoch.prev(),
    )
    .unwrap()
    .unwrap_or_default();
    let val_stake_post =
        read_validator_stake(&s, &params, &validator.address, pipeline_epoch)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(validator.tokens + amount_self_bond, val_stake_pre);
    assert_eq!(
        validator.tokens + amount_self_bond + amount_del,
        val_stake_post
    );
    let delegation = bond_handle(&delegator, &validator.address);
    assert_eq!(
        delegation
            .get_sum(&s, pipeline_epoch.prev(), &params)
            .unwrap()
            .unwrap_or_default(),
        token::Change::default()
    );
    assert_eq!(
        delegation
            .get_sum(&s, pipeline_epoch, &params)
            .unwrap()
            .unwrap_or_default(),
        amount_del.change()
    );

    // Check delegation bonds details after delegation
    let delegation_bond_id = BondId {
        source: delegator.clone(),
        validator: validator.address.clone(),
    };
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        assert_eq!(bond_details.len(), 1);
        let details = bond_details.get(&delegation_bond_id).unwrap();
        assert_eq!(details.bonds.len(), 1,);
        dbg!(&details.bonds);
        assert_eq!(
            details.bonds[0],
            BondDetails {
                start: pipeline_epoch,
                amount: amount_del,
                slashed_amount: None
            },
        );
    };
    // Try to call it with different combinations of owner/validator args
    check_bond_details(
        0,
        bonds_and_unbonds(&s, Some(delegator.clone()), None).unwrap(),
    );
    check_bond_details(
        1,
        bonds_and_unbonds(
            &s,
            Some(delegator.clone()),
            Some(validator.address.clone()),
        )
        .unwrap(),
    );

    // Check all bond details (self-bonds and delegation)
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        let self_bond_details = bond_details.get(&self_bond_id).unwrap();
        let delegation_details = bond_details.get(&delegation_bond_id).unwrap();
        assert_eq!(
            self_bond_details.bonds.len(),
            2,
            "Contains genesis and newly added self-bond"
        );
        assert_eq!(
            self_bond_details.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens,
                slashed_amount: None
            },
        );
        assert_eq!(self_bond_details.bonds[1].amount, amount_self_bond);
        assert_eq!(
            delegation_details.bonds[0],
            BondDetails {
                start: pipeline_epoch,
                amount: amount_del,
                slashed_amount: None
            },
        );
    };
    // Try to call it with different combinations of owner/validator args
    check_bond_details(0, bonds_and_unbonds(&s, None, None).unwrap());
    check_bond_details(
        1,
        bonds_and_unbonds(&s, None, Some(validator.address.clone())).unwrap(),
    );

    // Advance to epoch 5
    for _ in 0..2 {
        current_epoch = advance_epoch(&mut s, &params);
    }
    let pipeline_epoch = current_epoch + params.pipeline_len;

    // Unbond the self-bond with an amount that will remove all of the self-bond
    // executed after genesis and some of the genesis bond
    let amount_self_unbond: token::Amount =
        amount_self_bond + (validator.tokens / 2);
    // When the difference is 0, only the non-genesis self-bond is unbonded
    let unbonded_genesis_self_bond =
        amount_self_unbond - amount_self_bond != token::Amount::default();
    dbg!(
        amount_self_unbond,
        amount_self_bond,
        unbonded_genesis_self_bond
    );
    let self_unbond_epoch = s.storage.block.epoch;

    unbond_tokens(
        &mut s,
        None,
        &validator.address,
        amount_self_unbond,
        current_epoch,
        false,
    )
    .unwrap();

    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        pipeline_epoch.prev(),
    )
    .unwrap();

    let val_stake_post =
        read_validator_stake(&s, &params, &validator.address, pipeline_epoch)
            .unwrap();

    let val_delta =
        read_validator_deltas_value(&s, &validator.address, &pipeline_epoch)
            .unwrap();
    let unbond = unbond_handle(&validator.address, &validator.address);

    assert_eq!(val_delta, Some(-amount_self_unbond.change()));
    assert_eq!(
        unbond
            .at(&(pipeline_epoch
                + params.unbonding_len
                + params.cubic_slashing_window_length))
            .get(&s, &Epoch::default())
            .unwrap(),
        if unbonded_genesis_self_bond {
            Some(amount_self_unbond - amount_self_bond)
        } else {
            None
        }
    );
    assert_eq!(
        unbond
            .at(&(pipeline_epoch
                + params.unbonding_len
                + params.cubic_slashing_window_length))
            .get(&s, &(self_bond_epoch + params.pipeline_len))
            .unwrap(),
        Some(amount_self_bond)
    );
    assert_eq!(
        val_stake_pre,
        Some(validator.tokens + amount_self_bond + amount_del)
    );
    assert_eq!(
        val_stake_post,
        Some(
            validator.tokens + amount_self_bond + amount_del
                - amount_self_unbond
        )
    );

    // Check all bond and unbond details (self-bonds and delegation)
    let check_bond_details = |ix, bond_details: BondsAndUnbondsDetails| {
        println!("Check index {ix}");
        dbg!(&bond_details);
        assert_eq!(bond_details.len(), 2);
        let self_bond_details = bond_details.get(&self_bond_id).unwrap();
        let delegation_details = bond_details.get(&delegation_bond_id).unwrap();
        assert_eq!(
            self_bond_details.bonds.len(),
            1,
            "Contains only part of the genesis bond now"
        );
        assert_eq!(
            self_bond_details.bonds[0],
            BondDetails {
                start: start_epoch,
                amount: validator.tokens + amount_self_bond
                    - amount_self_unbond,
                slashed_amount: None
            },
        );
        assert_eq!(
            delegation_details.bonds[0],
            BondDetails {
                start: delegation_epoch + params.pipeline_len,
                amount: amount_del,
                slashed_amount: None
            },
        );
        assert_eq!(
            self_bond_details.unbonds.len(),
            if unbonded_genesis_self_bond { 2 } else { 1 },
            "Contains a full unbond of the last self-bond and an unbond from \
             the genesis bond"
        );
        if unbonded_genesis_self_bond {
            assert_eq!(
                self_bond_details.unbonds[0],
                UnbondDetails {
                    start: start_epoch,
                    withdraw: self_unbond_epoch
                        + params.pipeline_len
                        + params.unbonding_len
                        + params.cubic_slashing_window_length,
                    amount: amount_self_unbond - amount_self_bond,
                    slashed_amount: None
                }
            );
        }
        assert_eq!(
            self_bond_details.unbonds[usize::from(unbonded_genesis_self_bond)],
            UnbondDetails {
                start: self_bond_epoch + params.pipeline_len,
                withdraw: self_unbond_epoch
                    + params.pipeline_len
                    + params.unbonding_len
                    + params.cubic_slashing_window_length,
                amount: amount_self_bond,
                slashed_amount: None
            }
        );
    };
    check_bond_details(
        0,
        bonds_and_unbonds(&s, None, Some(validator.address.clone())).unwrap(),
    );

    // Unbond delegation
    let amount_undel = token::Amount::from_uint(1_000_000, 0).unwrap();
    unbond_tokens(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount_undel,
        current_epoch,
        false,
    )
    .unwrap();

    let val_stake_pre = read_validator_stake(
        &s,
        &params,
        &validator.address,
        pipeline_epoch.prev(),
    )
    .unwrap();
    let val_stake_post =
        read_validator_stake(&s, &params, &validator.address, pipeline_epoch)
            .unwrap();
    let val_delta =
        read_validator_deltas_value(&s, &validator.address, &pipeline_epoch)
            .unwrap();
    let unbond = unbond_handle(&delegator, &validator.address);

    assert_eq!(
        val_delta,
        Some(-(amount_self_unbond + amount_undel).change())
    );
    assert_eq!(
        unbond
            .at(&(pipeline_epoch
                + params.unbonding_len
                + params.cubic_slashing_window_length))
            .get(&s, &(delegation_epoch + params.pipeline_len))
            .unwrap(),
        Some(amount_undel)
    );
    assert_eq!(
        val_stake_pre,
        Some(validator.tokens + amount_self_bond + amount_del)
    );
    assert_eq!(
        val_stake_post,
        Some(
            validator.tokens + amount_self_bond - amount_self_unbond
                + amount_del
                - amount_undel
        )
    );

    let withdrawable_offset = params.unbonding_len
        + params.pipeline_len
        + params.cubic_slashing_window_length;

    // Advance to withdrawable epoch
    for _ in 0..withdrawable_offset {
        current_epoch = advance_epoch(&mut s, &params);
    }

    dbg!(current_epoch);

    let pos_balance = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token,
            &super::ADDRESS,
        ))
        .unwrap();

    assert_eq!(
        Some(pos_balance_pre + amount_self_bond + amount_del),
        pos_balance
    );

    // Withdraw the self-unbond
    withdraw_tokens(&mut s, None, &validator.address, current_epoch).unwrap();
    let unbond = unbond_handle(&validator.address, &validator.address);
    let unbond_iter = unbond.iter(&s).unwrap().next();
    assert!(unbond_iter.is_none());

    let pos_balance = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token,
            &super::ADDRESS,
        ))
        .unwrap();
    assert_eq!(
        Some(
            pos_balance_pre + amount_self_bond - amount_self_unbond
                + amount_del
        ),
        pos_balance
    );

    // Withdraw the delegation unbond
    withdraw_tokens(
        &mut s,
        Some(&delegator),
        &validator.address,
        current_epoch,
    )
    .unwrap();
    let unbond = unbond_handle(&delegator, &validator.address);
    let unbond_iter = unbond.iter(&s).unwrap().next();
    assert!(unbond_iter.is_none());

    let pos_balance = s
        .read::<token::Amount>(&token::balance_key(
            &staking_token,
            &super::ADDRESS,
        ))
        .unwrap();
    assert_eq!(
        Some(
            pos_balance_pre + amount_self_bond - amount_self_unbond
                + amount_del
                - amount_undel
        ),
        pos_balance
    );
}

/// Test validator initialization.
fn test_become_validator_aux(
    params: PosParams,
    new_validator: Address,
    new_validator_consensus_key: SecretKey,
    validators: Vec<GenesisValidator>,
) {
    println!(
        "Test inputs: {params:?}, new validator: {new_validator}, genesis \
         validators: {validators:#?}"
    );

    let mut s = TestWlStorage::default();

    // Genesis
    let mut current_epoch = dbg!(s.storage.block.epoch);
    init_genesis(
        &mut s,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    s.commit_block().unwrap();

    // Advance to epoch 1
    current_epoch = advance_epoch(&mut s, &params);

    let num_consensus_before =
        get_num_consensus_validators(&s, current_epoch + params.pipeline_len)
            .unwrap();
    let num_validators_over_thresh = validators
        .iter()
        .filter(|validator| {
            validator.tokens >= params.validator_stake_threshold
        })
        .count();

    assert_eq!(
        min(
            num_validators_over_thresh as u64,
            params.max_validator_slots
        ),
        num_consensus_before
    );
    assert!(!is_validator(&s, &new_validator).unwrap());

    // Initialize the validator account
    let consensus_key = new_validator_consensus_key.to_public();
    let eth_hot_key = key::common::PublicKey::Secp256k1(
        key::testing::gen_keypair::<key::secp256k1::SigScheme>().ref_to(),
    );
    let eth_cold_key = key::common::PublicKey::Secp256k1(
        key::testing::gen_keypair::<key::secp256k1::SigScheme>().ref_to(),
    );
    become_validator(BecomeValidator {
        storage: &mut s,
        params: &params,
        address: &new_validator,
        consensus_key: &consensus_key,
        eth_cold_key: &eth_cold_key,
        eth_hot_key: &eth_hot_key,
        current_epoch,
        commission_rate: Dec::new(5, 2).expect("Dec creation failed"),
        max_commission_rate_change: Dec::new(5, 2)
            .expect("Dec creation failed"),
    })
    .unwrap();
    assert!(is_validator(&s, &new_validator).unwrap());

    let num_consensus_after =
        get_num_consensus_validators(&s, current_epoch + params.pipeline_len)
            .unwrap();
    // The new validator is initialized with no stake and thus is in the
    // below-threshold set
    assert_eq!(num_consensus_before, num_consensus_after);

    // Advance to epoch 2
    current_epoch = advance_epoch(&mut s, &params);

    // Self-bond to the new validator
    let staking_token = staking_token_address(&s);
    let amount = token::Amount::from_uint(100_500_000, 0).unwrap();
    credit_tokens(&mut s, &staking_token, &new_validator, amount).unwrap();
    bond_tokens(&mut s, None, &new_validator, amount, current_epoch).unwrap();

    // Check the bond delta
    let bond_handle = bond_handle(&new_validator, &new_validator);
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let delta = bond_handle.get_delta_val(&s, pipeline_epoch).unwrap();
    assert_eq!(delta, Some(amount.change()));

    // Check the validator in the validator set -
    // If the consensus validator slots are full and all the genesis validators
    // have stake GTE the new validator's self-bond amount, the validator should
    // be added to the below-capacity set, or the consensus otherwise
    if params.max_validator_slots <= validators.len() as u64
        && validators
            .iter()
            .all(|validator| validator.tokens >= amount)
    {
        let set = read_below_capacity_validator_set_addresses_with_stake(
            &s,
            pipeline_epoch,
        )
        .unwrap();
        assert!(set.into_iter().any(
            |WeightedValidator {
                 bonded_stake,
                 address,
             }| {
                address == new_validator && bonded_stake == amount
            }
        ));
    } else {
        let set = read_consensus_validator_set_addresses_with_stake(
            &s,
            pipeline_epoch,
        )
        .unwrap();
        assert!(set.into_iter().any(
            |WeightedValidator {
                 bonded_stake,
                 address,
             }| {
                address == new_validator && bonded_stake == amount
            }
        ));
    }

    // Advance to epoch 3
    current_epoch = advance_epoch(&mut s, &params);

    // Unbond the self-bond
    unbond_tokens(&mut s, None, &new_validator, amount, current_epoch, false)
        .unwrap();

    let withdrawable_offset = params.unbonding_len + params.pipeline_len;

    // Advance to withdrawable epoch
    for _ in 0..withdrawable_offset {
        current_epoch = advance_epoch(&mut s, &params);
    }

    // Withdraw the self-bond
    withdraw_tokens(&mut s, None, &new_validator, current_epoch).unwrap();
}

fn test_slashes_with_unbonding_aux(
    mut params: PosParams,
    validators: Vec<GenesisValidator>,
    unbond_delay: u64,
) {
    // This can be useful for debugging:
    params.pipeline_len = 2;
    params.unbonding_len = 4;
    println!("\nTest inputs: {params:?}, genesis validators: {validators:#?}");
    let mut s = TestWlStorage::default();

    // Find the validator with the least stake to avoid the cubic slash rate
    // going to 100%
    let validator =
        itertools::Itertools::sorted_by_key(validators.iter(), |v| v.tokens)
            .next()
            .unwrap();
    let val_addr = &validator.address;
    let val_tokens = validator.tokens;
    println!(
        "Validator that will misbehave addr {val_addr}, tokens {}",
        val_tokens.to_string_native()
    );

    // Genesis
    // let start_epoch = s.storage.block.epoch;
    let mut current_epoch = s.storage.block.epoch;
    init_genesis(
        &mut s,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    s.commit_block().unwrap();

    current_epoch = advance_epoch(&mut s, &params);
    super::process_slashes(&mut s, current_epoch).unwrap();

    // Discover first slash
    let slash_0_evidence_epoch = current_epoch;
    // let slash_0_processing_epoch =
    //     slash_0_evidence_epoch + params.slash_processing_epoch_offset();
    let evidence_block_height = BlockHeight(0); // doesn't matter for slashing logic
    let slash_0_type = SlashType::DuplicateVote;
    slash(
        &mut s,
        &params,
        current_epoch,
        slash_0_evidence_epoch,
        evidence_block_height,
        slash_0_type,
        val_addr,
        current_epoch.next(),
    )
    .unwrap();

    // Advance to an epoch in which we can unbond
    let unfreeze_epoch =
        slash_0_evidence_epoch + params.slash_processing_epoch_offset();
    while current_epoch < unfreeze_epoch {
        current_epoch = advance_epoch(&mut s, &params);
        super::process_slashes(&mut s, current_epoch).unwrap();
    }

    // Advance more epochs randomly from the generated delay
    for _ in 0..unbond_delay {
        current_epoch = advance_epoch(&mut s, &params);
    }

    // Unbond half of the tokens
    let unbond_amount = Dec::new(5, 1).unwrap() * val_tokens;
    println!("Going to unbond {}", unbond_amount.to_string_native());
    let unbond_epoch = current_epoch;
    unbond_tokens(&mut s, None, val_addr, unbond_amount, unbond_epoch, false)
        .unwrap();

    // Discover second slash
    let slash_1_evidence_epoch = current_epoch;
    // Ensure that both slashes happen before `unbond_epoch + pipeline`
    let _slash_1_processing_epoch =
        slash_1_evidence_epoch + params.slash_processing_epoch_offset();
    let evidence_block_height = BlockHeight(0); // doesn't matter for slashing logic
    let slash_1_type = SlashType::DuplicateVote;
    slash(
        &mut s,
        &params,
        current_epoch,
        slash_1_evidence_epoch,
        evidence_block_height,
        slash_1_type,
        val_addr,
        current_epoch.next(),
    )
    .unwrap();

    // Advance to an epoch in which we can withdraw
    let withdraw_epoch = unbond_epoch + params.withdrawable_epoch_offset();
    while current_epoch < withdraw_epoch {
        current_epoch = advance_epoch(&mut s, &params);
        super::process_slashes(&mut s, current_epoch).unwrap();
    }
    let token = staking_token_address(&s);
    let val_balance_pre = read_balance(&s, &token, val_addr).unwrap();

    let bond_id = BondId {
        source: val_addr.clone(),
        validator: val_addr.clone(),
    };
    let binding =
        super::bonds_and_unbonds(&s, None, Some(val_addr.clone())).unwrap();
    let details = binding.get(&bond_id).unwrap();
    let exp_withdraw_from_details = details.unbonds[0].amount
        - details.unbonds[0].slashed_amount.unwrap_or_default();

    withdraw_tokens(&mut s, None, val_addr, current_epoch).unwrap();

    let val_balance_post = read_balance(&s, &token, val_addr).unwrap();
    let withdrawn_tokens = val_balance_post - val_balance_pre;
    println!("Withdrew {} tokens", withdrawn_tokens.to_string_native());

    assert_eq!(exp_withdraw_from_details, withdrawn_tokens);

    let slash_rate_0 = validator_slashes_handle(val_addr)
        .get(&s, 0)
        .unwrap()
        .unwrap()
        .rate;
    let slash_rate_1 = validator_slashes_handle(val_addr)
        .get(&s, 1)
        .unwrap()
        .unwrap()
        .rate;
    println!("Slash 0 rate {slash_rate_0}, slash 1 rate {slash_rate_1}");

    let expected_withdrawn_amount = Dec::from(
        (Dec::one() - slash_rate_1)
            * (Dec::one() - slash_rate_0)
            * unbond_amount,
    );
    // Allow some rounding error, 1 NAMNAM per each slash
    let rounding_error_tolerance =
        Dec::new(2, NATIVE_MAX_DECIMAL_PLACES).unwrap();
    assert!(
        dbg!(expected_withdrawn_amount.abs_diff(&Dec::from(withdrawn_tokens)))
            <= rounding_error_tolerance
    );

    // TODO: finish once implemented
    // let slash_0 = decimal_mult_amount(slash_rate_0, val_tokens);
    // let slash_1 = decimal_mult_amount(slash_rate_1, val_tokens - slash_0);
    // let expected_slash_pool = slash_0 + slash_1;
    // let slash_pool_balance =
    //     read_balance(&s, &token, &SLASH_POOL_ADDRESS).unwrap();
    // assert_eq!(expected_slash_pool, slash_pool_balance);
}

#[test]
fn test_validator_raw_hash() {
    let mut storage = TestWlStorage::default();
    let address = address::testing::established_address_1();
    let consensus_sk = key::testing::keypair_1();
    let consensus_pk = consensus_sk.to_public();
    let expected_raw_hash = key::tm_consensus_key_raw_hash(&consensus_pk);

    assert!(
        find_validator_by_raw_hash(&storage, &expected_raw_hash)
            .unwrap()
            .is_none()
    );
    write_validator_address_raw_hash(&mut storage, &address, &consensus_pk)
        .unwrap();
    let found =
        find_validator_by_raw_hash(&storage, &expected_raw_hash).unwrap();
    assert_eq!(found, Some(address));
}

#[test]
fn test_validator_sets() {
    let mut s = TestWlStorage::default();
    // Only 3 consensus validator slots
    let params = PosParams {
        max_validator_slots: 3,
        ..Default::default()
    };
    let addr_seed = "seed";
    let mut address_gen = EstablishedAddressGen::new(addr_seed);
    let mut sk_seed = 0;
    let mut gen_validator = || {
        let res = (
            address_gen.generate_address(addr_seed),
            key::testing::common_sk_from_simple_seed(sk_seed).to_public(),
        );
        // bump the sk seed
        sk_seed += 1;
        res
    };

    // A helper to insert a non-genesis validator
    let insert_validator = |s: &mut TestWlStorage,
                            addr,
                            pk: &PublicKey,
                            stake: token::Amount,
                            epoch: Epoch| {
        insert_validator_into_validator_set(
            s,
            &params,
            addr,
            stake,
            epoch,
            params.pipeline_len,
        )
        .unwrap();

        update_validator_deltas(
            s,
            addr,
            stake.change(),
            epoch,
            params.pipeline_len,
        )
        .unwrap();

        // Set their consensus key (needed for
        // `validator_set_update_tendermint` fn)
        validator_consensus_key_handle(addr)
            .set(s, pk.clone(), epoch, params.pipeline_len)
            .unwrap();
    };

    // Create genesis validators
    let ((val1, pk1), stake1) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val2, pk2), stake2) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val3, pk3), stake3) =
        (gen_validator(), token::Amount::native_whole(10));
    let ((val4, pk4), stake4) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val5, pk5), stake5) =
        (gen_validator(), token::Amount::native_whole(100));
    let ((val6, pk6), stake6) =
        (gen_validator(), token::Amount::native_whole(1));
    let ((val7, pk7), stake7) =
        (gen_validator(), token::Amount::native_whole(1));
    println!("\nval1: {val1}, {pk1}, {}", stake1.to_string_native());
    println!("val2: {val2}, {pk2}, {}", stake2.to_string_native());
    println!("val3: {val3}, {pk3}, {}", stake3.to_string_native());
    println!("val4: {val4}, {pk4}, {}", stake4.to_string_native());
    println!("val5: {val5}, {pk5}, {}", stake5.to_string_native());
    println!("val6: {val6}, {pk6}, {}", stake6.to_string_native());
    println!("val7: {val7}, {pk7}, {}", stake7.to_string_native());

    let start_epoch = Epoch::default();
    let epoch = start_epoch;

    init_genesis(
        &mut s,
        &params,
        [
            GenesisValidator {
                address: val1.clone(),
                tokens: stake1,
                consensus_key: pk1.clone(),
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
            },
            GenesisValidator {
                address: val2.clone(),
                tokens: stake2,
                consensus_key: pk2.clone(),
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
            },
        ]
        .into_iter(),
        epoch,
    )
    .unwrap();

    // Advance to EPOCH 1
    //
    // We cannot call `get_tendermint_set_updates` for the genesis state as
    // `validator_set_update_tendermint` is only called 2 blocks before the
    // start of an epoch and so we need to give it a predecessor epoch (see
    // `get_tendermint_set_updates`), which we cannot have on the first
    // epoch. In any way, the initial validator set is given to Tendermint
    // from InitChain, so `validator_set_update_tendermint` is
    // not being used for it.
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Insert another validator with the greater stake 10 NAM
    insert_validator(&mut s, &val3, &pk3, stake3, epoch);
    // Insert validator with stake 1 NAM
    insert_validator(&mut s, &val4, &pk4, stake4, epoch);

    // Validator `val3` and `val4` will be added at pipeline offset (2) - epoch
    // 3
    let val3_and_4_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val1 && stake == &stake1 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));

    // Check tendermint validator set updates - there should be none
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Advance to EPOCH 2
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Insert another validator with a greater stake still 1000 NAM. It should
    // replace 2nd consensus validator with stake 1, which should become
    // below-capacity
    insert_validator(&mut s, &val5, &pk5, stake5, epoch);
    // Validator `val5` will be added at pipeline offset (2) - epoch 4
    let val5_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val1 && stake == &stake1 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 2);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));

    // Advance to EPOCH 3
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(
        val3_and_4_epoch, epoch,
        "val3 and val4 are in the validator sets now"
    );
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    // `val4` is newly added below-capacity, must be skipped in updated in TM
    assert_eq!(tm_updates.len(), 1);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk3,
            bonded_stake: stake3,
        })
    );

    // Insert another validator with a stake 1 NAM. It should be added to the
    // below-capacity set
    insert_validator(&mut s, &val6, &pk6, stake6, epoch);
    // Validator `val6` will be added at pipeline offset (2) - epoch 5
    let val6_epoch = pipeline_epoch;

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 3);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(2)
    ));

    // Advance to EPOCH 4
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(val5_epoch, epoch, "val5 is in the validator sets now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert_eq!(tm_updates.len(), 2);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk5,
            bonded_stake: stake5,
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk2));

    // Unbond some stake from val1, it should be be swapped with the greatest
    // below-capacity validator val2 into the below-capacity set. The stake of
    // val1 will go below 1 NAM, which is the validator_stake_threshold, so it
    // will enter the below-threshold validator set.
    let unbond = token::Amount::from_uint(500_000, 0).unwrap();
    let stake1 = stake1 - unbond;
    println!("val1 {val1} new stake {}", stake1.to_string_native());
    // Because `update_validator_set` and `update_validator_deltas` are
    // effective from pipeline offset, we use pipeline epoch for the rest of the
    // checks
    update_validator_set(&mut s, &params, &val1, -unbond.change(), epoch)
        .unwrap();
    update_validator_deltas(
        &mut s,
        &val1,
        -unbond.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();
    // Epoch 6
    let val1_unbond_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 2);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(2)
    ));

    let below_threshold_vals =
        read_below_threshold_validator_set_addresses(&s, pipeline_epoch)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();

    assert_eq!(below_threshold_vals.len(), 1);
    assert_eq!(&below_threshold_vals[0], &val1);

    // Advance to EPOCH 5
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(val6_epoch, epoch, "val6 is in the validator sets now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Insert another validator with stake 1 - it should be added to below
    // capacity set
    insert_validator(&mut s, &val7, &pk7, stake7, epoch);
    // Epoch 7
    let val7_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val4 && stake == &stake4 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 3);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(2)
    ));
    assert!(matches!(
        &below_capacity_vals[2],
        (
            lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
            },
            address
        )
        if address == &val7 && stake == &stake7 && *position == Position(3)
    ));

    let below_threshold_vals =
        read_below_threshold_validator_set_addresses(&s, pipeline_epoch)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();

    assert_eq!(below_threshold_vals.len(), 1);
    assert_eq!(&below_threshold_vals[0], &val1);

    // Advance to EPOCH 6
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(val1_unbond_epoch, epoch, "val1's unbond is applied now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert_eq!(tm_updates.len(), 2);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk4.clone(),
            bonded_stake: stake4,
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk1));

    // Bond some stake to val6, it should be be swapped with the lowest
    // consensus validator val2 into the consensus set
    let bond = token::Amount::from_uint(500_000, 0).unwrap();
    let stake6 = stake6 + bond;
    println!("val6 {val6} new stake {}", stake6.to_string_native());
    update_validator_set(&mut s, &params, &val6, bond.change(), epoch).unwrap();
    update_validator_deltas(
        &mut s,
        &val6,
        bond.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();
    let val6_bond_epoch = pipeline_epoch;

    let consensus_vals: Vec<_> = consensus_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(consensus_vals.len(), 3);
    assert!(matches!(
        &consensus_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val6 && stake == &stake6 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val3 && stake == &stake3 && *position == Position(0)
    ));
    assert!(matches!(
        &consensus_vals[2],
        (lazy_map::NestedSubKey::Data {
                key: stake,
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val5 && stake == &stake5 && *position == Position(0)
    ));

    let below_capacity_vals: Vec<_> = below_capacity_validator_set_handle()
        .at(&pipeline_epoch)
        .iter(&s)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(below_capacity_vals.len(), 3);
    dbg!(&below_capacity_vals);
    assert!(matches!(
        &below_capacity_vals[0],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val2 && stake == &stake2 && *position == Position(1)
    ));
    assert!(matches!(
        &below_capacity_vals[1],
        (lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
        }, address)
        if address == &val7 && stake == &stake7 && *position == Position(3)
    ));
    assert!(matches!(
        &below_capacity_vals[2],
        (
            lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
            },
            address
        )
        if address == &val4 && stake == &stake4 && *position == Position(4)
    ));

    let below_threshold_vals =
        read_below_threshold_validator_set_addresses(&s, pipeline_epoch)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();

    assert_eq!(below_threshold_vals.len(), 1);
    assert_eq!(&below_threshold_vals[0], &val1);

    // Advance to EPOCH 7
    let epoch = advance_epoch(&mut s, &params);
    assert_eq!(val7_epoch, epoch, "val6 is in the validator sets now");

    // Check tendermint validator set updates
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Advance to EPOCH 8
    let epoch = advance_epoch(&mut s, &params);

    // Check tendermint validator set updates
    assert_eq!(val6_bond_epoch, epoch, "val5's bond is applied now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    dbg!(&tm_updates);
    assert_eq!(tm_updates.len(), 2);
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk6,
            bonded_stake: stake6,
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk4));

    // Check that the validator sets were purged for the old epochs
    let last_epoch = epoch;
    for e in Epoch::iter_bounds_inclusive(
        start_epoch,
        last_epoch
            .sub_or_default(Epoch(STORE_VALIDATOR_SETS_LEN))
            .sub_or_default(Epoch(1)),
    ) {
        assert!(
            consensus_validator_set_handle()
                .at(&e)
                .is_empty(&s)
                .unwrap()
        );
        assert!(
            below_capacity_validator_set_handle()
                .at(&e)
                .is_empty(&s)
                .unwrap()
        );
    }
}

/// When a consensus set validator with 0 voting power adds a bond in the same
/// epoch as another below-capacity set validator with 0 power, but who adds
/// more bonds than the validator who is in the consensus set, they get swapped
/// in the sets. But if both of their new voting powers are still 0 after
/// bonding, the newly below-capacity validator must not be given to tendermint
/// with 0 voting power, because it wasn't it its set before
#[test]
fn test_validator_sets_swap() {
    let mut s = TestWlStorage::default();
    // Only 2 consensus validator slots
    let params = PosParams {
        max_validator_slots: 2,
        // Set the stake threshold to 0 so no validators are in the
        // below-threshold set
        validator_stake_threshold: token::Amount::default(),
        // Set 0.1 votes per token
        tm_votes_per_token: Dec::new(1, 1).expect("Dec creation failed"),
        ..Default::default()
    };
    let addr_seed = "seed";
    let mut address_gen = EstablishedAddressGen::new(addr_seed);
    let mut sk_seed = 0;
    let mut gen_validator = || {
        let res = (
            address_gen.generate_address(addr_seed),
            key::testing::common_sk_from_simple_seed(sk_seed).to_public(),
        );
        // bump the sk seed
        sk_seed += 1;
        res
    };

    // A helper to insert a non-genesis validator
    let insert_validator = |s: &mut TestWlStorage,
                            addr,
                            pk: &PublicKey,
                            stake: token::Amount,
                            epoch: Epoch| {
        insert_validator_into_validator_set(
            s,
            &params,
            addr,
            stake,
            epoch,
            params.pipeline_len,
        )
        .unwrap();

        update_validator_deltas(
            s,
            addr,
            stake.change(),
            epoch,
            params.pipeline_len,
        )
        .unwrap();

        // Set their consensus key (needed for
        // `validator_set_update_tendermint` fn)
        validator_consensus_key_handle(addr)
            .set(s, pk.clone(), epoch, params.pipeline_len)
            .unwrap();
    };

    // Start with two genesis validators, one with 1 voting power and other 0
    let epoch = Epoch::default();
    // 1M voting power
    let ((val1, pk1), stake1) =
        (gen_validator(), token::Amount::native_whole(10));
    // 0 voting power
    let ((val2, pk2), stake2) =
        (gen_validator(), token::Amount::from_uint(5, 0).unwrap());
    // 0 voting power
    let ((val3, pk3), stake3) =
        (gen_validator(), token::Amount::from_uint(5, 0).unwrap());
    println!("val1: {val1}, {pk1}, {}", stake1.to_string_native());
    println!("val2: {val2}, {pk2}, {}", stake2.to_string_native());
    println!("val3: {val3}, {pk3}, {}", stake3.to_string_native());

    init_genesis(
        &mut s,
        &params,
        [
            GenesisValidator {
                address: val1,
                tokens: stake1,
                consensus_key: pk1,
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
            },
            GenesisValidator {
                address: val2.clone(),
                tokens: stake2,
                consensus_key: pk2,
                eth_hot_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                eth_cold_key: key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                ),
                commission_rate: Dec::new(1, 1).expect("Dec creation failed"),
                max_commission_rate_change: Dec::new(1, 1)
                    .expect("Dec creation failed"),
            },
        ]
        .into_iter(),
        epoch,
    )
    .unwrap();

    // Advance to EPOCH 1
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Insert another validator with 0 voting power
    insert_validator(&mut s, &val3, &pk3, stake3, epoch);

    assert_eq!(stake2, stake3);

    // Add 2 bonds, one for val2 and greater one for val3
    let bonds_epoch_1 = pipeline_epoch;
    let bond2 = token::Amount::from_uint(1, 0).unwrap();
    let stake2 = stake2 + bond2;
    let bond3 = token::Amount::from_uint(4, 0).unwrap();
    let stake3 = stake3 + bond3;

    assert!(stake2 < stake3);
    assert_eq!(into_tm_voting_power(params.tm_votes_per_token, stake2), 0);
    assert_eq!(into_tm_voting_power(params.tm_votes_per_token, stake3), 0);

    update_validator_set(&mut s, &params, &val2, bond2.change(), epoch)
        .unwrap();
    update_validator_deltas(
        &mut s,
        &val2,
        bond2.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();

    update_validator_set(&mut s, &params, &val3, bond3.change(), epoch)
        .unwrap();
    update_validator_deltas(
        &mut s,
        &val3,
        bond3.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();

    // Advance to EPOCH 2
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Add 2 more bonds, same amount for `val2` and val3`
    let bonds_epoch_2 = pipeline_epoch;
    let bonds = token::Amount::native_whole(1);
    let stake2 = stake2 + bonds;
    let stake3 = stake3 + bonds;
    assert!(stake2 < stake3);
    assert_eq!(
        into_tm_voting_power(params.tm_votes_per_token, stake2),
        into_tm_voting_power(params.tm_votes_per_token, stake3)
    );

    update_validator_set(&mut s, &params, &val2, bonds.change(), epoch)
        .unwrap();
    update_validator_deltas(
        &mut s,
        &val2,
        bonds.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();

    update_validator_set(&mut s, &params, &val3, bonds.change(), epoch)
        .unwrap();
    update_validator_deltas(
        &mut s,
        &val3,
        bonds.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();

    // Advance to EPOCH 3
    let epoch = advance_epoch(&mut s, &params);

    // Check tendermint validator set updates
    assert_eq!(bonds_epoch_1, epoch);
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    // `val2` must not be given to tendermint - even though it was in the
    // consensus set, its voting power was 0, so it wasn't in TM set before the
    // bond
    assert!(tm_updates.is_empty());

    // Advance to EPOCH 4
    let epoch = advance_epoch(&mut s, &params);

    // Check tendermint validator set updates
    assert_eq!(bonds_epoch_2, epoch);
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    dbg!(&tm_updates);
    assert_eq!(tm_updates.len(), 1);
    // `val2` must not be given to tendermint as it was and still is below
    // capacity
    assert_eq!(
        tm_updates[0],
        ValidatorSetUpdate::Consensus(ConsensusValidator {
            consensus_key: pk3,
            bonded_stake: stake3,
        })
    );
}

fn get_tendermint_set_updates(
    s: &TestWlStorage,
    params: &PosParams,
    Epoch(epoch): Epoch,
) -> Vec<ValidatorSetUpdate> {
    // Because the `validator_set_update_tendermint` is called 2 blocks before
    // the start of a new epoch, it expects to receive the epoch that is before
    // the start of a new one too and so we give it the predecessor of the
    // current epoch here to actually get the update for the current epoch.
    let epoch = Epoch(epoch - 1);
    validator_set_update_tendermint(s, params, epoch, |update| update).unwrap()
}

/// Advance to the next epoch. Returns the new epoch.
fn advance_epoch(s: &mut TestWlStorage, params: &PosParams) -> Epoch {
    s.storage.block.epoch = s.storage.block.epoch.next();
    let current_epoch = s.storage.block.epoch;
    store_total_consensus_stake(s, current_epoch).unwrap();
    copy_validator_sets_and_positions(
        s,
        current_epoch,
        current_epoch + params.pipeline_len,
    )
    .unwrap();
    purge_validator_sets_for_old_epoch(s, current_epoch).unwrap();
    // process_slashes(s, current_epoch).unwrap();
    // dbg!(current_epoch);
    current_epoch
}

fn arb_genesis_validators(
    size: Range<usize>,
    threshold: Option<token::Amount>,
) -> impl Strategy<Value = Vec<GenesisValidator>> {
    let tokens: Vec<_> = (0..size.end)
        .map(|ix| {
            if ix == 0 {
                // If there's a threshold, make sure that at least one validator
                // has at least a stake greater or equal to the threshold to
                // avoid having an empty consensus set.
                threshold
                    .map(|token| token.raw_amount())
                    .unwrap_or(Uint::one())
                    .as_u64()..=10_000_000_u64
            } else {
                1..=10_000_000_u64
            }
            .prop_map(token::Amount::from)
        })
        .collect();
    (size, tokens)
        .prop_map(|(size, token_amounts)| {
            // use unique seeds to generate validators' address and consensus
            // key
            let seeds = (0_u64..).take(size);
            seeds
                .zip(token_amounts)
                .map(|(seed, tokens)| {
                    let address = address_from_simple_seed(seed);
                    let consensus_sk = common_sk_from_simple_seed(seed);
                    let consensus_key = consensus_sk.to_public();

                    let eth_hot_key = key::common::PublicKey::Secp256k1(
                        key::testing::gen_keypair::<key::secp256k1::SigScheme>(
                        )
                        .ref_to(),
                    );
                    let eth_cold_key = key::common::PublicKey::Secp256k1(
                        key::testing::gen_keypair::<key::secp256k1::SigScheme>(
                        )
                        .ref_to(),
                    );

                    let commission_rate = Dec::new(5, 2).expect("Test failed");
                    let max_commission_rate_change =
                        Dec::new(1, 2).expect("Test failed");
                    GenesisValidator {
                        address,
                        tokens,
                        consensus_key,
                        eth_hot_key,
                        eth_cold_key,
                        commission_rate,
                        max_commission_rate_change,
                    }
                })
                .collect()
        })
        .prop_filter(
            "Must have at least one genesis validator with stake above the \
             provided threshold, if any.",
            move |gen_vals: &Vec<GenesisValidator>| {
                if let Some(thresh) = threshold {
                    gen_vals.iter().any(|val| val.tokens >= thresh)
                } else {
                    true
                }
            },
        )
}

/// `iterateBondsUpToAmountTest`
#[test]
fn test_find_bonds_to_remove() {
    let mut storage = TestWlStorage::default();
    let source = established_address_1();
    let validator = established_address_2();
    let bond_handle = bond_handle(&source, &validator);

    let (e1, e2, e6) = (Epoch(1), Epoch(2), Epoch(6));

    bond_handle.set(&mut storage, I256::from(5), e1, 0).unwrap();
    bond_handle.set(&mut storage, I256::from(3), e2, 0).unwrap();
    bond_handle.set(&mut storage, I256::from(8), e6, 0).unwrap();

    // Test 1
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        I256::from(8),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6].into_iter().collect::<HashSet<Epoch>>()
    );
    assert!(bonds_for_removal.new_entry.is_none());

    // Test 2
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        I256::from(10),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6].into_iter().collect::<HashSet<Epoch>>()
    );
    assert_eq!(bonds_for_removal.new_entry, Some((Epoch(2), I256::from(1))));

    // Test 3
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        I256::from(11),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6, e2].into_iter().collect::<HashSet<Epoch>>()
    );
    assert!(bonds_for_removal.new_entry.is_none());

    // Test 4
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        I256::from(12),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6, e2].into_iter().collect::<HashSet<Epoch>>()
    );
    assert_eq!(bonds_for_removal.new_entry, Some((Epoch(1), I256::from(4))));
}

/// `computeModifiedRedelegationTest`
#[test]
fn test_compute_modified_redelegation() {
    let mut storage = TestWlStorage::default();
    let validator1 = established_address_1();
    let validator2 = established_address_2();
    let owner = established_address_3();
    let outer_epoch = Epoch(0);

    // Fill redelegated bonds in storage
    let redelegated_bonds_map = delegator_redelegated_bonds_handle(&owner)
        .at(&validator1)
        .at(&outer_epoch);
    redelegated_bonds_map
        .at(&validator1)
        .insert(&mut storage, Epoch(2), I256::from(6))
        .unwrap();
    redelegated_bonds_map
        .at(&validator1)
        .insert(&mut storage, Epoch(4), I256::from(7))
        .unwrap();
    redelegated_bonds_map
        .at(&validator2)
        .insert(&mut storage, Epoch(1), I256::from(5))
        .unwrap();
    redelegated_bonds_map
        .at(&validator2)
        .insert(&mut storage, Epoch(4), I256::from(7))
        .unwrap();

    let mr1 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        I256::from(25),
    )
    .unwrap();
    let mr2 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        I256::from(30),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation::default();

    assert_eq!(mr1, exp_mr);
    assert_eq!(mr2, exp_mr);

    // TODO: more tests once deterministic validator ordering is implemented and
    // synced between Rust and Quint
}

/// `mergeRedelegatedBondsMapTest`
#[test]
fn test_merge_redelegated_bonds_map() {
    let alice_address = established_address_1();
    let bob_address = established_address_2();
    let tom_address = established_address_3();

    let ep1 = Epoch(1);
    let ep2 = Epoch(2);
    let ep4 = Epoch(4);
    let ep5 = Epoch(5);
    let ep7 = Epoch(7);

    let alice_map = vec![(ep1, 2), (ep2, 3)]
        .into_iter()
        .map(|(epoch, amount)| (epoch, I256::from(amount)))
        .collect::<BTreeMap<_, _>>();
    let bob_map = vec![(ep1, 2), (ep2, 3)]
        .into_iter()
        .map(|(epoch, amount)| (epoch, I256::from(amount)))
        .collect::<BTreeMap<_, _>>();
    let tom_map = vec![(ep4, 3), (ep5, 6)]
        .into_iter()
        .map(|(epoch, amount)| (epoch, I256::from(amount)))
        .collect::<BTreeMap<_, _>>();
    let tom_map_2 = vec![(ep4, 3), (ep7, 6)]
        .into_iter()
        .map(|(epoch, amount)| (epoch, I256::from(amount)))
        .collect::<BTreeMap<_, _>>();
    let comb_tom_map = vec![(ep4, 6), (ep5, 6), (ep7, 6)]
        .into_iter()
        .map(|(epoch, amount)| (epoch, I256::from(amount)))
        .collect::<BTreeMap<_, _>>();

    let alice_bob_map = vec![
        (alice_address.clone(), alice_map.clone()),
        (bob_address.clone(), bob_map.clone()),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let bob_tom_map = vec![
        (tom_address.clone(), tom_map),
        (bob_address.clone(), bob_map.clone()),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let alice_tom2_map = vec![
        (tom_address.clone(), tom_map_2),
        (alice_address.clone(), alice_map.clone()),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let everyone = vec![
        (alice_address.clone(), alice_map.clone()),
        (bob_address.clone(), bob_map.clone()),
        (tom_address, comb_tom_map),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(
        merge_redelegated_bonds_map(
            &EagerRedelegatedBondsMap::default(),
            &EagerRedelegatedBondsMap::default()
        ),
        EagerRedelegatedBondsMap::default()
    );
    assert_eq!(
        merge_redelegated_bonds_map(
            &alice_bob_map,
            &EagerRedelegatedBondsMap::default()
        ),
        alice_bob_map
    );
    assert_eq!(
        merge_redelegated_bonds_map(
            &EagerRedelegatedBondsMap::default(),
            &alice_bob_map
        ),
        alice_bob_map
    );
    assert_eq!(
        merge_redelegated_bonds_map(
            &vec![(alice_address, alice_map)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
            &vec![(bob_address, bob_map)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        ),
        alice_bob_map
    );
    assert_eq!(
        merge_redelegated_bonds_map(&bob_tom_map, &alice_tom2_map),
        everyone
    )
}

/// `computeNewRedelegatedUnbondsTest`
#[test]
fn test_compute_new_redelegated_unbonds() {
    let mut storage = TestWlStorage::default();
    let alice = established_address_1();
    let bob = established_address_2();

    let key = Key::parse("testing").unwrap();
    let redelegated_bonds = NestedMap::<Epoch, RedelegatedBonds>::open(key);

    // Populate the lazy and eager maps
    let (ep1, ep2, ep4, ep5, ep6, ep7) =
        (Epoch(1), Epoch(2), Epoch(4), Epoch(5), Epoch(6), Epoch(7));
    let keys_and_values = vec![
        (ep5, alice.clone(), ep2, 1),
        (ep5, alice.clone(), ep4, 1),
        (ep7, alice.clone(), ep2, 1),
        (ep7, alice.clone(), ep4, 1),
        (ep5, bob.clone(), ep1, 1),
        (ep5, bob.clone(), ep4, 2),
        (ep7, bob.clone(), ep1, 1),
        (ep7, bob.clone(), ep4, 2),
    ];
    let mut eager_map = BTreeMap::<Epoch, EagerRedelegatedBondsMap>::new();
    for (outer_ep, address, inner_ep, amount) in keys_and_values {
        redelegated_bonds
            .at(&outer_ep)
            .at(&address)
            .insert(&mut storage, inner_ep, I256::from(amount))
            .unwrap();
        eager_map
            .entry(outer_ep)
            .or_default()
            .entry(address.clone())
            .or_default()
            .insert(inner_ep, I256::from(amount));
    }

    // Different ModifiedRedelegation objects for testing
    let empty_mr = ModifiedRedelegation::default();
    let all_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: HashSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: None,
        epochs_to_remove: Default::default(),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_val_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: HashSet::from_iter([alice.clone()]),
        validator_to_modify: None,
        epochs_to_remove: Default::default(),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_val_partial_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: HashSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: HashSet::from_iter([ep1]),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_epoch_partial_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: HashSet::from_iter([alice, bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: HashSet::from_iter([ep1, ep4]),
        epoch_to_modify: Some(ep4),
        new_amount: Some(I256::from(1)),
    };

    // Test case 1
    let res = compute_new_redelegated_unbonds(
        &mut storage,
        &redelegated_bonds,
        &Default::default(),
        &empty_mr,
    )
    .unwrap();
    assert_eq!(res, Default::default());

    let set5 = HashSet::<Epoch>::from_iter([ep5]);
    let set56 = HashSet::<Epoch>::from_iter([ep5, ep6]);

    // Test case 2
    let res = compute_new_redelegated_unbonds(
        &mut storage,
        &redelegated_bonds,
        &set5,
        &empty_mr,
    )
    .unwrap();
    let mut exp_res = eager_map.clone();
    exp_res.remove(&ep7);
    assert_eq!(res, exp_res);

    // Test case 3
    let res = compute_new_redelegated_unbonds(
        &mut storage,
        &redelegated_bonds,
        &set56,
        &empty_mr,
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 4
    println!("\nTEST CASE 4\n");
    let res = compute_new_redelegated_unbonds(
        &mut storage,
        &redelegated_bonds,
        &set56,
        &all_mr,
    )
    .unwrap();
    assert_eq!(res, eager_map);

    // Test case 5
    let res = compute_new_redelegated_unbonds(
        &mut storage,
        &redelegated_bonds,
        &set56,
        &mod_val_mr,
    )
    .unwrap();
    exp_res = eager_map.clone();
    exp_res.entry(ep7).or_default().remove(&bob);
    assert_eq!(res, exp_res);

    // Test case 6
    let res = compute_new_redelegated_unbonds(
        &mut storage,
        &redelegated_bonds,
        &set56,
        &mod_val_partial_mr,
    )
    .unwrap();
    exp_res = eager_map.clone();
    exp_res
        .entry(ep7)
        .or_default()
        .entry(bob.clone())
        .or_default()
        .remove(&ep4);
    assert_eq!(res, exp_res);

    // Test case 7
    let res = compute_new_redelegated_unbonds(
        &mut storage,
        &redelegated_bonds,
        &set56,
        &mod_epoch_partial_mr,
    )
    .unwrap();
    exp_res
        .entry(ep7)
        .or_default()
        .entry(bob)
        .or_default()
        .insert(ep4, I256::from(1));
    assert_eq!(res, exp_res);
}

/// `applyListSlashesTest`
#[test]
fn test_apply_list_slashes() {
    let init_epoch = Epoch(2);
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    // let unbonding_len = 4u64;
    // let cubic_offset = 1u64;

    let slash1 = Slash {
        epoch: init_epoch,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slash2 = Slash {
        epoch: init_epoch
            + params.unbonding_len
            + params.cubic_slashing_window_length
            + 1u64,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let list1 = vec![slash1.clone()];
    let list2 = vec![slash1.clone(), slash2.clone()];
    let list3 = vec![slash1.clone(), slash1.clone()];
    let list4 = vec![slash1.clone(), slash1, slash2];

    let res = apply_list_slashes(&params, &vec![], token::Change::from(100));
    assert_eq!(res, token::Amount::from(100));

    let res = apply_list_slashes(&params, &list1, token::Change::from(100));
    assert_eq!(res, token::Amount::zero());

    let res = apply_list_slashes(&params, &list2, token::Change::from(100));
    assert_eq!(res, token::Amount::zero());

    let res = apply_list_slashes(&params, &list3, token::Change::from(100));
    assert_eq!(res, token::Amount::zero());

    let res = apply_list_slashes(&params, &list4, token::Change::from(100));
    assert_eq!(res, token::Amount::zero());
}

/// `computeSlashableAmountTest`
#[test]
fn test_compute_slashable_amount() {
    let init_epoch = Epoch(2);
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    let slash1 = Slash {
        epoch: init_epoch
            + params.unbonding_len
            + params.cubic_slashing_window_length,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let slash2 = Slash {
        epoch: init_epoch
            + params.unbonding_len
            + params.cubic_slashing_window_length
            + 1u64,
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let test_map = vec![(init_epoch, token::Change::from(50))]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let res = compute_slashable_amount(
        &params,
        &slash1,
        token::Change::from(100),
        &BTreeMap::new(),
    );
    assert_eq!(res, token::Change::from(100));

    let res = compute_slashable_amount(
        &params,
        &slash2,
        token::Change::from(100),
        &test_map,
    );
    assert_eq!(res, token::Change::from(50));

    let res = compute_slashable_amount(
        &params,
        &slash1,
        token::Change::from(100),
        &test_map,
    );
    assert_eq!(res, token::Change::from(100));
}

/// `foldAndSlashRedelegatedBondsMapTest`
#[test]
fn test_fold_and_slash_redelegated_bonds() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let start_epoch = Epoch(7);

    let alice = established_address_1();
    let bob = established_address_2();

    println!("\n\nAlice: {}", alice);
    println!("Bob: {}\n", bob);

    let test_slash = Slash {
        epoch: Default::default(),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };

    let test_data = vec![
        (alice.clone(), vec![(2, 1), (4, 1)]),
        (bob, vec![(1, 1), (4, 2)]),
    ];
    let mut eager_redel_bonds = EagerRedelegatedBondsMap::default();
    for (address, pair) in test_data {
        for (epoch, amount) in pair {
            eager_redel_bonds
                .entry(address.clone())
                .or_default()
                .insert(Epoch(epoch), I256::from(amount));
        }
    }

    // Test case 1
    let res = fold_and_slash_redelegated_bonds(
        &storage,
        &params,
        &eager_redel_bonds,
        &start_epoch,
        &Vec::new(),
        |_| true,
    );
    assert_eq!(
        res,
        FoldRedelegatedBondsResult {
            total_redelegated: token::Amount::from(5),
            total_after_slashing: token::Amount::from(5),
        }
    );

    // Test case 2
    let res = fold_and_slash_redelegated_bonds(
        &storage,
        &params,
        &eager_redel_bonds,
        &start_epoch,
        &[test_slash],
        |_| true,
    );
    assert_eq!(
        res,
        FoldRedelegatedBondsResult {
            total_redelegated: token::Amount::from(5),
            total_after_slashing: token::Amount::zero(),
        }
    );

    // Test case 3
    let alice_slash = Slash {
        epoch: Epoch(6),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();

    let res = fold_and_slash_redelegated_bonds(
        &storage,
        &params,
        &eager_redel_bonds,
        &start_epoch,
        &Vec::new(),
        |_| true,
    );
    assert_eq!(
        res,
        FoldRedelegatedBondsResult {
            total_redelegated: token::Amount::from(5),
            total_after_slashing: token::Amount::from(3),
        }
    );
}

/// `mergeOutgoingRedelegationsTest`
#[test]
fn test_merge_outgoing_redelegations() {
    let ep6 = Epoch(6);
    let existing = vec![((2, 6), 4), ((2, 5), 6), ((3, 6), 3)]
        .into_iter()
        .map(|((start, end), amount)| {
            let epoch_pair = (Epoch(start), Epoch(end));
            let amount = token::Change::from(amount);
            (epoch_pair, amount)
        })
        .collect::<BTreeMap<_, _>>();

    // Test case 1
    assert_eq!(
        merge_outgoing_redelegations(BTreeMap::new(), BTreeMap::new(), ep6),
        BTreeMap::new()
    );

    // Test case 2
    assert_eq!(
        merge_outgoing_redelegations(existing.clone(), BTreeMap::new(), ep6),
        existing
    );

    // Test case 3
    let test_bonds = vec![(2, 5)]
        .into_iter()
        .map(|(start, amount)| (Epoch(start), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    let exp_res = vec![((2, 6), 5)]
        .into_iter()
        .map(|((start, end), amount)| {
            let epoch_pair = (Epoch(start), Epoch(end));
            let amount = token::Change::from(amount);
            (epoch_pair, amount)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        merge_outgoing_redelegations(BTreeMap::new(), test_bonds.clone(), ep6),
        exp_res
    );

    // Test case 4
    let exp_res = vec![((2, 6), 9), ((2, 5), 6), ((3, 6), 3)]
        .into_iter()
        .map(|((start, end), amount)| {
            let epoch_pair = (Epoch(start), Epoch(end));
            let amount = token::Change::from(amount);
            (epoch_pair, amount)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        merge_outgoing_redelegations(existing, test_bonds, ep6),
        exp_res
    );
}

/// `computeTotalUnbondedTest`
#[test]
fn test_compute_total_unbonded() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let alice = established_address_1();
    let bob = established_address_2();

    let total_unbonded = unbond_records_handle(&alice).at(&Epoch::default());
    total_unbonded
        .insert(&mut storage, Epoch(2), token::Amount::from(5))
        .unwrap();
    total_unbonded
        .insert(&mut storage, Epoch(8), token::Amount::from(20))
        .unwrap();

    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&alice)
            .at(&Epoch::default());
    total_redelegated_unbonded
        .at(&Epoch(8))
        .at(&bob)
        .insert(&mut storage, Epoch(4), I256::from(10))
        .unwrap();

    // Test case 1
    let res = compute_total_unbonded(
        &storage,
        &params,
        &alice,
        Epoch(10),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::from(25));

    // Test case 2
    let res = compute_total_unbonded(
        &storage,
        &params,
        &alice,
        Epoch(7),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::from(5));

    // Insert slash for alice
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(2),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();

    // Test case 3
    let res = compute_total_unbonded(
        &storage,
        &params,
        &alice,
        Epoch(10),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::from(20));

    // Insert slash for bob
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(4),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();

    // Test case 4
    let res = compute_total_unbonded(
        &storage,
        &params,
        &alice,
        Epoch(10),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::from(10));
}

/// `foldRedelegatedBondsMapTest`
#[test]
fn test_fold_redelegated_bonds() {
    let mut storage = TestWlStorage::default();

    let alice = established_address_1();
    let bob = established_address_2();

    let key = Key::parse("testing").unwrap();
    let redelegated_bonds = RedelegatedBonds::open(key);

    let res = fold_redelegated_bonds_map(&storage, &redelegated_bonds).unwrap();
    assert_eq!(res, token::Change::zero());

    redelegated_bonds
        .at(&alice)
        .insert(&mut storage, Epoch(5), token::Change::from(6))
        .unwrap();
    let res = fold_redelegated_bonds_map(&storage, &redelegated_bonds).unwrap();
    assert_eq!(res, token::Change::from(6));

    redelegated_bonds
        .at(&alice)
        .insert(&mut storage, Epoch(6), token::Change::from(8))
        .unwrap();
    let res = fold_redelegated_bonds_map(&storage, &redelegated_bonds).unwrap();
    assert_eq!(res, token::Change::from(14));

    redelegated_bonds
        .at(&bob)
        .insert(&mut storage, Epoch(3), token::Change::from(7))
        .unwrap();
    let res = fold_redelegated_bonds_map(&storage, &redelegated_bonds).unwrap();
    assert_eq!(res, token::Change::from(21));
}

/// `computeRecentTotalUnbondedTest`
#[test]
fn test_compute_recent_total_unbonded() {
    let mut storage = TestWlStorage::default();

    let alice = established_address_1();
    let bob = established_address_2();

    let total_unbonded = unbond_records_handle(&alice).at(&Epoch::default());
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&bob).at(&Epoch::default());

    // Test case 1
    let res = compute_recent_total_unbonded(
        &storage,
        Epoch(5),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::zero());

    // Test case 2
    total_unbonded
        .insert(&mut storage, Epoch(6), token::Amount::from(10))
        .unwrap();
    total_unbonded
        .insert(&mut storage, Epoch(7), token::Amount::from(20))
        .unwrap();
    let res = compute_recent_total_unbonded(
        &storage,
        Epoch(5),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::from(30));

    // Test case 3
    total_unbonded.remove(&mut storage, &Epoch(6)).unwrap();
    total_unbonded
        .insert(&mut storage, Epoch(4), token::Amount::from(10))
        .unwrap();
    let res = compute_recent_total_unbonded(
        &storage,
        Epoch(5),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::from(20));

    // Test case 4
    let res = compute_recent_total_unbonded(
        &storage,
        Epoch(8),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::zero());

    // Test case 5
    total_unbonded.remove(&mut storage, &Epoch(4)).unwrap();
    total_unbonded
        .insert(&mut storage, Epoch(6), token::Amount::from(10))
        .unwrap();
    total_redelegated_unbonded
        .at(&Epoch(6))
        .at(&alice)
        .insert(&mut storage, Epoch(5), token::Change::from(6))
        .unwrap();
    total_redelegated_unbonded
        .at(&Epoch(6))
        .at(&alice)
        .insert(&mut storage, Epoch(6), token::Change::from(4))
        .unwrap();
    let res = compute_recent_total_unbonded(
        &storage,
        Epoch(5),
        &total_unbonded,
        &total_redelegated_unbonded,
    )
    .unwrap();
    assert_eq!(res, I256::from(20));
}

/// `hasRedelegationTest`
#[test]
fn test_has_redelegation() {
    let mut storage = TestWlStorage::default();

    let alice = established_address_1();
    let bob = established_address_2();

    let test_data = vec![
        (4, alice.clone(), 2, 6),
        (4, alice.clone(), 3, 7),
        (6, bob.clone(), 1, 8),
    ];
    let test_redelegations =
        validator_total_redelegated_unbonded_handle(&alice)
            .at(&Epoch::default());

    let mut redel = Redelegation {
        redel_bond_start: Epoch(4),
        src_validator: alice.clone(),
        bond_start: Epoch(3),
        amount: Default::default(),
    };

    // Test case 1
    assert!(!has_redelegation(&storage, &test_redelegations, &redel,).unwrap());

    // Now fill the map in storage
    for (outer_ep, address, inner_ep, amount) in test_data {
        test_redelegations
            .at(&Epoch(outer_ep))
            .at(&address)
            .insert(&mut storage, Epoch(inner_ep), token::Change::from(amount))
            .unwrap();
    }

    // Test case 2
    assert!(has_redelegation(&storage, &test_redelegations, &redel,).unwrap());

    // Test case 3
    redel.bond_start = Epoch(4);
    assert!(!has_redelegation(&storage, &test_redelegations, &redel,).unwrap());

    // Test case 4
    redel.bond_start = Epoch(3);
    redel.src_validator = bob;
    assert!(!has_redelegation(&storage, &test_redelegations, &redel,).unwrap());

    // Test case 5
    redel.src_validator = alice;
    redel.redel_bond_start = Epoch(6);
    assert!(!has_redelegation(&storage, &test_redelegations, &redel,).unwrap());
}

/// `computeRemainderRedelegationTest`
#[test]
fn test_compute_remainder_redelegation() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    let alice = established_address_1();
    let bob = established_address_2();

    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&alice);
    let slashes = validator_slashes_handle(&alice);

    let redelegation = Redelegation {
        redel_bond_start: Epoch(8),
        src_validator: alice.clone(),
        bond_start: Epoch(5),
        amount: token::Change::from(10),
    };
    let mut balances = vec![(9, 0), (10, 0)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    let init_balances = balances.clone();

    // Test case 1
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 10), (10, 10)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 2
    balances = init_balances.clone();
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(4),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    assert_eq!(balances, exp_balances);

    // Test case 3
    balances.insert(Epoch(9), token::Change::from(5));
    balances.insert(Epoch(10), token::Change::from(4));
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 15), (10, 14)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 4
    slashes.pop(&mut storage).unwrap();
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(5),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    balances = init_balances.clone();
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 0), (10, 0)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 5
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(6),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    balances = init_balances.clone();
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    assert_eq!(balances, exp_balances);

    // Test case 6
    assert_eq!(slashes.len(&storage).unwrap(), 2);
    slashes.pop(&mut storage).unwrap();
    slashes.pop(&mut storage).unwrap();

    balances = init_balances.clone();
    total_redelegated_unbonded
        .at(&Epoch(8))
        .at(&Epoch(8))
        .at(&bob)
        .insert(&mut storage, Epoch(5), token::Change::from(8))
        .unwrap();
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 10), (10, 10)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 7
    balances = init_balances.clone();
    total_redelegated_unbonded
        .remove_all(&mut storage, &Epoch(8))
        .unwrap();
    assert!(total_redelegated_unbonded.is_empty(&storage).unwrap());
    total_redelegated_unbonded
        .at(&Epoch(8))
        .at(&Epoch(8))
        .at(&alice)
        .insert(&mut storage, Epoch(5), token::Change::from(8))
        .unwrap();
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 2), (10, 2)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 8
    balances = init_balances;
    total_redelegated_unbonded
        .remove_all(&mut storage, &Epoch(8))
        .unwrap();
    assert!(total_redelegated_unbonded.is_empty(&storage).unwrap());
    total_redelegated_unbonded
        .at(&Epoch(10))
        .at(&Epoch(8))
        .at(&alice)
        .insert(&mut storage, Epoch(5), token::Change::from(8))
        .unwrap();
    compute_remainder_redelegation(
        &storage,
        &params,
        &redelegation,
        Epoch(8),
        &slashes,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 10), (10, 2)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);
}

/// `computeBalanceRedelegatedBondsTest`
#[test]
fn test_compute_redelegated_bonds_balance() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    let alice = established_address_1();
    let bob = established_address_2();

    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&alice);

    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&alice).at(&Epoch::default());
    let test_data = vec![
        (alice.clone(), 5, 10),
        (alice.clone(), 6, 5),
        (bob.clone(), 5, 9),
        (bob.clone(), 6, 5),
    ];
    for (address, epoch, amount) in test_data {
        total_redelegated_bonded
            .at(&address)
            .insert(&mut storage, Epoch(epoch), token::Change::from(amount))
            .unwrap();
    }
    let mut balances = vec![(9, 0), (10, 0)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    let init_balances = balances.clone();

    // Test case 1
    compute_redelegated_bonds_balance(
        &storage,
        &params,
        Epoch(7),
        Epoch(8),
        &total_redelegated_bonded,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 29), (10, 29)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 2
    balances.insert(Epoch(9), token::Change::from(2));
    balances.insert(Epoch(10), token::Change::from(1));
    compute_redelegated_bonds_balance(
        &storage,
        &params,
        Epoch(7),
        Epoch(8),
        &total_redelegated_bonded,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 31), (10, 30)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 3
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(4),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    balances = init_balances.clone();
    compute_redelegated_bonds_balance(
        &storage,
        &params,
        Epoch(7),
        Epoch(8),
        &total_redelegated_bonded,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 29), (10, 29)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 4
    validator_slashes_handle(&alice).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(5),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    balances = init_balances.clone();
    compute_redelegated_bonds_balance(
        &storage,
        &params,
        Epoch(7),
        Epoch(8),
        &total_redelegated_bonded,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 19), (10, 19)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);

    // Test case 5
    balances = init_balances;
    total_redelegated_unbonded
        .at(&Epoch(10))
        .at(&Epoch(7))
        .at(&bob)
        .insert(&mut storage, Epoch(5), token::Change::from(9))
        .unwrap();
    total_redelegated_unbonded
        .at(&Epoch(10))
        .at(&Epoch(7))
        .at(&bob)
        .insert(&mut storage, Epoch(6), token::Change::from(3))
        .unwrap();
    compute_redelegated_bonds_balance(
        &storage,
        &params,
        Epoch(7),
        Epoch(8),
        &total_redelegated_bonded,
        &total_redelegated_unbonded,
        &mut balances,
    )
    .unwrap();
    let exp_balances = vec![(9, 19), (10, 7)]
        .into_iter()
        .map(|(epoch, amount)| (Epoch(epoch), token::Change::from(amount)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(balances, exp_balances);
}

/// `slashRedelegationTest`
#[test]
fn test_slash_redelegation() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let alice = established_address_1();

    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&alice);
    total_redelegated_unbonded
        .at(&Epoch(13))
        .at(&Epoch(10))
        .at(&alice)
        .insert(&mut storage, Epoch(7), token::Change::from(2))
        .unwrap();

    let slashes = validator_slashes_handle(&alice);

    let mut slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Change::zero()),
        (Epoch(16), token::Change::zero()),
    ]);
    let empty_slash_amounts = slashed_amounts_map.clone();

    // Test case 1
    slash_redelegation(
        &storage,
        &params,
        token::Change::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Change::from(5)),
            (Epoch(16), token::Change::from(5)),
        ])
    );

    // Test case 2
    slashed_amounts_map = empty_slash_amounts.clone();
    slash_redelegation(
        &storage,
        &params,
        token::Change::from(7),
        Epoch(7),
        Epoch(11),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Change::from(7)),
            (Epoch(16), token::Change::from(7)),
        ])
    );

    // Test case 3
    slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Change::from(2)),
        (Epoch(16), token::Change::from(3)),
    ]);
    slash_redelegation(
        &storage,
        &params,
        token::Change::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Change::from(7)),
            (Epoch(16), token::Change::from(8)),
        ])
    );

    // Test case 4
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(8),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slashed_amounts_map = empty_slash_amounts.clone();
    slash_redelegation(
        &storage,
        &params,
        token::Change::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 5
    slashes.pop(&mut storage).unwrap();
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(9),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slash_redelegation(
        &storage,
        &params,
        token::Change::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 6
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(8),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slash_redelegation(
        &storage,
        &params,
        token::Change::from(7),
        Epoch(7),
        Epoch(10),
        &alice,
        Epoch(14),
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);
}

/// `slashValidatorRedelegationTest`
#[test]
fn test_slash_validator_redelegation() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let alice = established_address_1();
    let bob = established_address_2();

    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&alice);
    total_redelegated_unbonded
        .at(&Epoch(13))
        .at(&Epoch(10))
        .at(&alice)
        .insert(&mut storage, Epoch(7), token::Change::from(2))
        .unwrap();

    let outgoing_redelegations =
        validator_outgoing_redelegations_handle(&alice).at(&bob);

    let slashes = validator_slashes_handle(&alice);

    let mut slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Change::zero()),
        (Epoch(16), token::Change::zero()),
    ]);
    let empty_slash_amounts = slashed_amounts_map.clone();

    // Test case 1
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 2
    total_redelegated_unbonded
        .remove_all(&mut storage, &Epoch(13))
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);

    // Test case 3
    total_redelegated_unbonded
        .at(&Epoch(13))
        .at(&Epoch(10))
        .at(&alice)
        .insert(&mut storage, Epoch(7), token::Change::from(2))
        .unwrap();
    outgoing_redelegations
        .at(&Epoch(6))
        .insert(&mut storage, Epoch(8), token::Amount::from(7))
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Change::from(7)),
            (Epoch(16), token::Change::from(7)),
        ])
    );

    // Test case 4
    slashed_amounts_map = empty_slash_amounts.clone();
    outgoing_redelegations
        .remove_all(&mut storage, &Epoch(6))
        .unwrap();
    outgoing_redelegations
        .at(&Epoch(7))
        .insert(&mut storage, Epoch(8), token::Amount::from(7))
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Change::from(5)),
            (Epoch(16), token::Change::from(5)),
        ])
    );

    // Test case 5
    slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Change::from(2)),
        (Epoch(16), token::Change::from(3)),
    ]);
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(
        slashed_amounts_map,
        BTreeMap::from_iter([
            (Epoch(15), token::Change::from(7)),
            (Epoch(16), token::Change::from(8)),
        ])
    );

    // Test case 6
    slashed_amounts_map = empty_slash_amounts.clone();
    slashes
        .push(
            &mut storage,
            Slash {
                epoch: Epoch(8),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    slash_validator_redelegation(
        &storage,
        &params,
        &alice,
        Epoch(14),
        &outgoing_redelegations,
        &slashes,
        &total_redelegated_unbonded,
        Dec::one(),
        &mut slashed_amounts_map,
    )
    .unwrap();
    assert_eq!(slashed_amounts_map, empty_slash_amounts);
}

/// `slashValidatorTest`
#[test]
fn test_slash_validator() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };
    let alice = established_address_1();
    let bob = established_address_2();

    let total_bonded = total_bonded_handle(&bob);
    let total_unbonded = unbond_records_handle(&bob);
    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&bob);
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&bob);

    let infraction_stake = token::Change::from(23);

    let initial_stakes = BTreeMap::from_iter([
        (Epoch(10), infraction_stake),
        (Epoch(11), infraction_stake),
    ]);

    let current_epoch = Epoch(10);
    let slash_rate = Dec::one();

    // Insert initial stake at epoch 0
    validator_deltas_handle(&bob)
        .set(&mut storage, infraction_stake, Epoch::default(), 0)
        .unwrap();

    // Test case 1
    // There are no non-genesis bonds or slashes
    println!("\nTEST 1:");
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 2
    // A bond to bob becomes active at current epoch
    println!("\nTEST 2:");
    total_bonded
        .set(
            &mut storage,
            token::Change::from(6),
            current_epoch - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::from(6),
            current_epoch - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 3
    // A bond that became active at the current epoch is fully unbonded at
    // current epoch + 1
    println!("\nTEST 3:");
    total_unbonded
        .at(&current_epoch.next())
        .insert(&mut storage, current_epoch, token::Amount::from(6))
        .unwrap();
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::from(-6),
            current_epoch.next() - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 4
    // A bond that became active at the current epoch is partially unbonded at
    // current epoch + 1
    println!("\nTEST 4:");
    total_unbonded
        .at(&current_epoch.next())
        .insert(&mut storage, current_epoch, token::Amount::from(3))
        .unwrap();
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::from(-3),
            current_epoch.next() - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 5
    // A redelegation from alice to bob becomes active at current epoch
    println!("\nTEST 5:");
    total_bonded
        .get_data_handler()
        .remove(&mut storage, &current_epoch)
        .unwrap();
    total_unbonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::zero(),
            current_epoch.next() - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Change::from(5))
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, Epoch(3), token::Change::from(1))
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 6
    // A redelegation that became active at current epoch is fully unbonded at
    // current epoch + 1
    println!("Test case 6");
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Change::from(5))
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, Epoch(3), token::Change::from(1))
        .unwrap();
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::from(-6),
            current_epoch.next() - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 7
    // A redelegation that became active at current epoch is partially unbonded
    // at current epoch + 1
    println!("Test case 7");
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::from(-4),
            current_epoch.next() - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Change::from(4))
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .remove(&mut storage, &Epoch(3))
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 8
    // A bond is active at current epoch and a redelegation becomes active at
    // current epoch + 1. The redelegation is partially unbonded at current
    // epoch + 1 as well
    println!("Test case 8");
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::from(12),
            current_epoch - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch.next())
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Change::from(5))
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch.next())
        .at(&alice)
        .insert(&mut storage, Epoch(3), token::Change::from(1))
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch.next())
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Change::from(4))
        .unwrap();
    total_bonded
        .get_data_handler()
        .insert(&mut storage, current_epoch, token::Change::from(6))
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, initial_stakes);

    // Test case 9
    // A bond is active at current epoch and a slash exists for alice
    println!("Test case 9");
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    validator_deltas_handle(&bob)
        .get_data_handler()
        .remove(&mut storage, &current_epoch.next())
        .unwrap();
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            token::Change::from(6),
            current_epoch - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    validator_deltas_handle(&bob)
        .set(
            &mut storage,
            -infraction_stake,
            current_epoch.prev() - params.pipeline_len,
            params.pipeline_len,
        )
        .unwrap();
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: current_epoch.prev()
                    - params.slash_processing_epoch_offset(),
                rate: Dec::one(),
                block_height: Default::default(),
                r#type: SlashType::DuplicateVote,
            },
        )
        .unwrap();
    let res = slash_validator(
        &mut storage,
        &params,
        &bob,
        slash_rate,
        current_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(
        res,
        BTreeMap::from_iter([
            (current_epoch, token::Change::zero()),
            (current_epoch.next(), token::Change::zero())
        ])
    );
}
