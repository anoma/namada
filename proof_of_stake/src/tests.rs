//! PoS system tests

mod state_machine;
mod state_machine_v2;
mod utils;

use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, Range};
use std::str::FromStr;

use assert_matches::assert_matches;
use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::collections::lazy_map::{
    self, Collectable, NestedMap,
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
use namada_core::types::token::testing::arb_amount_non_zero_ceiled;
use namada_core::types::token::NATIVE_MAX_DECIMAL_PLACES;
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
    RedelegatedTokens, ReverseOrdTokenAmount, Slash, SlashType, UnbondDetails,
    ValidatorSetUpdate, ValidatorState, WeightedValidator,
};
use crate::{
    apply_list_slashes, become_validator, below_capacity_validator_set_handle,
    bond_handle, bond_tokens, bonds_and_unbonds,
    compute_amount_after_slashing_unbond,
    compute_amount_after_slashing_withdraw, compute_bond_at_epoch,
    compute_modified_redelegation, compute_new_redelegated_unbonds,
    compute_slash_bond_at_epoch, compute_slashable_amount,
    consensus_validator_set_handle, copy_validator_sets_and_positions,
    delegator_redelegated_bonds_handle, delegator_redelegated_unbonds_handle,
    find_bonds_to_remove, find_validator_by_raw_hash,
    fold_and_slash_redelegated_bonds, get_num_consensus_validators,
    init_genesis, insert_validator_into_validator_set, is_validator,
    process_slashes, purge_validator_sets_for_old_epoch,
    read_below_capacity_validator_set_addresses_with_stake,
    read_below_threshold_validator_set_addresses,
    read_consensus_validator_set_addresses_with_stake, read_total_stake,
    read_validator_deltas_value, read_validator_stake, slash,
    slash_redelegation, slash_validator, slash_validator_redelegation,
    staking_token_address, store_total_consensus_stake, total_bonded_handle,
    total_deltas_handle, total_unbonded_handle, unbond_handle, unbond_tokens,
    unjail_validator, update_validator_deltas, update_validator_set,
    validator_consensus_key_handle, validator_incoming_redelegations_handle,
    validator_outgoing_redelegations_handle, validator_set_positions_handle,
    validator_set_update_tendermint, validator_slashes_handle,
    validator_state_handle, validator_total_redelegated_bonded_handle,
    validator_total_redelegated_unbonded_handle, withdraw_tokens,
    write_validator_address_raw_hash, BecomeValidator, EagerRedelegatedUnbonds,
    FoldRedelegatedBondsResult, ModifiedRedelegation, RedelegationError,
    STORE_VALIDATOR_SETS_LEN,
};

proptest! {
    // Generate arb valid input for `test_init_genesis_aux`
    #![proptest_config(Config {
        cases: 100,
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
        cases: 100,
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
        cases: 100,
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
        cases: 100,
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

proptest! {
    // Generate arb valid input for `test_unjail_validator_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_unjail_validator(
        (pos_params, genesis_validators)
            in arb_params_and_genesis_validators(Some(4),6..9)
    ) {
        test_unjail_validator_aux(pos_params,
            genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_simple_redelegation_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_simple_redelegation(

    genesis_validators in arb_genesis_validators(2..4, None),
    (amount_delegate, amount_redelegate, amount_unbond) in arb_redelegation_amounts(20)

    ) {
        test_simple_redelegation_aux(genesis_validators, amount_delegate, amount_redelegate, amount_unbond)
    }
}

proptest! {
    // Generate arb valid input for `test_simple_redelegation_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_redelegation_with_slashing(

    genesis_validators in arb_genesis_validators(2..4, None),
    (amount_delegate, amount_redelegate, amount_unbond) in arb_redelegation_amounts(20)

    ) {
        test_redelegation_with_slashing_aux(genesis_validators, amount_delegate, amount_redelegate, amount_unbond)
    }
}

proptest! {
    // Generate arb valid input for `test_chain_redelegations_aux`
    #![proptest_config(Config {
        cases: 100,
        .. Config::default()
    })]
    #[test]
    fn test_chain_redelegations(

    genesis_validators in arb_genesis_validators(3..4, None),

    ) {
        test_chain_redelegations_aux(genesis_validators)
    }
}

proptest! {
    // Generate arb valid input for `test_overslashing_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_overslashing(

    genesis_validators in arb_genesis_validators(4..5, None),

    ) {
        test_overslashing_aux(genesis_validators)
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
    assert_eq!(delta, Some(amount_self_bond));

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
    .unwrap();
    let val_stake_post =
        read_validator_stake(&s, &params, &validator.address, pipeline_epoch)
            .unwrap();
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
        token::Amount::zero()
    );
    assert_eq!(
        delegation
            .get_sum(&s, pipeline_epoch, &params)
            .unwrap()
            .unwrap_or_default(),
        amount_del
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
        amount_self_unbond - amount_self_bond != token::Amount::zero();
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
            .at(&Epoch::default())
            .get(
                &s,
                &(pipeline_epoch
                    + params.unbonding_len
                    + params.cubic_slashing_window_length)
            )
            .unwrap(),
        if unbonded_genesis_self_bond {
            Some(amount_self_unbond - amount_self_bond)
        } else {
            None
        }
    );
    assert_eq!(
        unbond
            .at(&(self_bond_epoch + params.pipeline_len))
            .get(
                &s,
                &(pipeline_epoch
                    + params.unbonding_len
                    + params.cubic_slashing_window_length)
            )
            .unwrap(),
        Some(amount_self_bond)
    );
    assert_eq!(
        val_stake_pre,
        validator.tokens + amount_self_bond + amount_del
    );
    assert_eq!(
        val_stake_post,
        validator.tokens + amount_self_bond + amount_del - amount_self_unbond
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
            .at(&(delegation_epoch + params.pipeline_len))
            .get(
                &s,
                &(pipeline_epoch
                    + params.unbonding_len
                    + params.cubic_slashing_window_length)
            )
            .unwrap(),
        Some(amount_undel)
    );
    assert_eq!(
        val_stake_pre,
        validator.tokens + amount_self_bond + amount_del
    );
    assert_eq!(
        val_stake_post,
        validator.tokens + amount_self_bond - amount_self_unbond + amount_del
            - amount_undel
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
    assert_eq!(delta, Some(amount));

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
    update_validator_set(
        &mut s,
        &params,
        &val1,
        -unbond.change(),
        pipeline_epoch,
    )
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
    update_validator_set(&mut s, &params, &val6, bond.change(), pipeline_epoch)
        .unwrap();
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
        validator_stake_threshold: token::Amount::zero(),
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

    update_validator_set(
        &mut s,
        &params,
        &val2,
        bond2.change(),
        pipeline_epoch,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &val2,
        bond2.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();

    update_validator_set(
        &mut s,
        &params,
        &val3,
        bond3.change(),
        pipeline_epoch,
    )
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

    update_validator_set(
        &mut s,
        &params,
        &val2,
        bonds.change(),
        pipeline_epoch,
    )
    .unwrap();
    update_validator_deltas(
        &mut s,
        &val2,
        bonds.change(),
        epoch,
        params.pipeline_len,
    )
    .unwrap();

    update_validator_set(
        &mut s,
        &params,
        &val3,
        bonds.change(),
        pipeline_epoch,
    )
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
    let threshold = threshold
        .unwrap_or_else(|| PosParams::default().validator_stake_threshold);
    let tokens: Vec<_> = (0..size.end)
        .map(|ix| {
            if ix == 0 {
                // Make sure that at least one validator has at least a stake
                // greater or equal to the threshold to avoid having an empty
                // consensus set.
                threshold.raw_amount().as_u64()..=10_000_000_u64
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
                gen_vals.iter().any(|val| val.tokens >= threshold)
            },
        )
}

fn test_unjail_validator_aux(
    params: PosParams,
    mut validators: Vec<GenesisValidator>,
) {
    println!("\nTest inputs: {params:?}, genesis validators: {validators:#?}");
    let mut s = TestWlStorage::default();

    // Find the validator with the most stake and 100x his stake to keep the
    // cubic slash rate small
    let num_vals = validators.len();
    validators.sort_by_key(|a| a.tokens);
    validators[num_vals - 1].tokens = 100 * validators[num_vals - 1].tokens;

    // Get second highest stake validator tomisbehave
    let val_addr = &validators[num_vals - 2].address;
    let val_tokens = validators[num_vals - 2].tokens;
    println!(
        "Validator that will misbehave addr {val_addr}, tokens {}",
        val_tokens.to_string_native()
    );

    // Genesis
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

    assert_eq!(
        validator_state_handle(val_addr)
            .get(&s, current_epoch, &params)
            .unwrap(),
        Some(ValidatorState::Consensus)
    );

    for epoch in Epoch::iter_bounds_inclusive(
        current_epoch.next(),
        current_epoch + params.pipeline_len,
    ) {
        // Check the validator state
        assert_eq!(
            validator_state_handle(val_addr)
                .get(&s, epoch, &params)
                .unwrap(),
            Some(ValidatorState::Jailed)
        );
        // Check the validator set positions
        assert!(
            validator_set_positions_handle()
                .at(&epoch)
                .get(&s, val_addr)
                .unwrap()
                .is_none(),
        );
    }

    // Advance past an epoch in which we can unbond
    let unfreeze_epoch =
        slash_0_evidence_epoch + params.slash_processing_epoch_offset();
    while current_epoch < unfreeze_epoch + 4u64 {
        current_epoch = advance_epoch(&mut s, &params);
        super::process_slashes(&mut s, current_epoch).unwrap();
    }

    // Unjail the validator
    unjail_validator(&mut s, val_addr, current_epoch).unwrap();

    // Check the validator state
    for epoch in
        Epoch::iter_bounds_inclusive(current_epoch, current_epoch.next())
    {
        assert_eq!(
            validator_state_handle(val_addr)
                .get(&s, epoch, &params)
                .unwrap(),
            Some(ValidatorState::Jailed)
        );
    }

    assert_eq!(
        validator_state_handle(val_addr)
            .get(&s, current_epoch + params.pipeline_len, &params)
            .unwrap(),
        Some(ValidatorState::Consensus)
    );
    assert!(
        validator_set_positions_handle()
            .at(&(current_epoch + params.pipeline_len))
            .get(&s, val_addr)
            .unwrap()
            .is_some(),
    );

    // Advance another epoch
    current_epoch = advance_epoch(&mut s, &params);
    super::process_slashes(&mut s, current_epoch).unwrap();

    let second_att = unjail_validator(&mut s, val_addr, current_epoch);
    assert!(second_att.is_err());
}

/// `iterateBondsUpToAmountTest`
#[test]
fn test_find_bonds_to_remove() {
    let mut storage = TestWlStorage::default();
    let source = established_address_1();
    let validator = established_address_2();
    let bond_handle = bond_handle(&source, &validator);

    let (e1, e2, e6) = (Epoch(1), Epoch(2), Epoch(6));

    bond_handle
        .set(&mut storage, token::Amount::from(5), e1, 0)
        .unwrap();
    bond_handle
        .set(&mut storage, token::Amount::from(3), e2, 0)
        .unwrap();
    bond_handle
        .set(&mut storage, token::Amount::from(8), e6, 0)
        .unwrap();

    // Test 1
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(8),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert!(bonds_for_removal.new_entry.is_none());

    // Test 2
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(10),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert_eq!(
        bonds_for_removal.new_entry,
        Some((Epoch(2), token::Amount::from(1)))
    );

    // Test 3
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(11),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6, e2].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert!(bonds_for_removal.new_entry.is_none());

    // Test 4
    let bonds_for_removal = find_bonds_to_remove(
        &storage,
        &bond_handle.get_data_handler(),
        token::Amount::from(12),
    )
    .unwrap();
    assert_eq!(
        bonds_for_removal.epochs,
        vec![e6, e2].into_iter().collect::<BTreeSet<Epoch>>()
    );
    assert_eq!(
        bonds_for_removal.new_entry,
        Some((Epoch(1), token::Amount::from(4)))
    );
}

/// `computeModifiedRedelegationTest`
#[test]
fn test_compute_modified_redelegation() {
    let mut storage = TestWlStorage::default();
    let validator1 = established_address_1();
    let validator2 = established_address_2();
    let owner = established_address_3();
    let outer_epoch = Epoch(0);

    let mut alice = validator1.clone();
    let mut bob = validator2.clone();

    // Ensure a ranking order of alice > bob
    // TODO: check why this needs to be > (am I just confusing myself?)
    if bob > alice {
        alice = validator2;
        bob = validator1;
    }
    println!("\n\nalice = {}\nbob   = {}\n", &alice, &bob);

    // Fill redelegated bonds in storage
    let redelegated_bonds_map = delegator_redelegated_bonds_handle(&owner)
        .at(&alice)
        .at(&outer_epoch);
    redelegated_bonds_map
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Amount::from(6))
        .unwrap();
    redelegated_bonds_map
        .at(&alice)
        .insert(&mut storage, Epoch(4), token::Amount::from(7))
        .unwrap();
    redelegated_bonds_map
        .at(&bob)
        .insert(&mut storage, Epoch(1), token::Amount::from(5))
        .unwrap();
    redelegated_bonds_map
        .at(&bob)
        .insert(&mut storage, Epoch(4), token::Amount::from(7))
        .unwrap();

    // Test cases 1 and 2
    let mr1 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(25),
    )
    .unwrap();
    let mr2 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(30),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        ..Default::default()
    };

    assert_eq!(mr1, exp_mr);
    assert_eq!(mr2, exp_mr);

    // Test case 3
    let mr3 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(7),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(4)]),
        ..Default::default()
    };
    assert_eq!(mr3, exp_mr);

    // Test case 4
    let mr4 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        token::Amount::from(8),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(1), Epoch(4)]),
        epoch_to_modify: Some(Epoch(1)),
        new_amount: Some(4.into()),
    };
    assert_eq!(mr4, exp_mr);

    // Test case 5
    let mr5 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        12.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([bob.clone()]),
        ..Default::default()
    };
    assert_eq!(mr5, exp_mr);

    // Test case 6
    let mr6 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        14.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: Some(alice.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(4)]),
        epoch_to_modify: Some(Epoch(4)),
        new_amount: Some(5.into()),
    };
    assert_eq!(mr6, exp_mr);

    // Test case 7
    let mr7 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        19.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: Some(alice.clone()),
        epochs_to_remove: BTreeSet::from_iter([Epoch(4)]),
        ..Default::default()
    };
    assert_eq!(mr7, exp_mr);

    // Test case 8
    let mr8 = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map,
        Epoch(5),
        21.into(),
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(5)),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob]),
        validator_to_modify: Some(alice),
        epochs_to_remove: BTreeSet::from_iter([Epoch(2), Epoch(4)]),
        epoch_to_modify: Some(Epoch(2)),
        new_amount: Some(4.into()),
    };
    assert_eq!(mr8, exp_mr);
}

/// `computeBondAtEpochTest`
#[test]
fn test_compute_bond_at_epoch() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        pipeline_len: 2,
        unbonding_len: 4,
        cubic_slashing_window_length: 1,
        ..Default::default()
    };
    let alice = established_address_1();
    let bob = established_address_2();

    // Test 1
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&Default::default()),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 23.into());

    // Test 2
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: 4.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&Default::default()),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());

    // Test 3
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    let mut redel_bonds = EagerRedelegatedBondsMap::default();
    redel_bonds.insert(
        alice.clone(),
        BTreeMap::from_iter([(Epoch(1), token::Amount::from(5))]),
    );
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 23.into());

    // Test 4
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: 4.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());

    // Test 5
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: 6.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        12.into(),
        3.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 23.into());

    // Test 6
    validator_slashes_handle(&alice).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(
            &mut storage,
            Slash {
                epoch: 4.into(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_bond_at_epoch(
        &storage,
        &params,
        &bob,
        18.into(),
        9.into(),
        23.into(),
        Some(&redel_bonds),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 18.into());
}

/// `computeSlashBondAtEpochTest`
#[test]
fn test_compute_slash_bond_at_epoch() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        pipeline_len: 2,
        unbonding_len: 4,
        cubic_slashing_window_length: 1,
        ..Default::default()
    };
    let alice = established_address_1();
    let bob = established_address_2();

    let current_epoch = Epoch(20);
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();

    let redelegated_bond = BTreeMap::from_iter([(
        alice,
        BTreeMap::from_iter([(infraction_epoch - 4, token::Amount::from(10))]),
    )]);

    // Test 1
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&Default::default()),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 30.into());

    // Test 2
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&redelegated_bond),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 30.into());

    // Test 3
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: infraction_epoch.prev(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&Default::default()),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());

    // Test 4
    let res = compute_slash_bond_at_epoch(
        &storage,
        &params,
        &bob,
        current_epoch.next(),
        infraction_epoch,
        infraction_epoch - 2,
        30.into(),
        Some(&redelegated_bond),
        Dec::one(),
    )
    .unwrap();

    pretty_assertions::assert_eq!(res, 0.into());
}

/// `computeNewRedelegatedUnbondsTest`
#[test]
fn test_compute_new_redelegated_unbonds() {
    let mut storage = TestWlStorage::default();
    let alice = established_address_1();
    let bob = established_address_2();

    let key = Key::parse("testing").unwrap();
    let redelegated_bonds = NestedMap::<Epoch, RedelegatedTokens>::open(key);

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
            .insert(&mut storage, inner_ep, token::Amount::from(amount))
            .unwrap();
        eager_map
            .entry(outer_ep)
            .or_default()
            .entry(address.clone())
            .or_default()
            .insert(inner_ep, token::Amount::from(amount));
    }

    // Different ModifiedRedelegation objects for testing
    let empty_mr = ModifiedRedelegation::default();
    let all_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: None,
        epochs_to_remove: Default::default(),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_val_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice.clone()]),
        validator_to_modify: None,
        epochs_to_remove: Default::default(),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_val_partial_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice.clone(), bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([ep1]),
        epoch_to_modify: None,
        new_amount: None,
    };
    let mod_epoch_partial_mr = ModifiedRedelegation {
        epoch: Some(ep7),
        validators_to_remove: BTreeSet::from_iter([alice, bob.clone()]),
        validator_to_modify: Some(bob.clone()),
        epochs_to_remove: BTreeSet::from_iter([ep1, ep4]),
        epoch_to_modify: Some(ep4),
        new_amount: Some(token::Amount::from(1)),
    };

    // Test case 1
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &Default::default(),
        &empty_mr,
    )
    .unwrap();
    assert_eq!(res, Default::default());

    let set5 = BTreeSet::<Epoch>::from_iter([ep5]);
    let set56 = BTreeSet::<Epoch>::from_iter([ep5, ep6]);

    // Test case 2
    let res = compute_new_redelegated_unbonds(
        &storage,
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
        &storage,
        &redelegated_bonds,
        &set56,
        &empty_mr,
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 4
    println!("\nTEST CASE 4\n");
    let res = compute_new_redelegated_unbonds(
        &storage,
        &redelegated_bonds,
        &set56,
        &all_mr,
    )
    .unwrap();
    assert_eq!(res, eager_map);

    // Test case 5
    let res = compute_new_redelegated_unbonds(
        &storage,
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
        &storage,
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
        &storage,
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
        .insert(ep4, token::Amount::from(1));
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

    let res = apply_list_slashes(&params, &[], token::Amount::from(100));
    assert_eq!(res, token::Amount::from(100));

    let res = apply_list_slashes(&params, &list1, token::Amount::from(100));
    assert_eq!(res, token::Amount::zero());

    let res = apply_list_slashes(&params, &list2, token::Amount::from(100));
    assert_eq!(res, token::Amount::zero());

    let res = apply_list_slashes(&params, &list3, token::Amount::from(100));
    assert_eq!(res, token::Amount::zero());

    let res = apply_list_slashes(&params, &list4, token::Amount::from(100));
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

    let test_map = vec![(init_epoch, token::Amount::from(50))]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let res = compute_slashable_amount(
        &params,
        &slash1,
        token::Amount::from(100),
        &BTreeMap::new(),
    );
    assert_eq!(res, token::Amount::from(100));

    let res = compute_slashable_amount(
        &params,
        &slash2,
        token::Amount::from(100),
        &test_map,
    );
    assert_eq!(res, token::Amount::from(50));

    let res = compute_slashable_amount(
        &params,
        &slash1,
        token::Amount::from(100),
        &test_map,
    );
    assert_eq!(res, token::Amount::from(100));
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
                .insert(Epoch(epoch), token::Amount::from(amount));
        }
    }

    // Test case 1
    let res = fold_and_slash_redelegated_bonds(
        &storage,
        &params,
        &eager_redel_bonds,
        start_epoch,
        &[],
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
        start_epoch,
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
        start_epoch,
        &[],
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
        .insert(&mut storage, Epoch(7), token::Amount::from(2))
        .unwrap();

    let slashes = validator_slashes_handle(&alice);

    let mut slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::zero()),
        (Epoch(16), token::Amount::zero()),
    ]);
    let empty_slash_amounts = slashed_amounts_map.clone();

    // Test case 1
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
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
            (Epoch(15), token::Amount::from(5)),
            (Epoch(16), token::Amount::from(5)),
        ])
    );

    // Test case 2
    slashed_amounts_map = empty_slash_amounts.clone();
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
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
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(7)),
        ])
    );

    // Test case 3
    slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::from(2)),
        (Epoch(16), token::Amount::from(3)),
    ]);
    slash_redelegation(
        &storage,
        &params,
        token::Amount::from(7),
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
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(8)),
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
        token::Amount::from(7),
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
        token::Amount::from(7),
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
        token::Amount::from(7),
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
        .insert(&mut storage, Epoch(7), token::Amount::from(2))
        .unwrap();

    let outgoing_redelegations =
        validator_outgoing_redelegations_handle(&alice).at(&bob);

    let slashes = validator_slashes_handle(&alice);

    let mut slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::zero()),
        (Epoch(16), token::Amount::zero()),
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
        .insert(&mut storage, Epoch(7), token::Amount::from(2))
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
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(7)),
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
            (Epoch(15), token::Amount::from(5)),
            (Epoch(16), token::Amount::from(5)),
        ])
    );

    // Test case 5
    slashed_amounts_map = BTreeMap::from_iter([
        (Epoch(15), token::Amount::from(2)),
        (Epoch(16), token::Amount::from(3)),
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
            (Epoch(15), token::Amount::from(7)),
            (Epoch(16), token::Amount::from(8)),
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
    let total_unbonded = total_unbonded_handle(&bob);
    let total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&bob);
    let total_redelegated_unbonded =
        validator_total_redelegated_unbonded_handle(&bob);

    let infraction_stake = token::Amount::from(23);

    let initial_stakes = BTreeMap::from_iter([
        (Epoch(11), infraction_stake),
        (Epoch(12), infraction_stake),
        (Epoch(13), infraction_stake),
    ]);
    let mut exp_res = initial_stakes.clone();

    let current_epoch = Epoch(10);
    let infraction_epoch =
        current_epoch - params.slash_processing_epoch_offset();
    let processing_epoch = current_epoch.next();
    let slash_rate = Dec::one();

    // Test case 1
    println!("\nTEST 1:");

    total_bonded
        .set(&mut storage, 23.into(), infraction_epoch - 2, 0)
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 2
    println!("\nTEST 2:");
    total_bonded
        .set(&mut storage, 17.into(), infraction_epoch - 2, 0)
        .unwrap();
    total_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .insert(&mut storage, infraction_epoch - 2, 6.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res.insert(Epoch(12), 17.into());
    exp_res.insert(Epoch(13), 17.into());
    assert_eq!(res, exp_res);

    // Test case 3
    println!("\nTEST 3:");
    total_redelegated_bonded
        .at(&infraction_epoch.prev())
        .at(&alice)
        .insert(&mut storage, Epoch(2), 5.into())
        .unwrap();
    total_redelegated_bonded
        .at(&infraction_epoch.prev())
        .at(&alice)
        .insert(&mut storage, Epoch(3), 1.into())
        .unwrap();

    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 4
    println!("\nTEST 4:");
    total_unbonded_handle(&bob)
        .at(&(current_epoch + params.pipeline_len))
        .remove(&mut storage, &(infraction_epoch - 2))
        .unwrap();
    total_unbonded_handle(&bob)
        .at(&(current_epoch + params.pipeline_len))
        .insert(&mut storage, infraction_epoch - 1, 6.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev())
        .at(&alice)
        .insert(&mut storage, Epoch(2), 5.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev())
        .at(&alice)
        .insert(&mut storage, Epoch(3), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 5
    println!("\nTEST 5:");
    total_bonded_handle(&bob)
        .set(&mut storage, 19.into(), infraction_epoch - 2, 0)
        .unwrap();
    total_unbonded_handle(&bob)
        .at(&(current_epoch + params.pipeline_len))
        .insert(&mut storage, infraction_epoch - 1, 4.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, Epoch(2), token::Amount::from(1))
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev())
        .at(&alice)
        .remove(&mut storage, &Epoch(3))
        .unwrap();
    total_redelegated_unbonded
        .at(&(current_epoch + params.pipeline_len))
        .at(&infraction_epoch.prev())
        .at(&alice)
        .insert(&mut storage, Epoch(2), 4.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res.insert(Epoch(12), 19.into());
    exp_res.insert(Epoch(13), 19.into());
    assert_eq!(res, exp_res);

    // Test case 6
    println!("\nTEST 6:");
    total_unbonded_handle(&bob)
        .remove_all(&mut storage, &(current_epoch + params.pipeline_len))
        .unwrap();
    total_redelegated_unbonded
        .remove_all(&mut storage, &(current_epoch + params.pipeline_len))
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_bonded_handle(&bob)
        .set(&mut storage, 23.into(), infraction_epoch - 2, 0)
        .unwrap();
    total_bonded_handle(&bob)
        .set(&mut storage, 6.into(), current_epoch, 0)
        .unwrap();

    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res = initial_stakes;
    assert_eq!(res, exp_res);

    // Test case 7
    println!("\nTEST 7:");
    total_bonded
        .get_data_handler()
        .remove(&mut storage, &current_epoch)
        .unwrap();
    total_unbonded
        .at(&current_epoch.next())
        .insert(&mut storage, current_epoch, 6.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 8
    println!("\nTEST 8:");
    total_bonded
        .get_data_handler()
        .insert(&mut storage, current_epoch, 3.into())
        .unwrap();
    total_unbonded
        .at(&current_epoch.next())
        .insert(&mut storage, current_epoch, 3.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 9
    println!("\nTEST 9:");
    total_unbonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    total_bonded
        .set(&mut storage, 6.into(), current_epoch, 0)
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 5.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 10
    println!("\nTEST 10:");
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_bonded
        .get_data_handler()
        .remove(&mut storage, &current_epoch)
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 5.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 11
    println!("\nTEST 11:");
    total_bonded
        .set(&mut storage, 2.into(), current_epoch, 0)
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 4.into())
        .unwrap();
    total_redelegated_unbonded
        .at(&current_epoch.next())
        .at(&current_epoch)
        .at(&alice)
        .remove(&mut storage, &3.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 2.into(), 1.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch)
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 12
    println!("\nTEST 12:");
    total_bonded
        .set(&mut storage, 6.into(), current_epoch, 0)
        .unwrap();
    total_bonded
        .set(&mut storage, 2.into(), current_epoch.next(), 0)
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch)
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch.next())
        .at(&alice)
        .insert(&mut storage, 2.into(), 1.into())
        .unwrap();
    total_redelegated_bonded
        .at(&current_epoch.next())
        .at(&alice)
        .insert(&mut storage, 3.into(), 1.into())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(res, exp_res);

    // Test case 13
    println!("\nTEST 13:");
    validator_slashes_handle(&bob)
        .push(
            &mut storage,
            Slash {
                epoch: infraction_epoch.prev(),
                block_height: 0,
                r#type: SlashType::DuplicateVote,
                rate: Dec::one(),
            },
        )
        .unwrap();
    total_redelegated_unbonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    total_bonded
        .get_data_handler()
        .remove(&mut storage, &current_epoch.next())
        .unwrap();
    total_redelegated_bonded
        .remove_all(&mut storage, &current_epoch.next())
        .unwrap();
    let res = slash_validator(
        &storage,
        &params,
        &bob,
        slash_rate,
        processing_epoch,
        &Default::default(),
    )
    .unwrap();
    exp_res.insert(Epoch(11), 0.into());
    exp_res.insert(Epoch(12), 0.into());
    exp_res.insert(Epoch(13), 0.into());
    assert_eq!(res, exp_res);
}

/// `computeAmountAfterSlashingUnbondTest`
#[test]
fn compute_amount_after_slashing_unbond_test() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Test data
    let alice = established_address_1();
    let bob = established_address_2();
    let unbonds: BTreeMap<Epoch, token::Amount> = BTreeMap::from_iter([
        ((Epoch(2)), token::Amount::from(5)),
        ((Epoch(4)), token::Amount::from(6)),
    ]);
    let redelegated_unbonds: EagerRedelegatedUnbonds = BTreeMap::from_iter([(
        Epoch(2),
        BTreeMap::from_iter([(
            alice.clone(),
            BTreeMap::from_iter([(Epoch(1), token::Amount::from(1))]),
        )]),
    )]);

    // Test case 1
    let slashes = vec![];
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 2
    let bob_slash = Slash {
        epoch: Epoch(5),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![bob_slash.clone()];
    validator_slashes_handle(&bob)
        .push(&mut storage, bob_slash)
        .unwrap();
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 0.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 0.into()), (4.into(), 0.into())],
    );

    // Test case 3
    let alice_slash = Slash {
        epoch: Epoch(0),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 4
    let alice_slash = Slash {
        epoch: Epoch(1),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    let result = compute_amount_after_slashing_unbond(
        &storage,
        &params,
        &unbonds,
        &redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 10.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 4.into()), (4.into(), 6.into())],
    );
}

/// `computeAmountAfterSlashingWithdrawTest`
#[test]
fn compute_amount_after_slashing_withdraw_test() {
    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Test data
    let alice = established_address_1();
    let bob = established_address_2();
    let unbonds_and_redelegated_unbonds: BTreeMap<
        (Epoch, Epoch),
        (token::Amount, EagerRedelegatedBondsMap),
    > = BTreeMap::from_iter([
        (
            (Epoch(2), Epoch(20)),
            (
                // unbond
                token::Amount::from(5),
                // redelegations
                BTreeMap::from_iter([(
                    alice.clone(),
                    BTreeMap::from_iter([(Epoch(1), token::Amount::from(1))]),
                )]),
            ),
        ),
        (
            (Epoch(4), Epoch(20)),
            (
                // unbond
                token::Amount::from(6),
                // redelegations
                BTreeMap::default(),
            ),
        ),
    ]);

    // Test case 1
    let slashes = vec![];
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 2
    let bob_slash = Slash {
        epoch: Epoch(5),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![bob_slash.clone()];
    validator_slashes_handle(&bob)
        .push(&mut storage, bob_slash)
        .unwrap();
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 0.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 0.into()), (4.into(), 0.into())],
    );

    // Test case 3
    let alice_slash = Slash {
        epoch: Epoch(0),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    validator_slashes_handle(&bob).pop(&mut storage).unwrap();
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 11.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 5.into()), (4.into(), 6.into())],
    );

    // Test case 4
    let alice_slash = Slash {
        epoch: Epoch(1),
        block_height: Default::default(),
        r#type: SlashType::DuplicateVote,
        rate: Dec::one(),
    };
    let slashes = vec![alice_slash.clone()];
    validator_slashes_handle(&alice).pop(&mut storage).unwrap();
    validator_slashes_handle(&alice)
        .push(&mut storage, alice_slash)
        .unwrap();
    let result = compute_amount_after_slashing_withdraw(
        &storage,
        &params,
        &unbonds_and_redelegated_unbonds,
        slashes,
    )
    .unwrap();
    assert_eq!(result.sum, 10.into());
    itertools::assert_equal(
        result.epoch_map,
        [(2.into(), 4.into()), (4.into(), 6.into())],
    );
}

fn arb_redelegation_amounts(
    max_delegation: u64,
) -> impl Strategy<Value = (token::Amount, token::Amount, token::Amount)> {
    let arb_delegation = arb_amount_non_zero_ceiled(max_delegation);
    let amounts = arb_delegation.prop_flat_map(move |amount_delegate| {
        let amount_redelegate = arb_amount_non_zero_ceiled(max(
            1,
            u64::try_from(amount_delegate.raw_amount()).unwrap() - 1,
        ));
        (Just(amount_delegate), amount_redelegate)
    });
    amounts.prop_flat_map(move |(amount_delegate, amount_redelegate)| {
        let amount_unbond = arb_amount_non_zero_ceiled(max(
            1,
            u64::try_from(amount_redelegate.raw_amount()).unwrap() - 1,
        ));
        (
            Just(amount_delegate),
            Just(amount_redelegate),
            amount_unbond,
        )
    })
}

fn test_simple_redelegation_aux(
    mut validators: Vec<GenesisValidator>,
    amount_delegate: token::Amount,
    amount_redelegate: token::Amount,
    amount_unbond: token::Amount,
) {
    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let src_validator = validators[0].address.clone();
    let dest_validator = validators[1].address.clone();

    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Genesis
    let mut current_epoch = storage.storage.block.epoch;
    init_genesis(
        &mut storage,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    storage.commit_block().unwrap();

    // Get a delegator with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator = address::testing::gen_implicit_address();
    let del_balance = token::Amount::from_uint(1_000_000, 0).unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator, del_balance)
        .unwrap();

    // Ensure that we cannot redelegate with the same src and dest validator
    let err = super::redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &src_validator,
        current_epoch,
        amount_redelegate,
    )
    .unwrap_err();
    let err_str = err.to_string();
    assert_matches!(
        err.downcast::<RedelegationError>().unwrap().deref(),
        RedelegationError::RedelegationSrcEqDest,
        "Redelegation with the same src and dest validator must be rejected, \
         got {err_str}",
    );

    for _ in 0..5 {
        current_epoch = advance_epoch(&mut storage, &params);
        super::process_slashes(&mut storage, current_epoch).unwrap();
    }

    let init_epoch = current_epoch;

    // Delegate in epoch 1 to src_validator
    println!(
        "\nBONDING {} TOKENS TO {}\n",
        amount_delegate.to_string_native(),
        &src_validator
    );
    super::bond_tokens(
        &mut storage,
        Some(&delegator),
        &src_validator,
        amount_delegate,
        current_epoch,
    )
    .unwrap();

    println!("\nAFTER DELEGATION\n");
    let bonds = bond_handle(&delegator, &src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let bonds_dest = bond_handle(&delegator, &dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let unbonds = unbond_handle(&delegator, &src_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_bonds = total_bonded_handle(&src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds = total_unbonded_handle(&src_validator)
        .collect_map(&storage)
        .unwrap();
    dbg!(&bonds, &bonds_dest, &unbonds, &tot_bonds, &tot_unbonds);

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    // Redelegate in epoch 3
    println!(
        "\nREDELEGATING {} TOKENS TO {}\n",
        amount_redelegate.to_string_native(),
        &dest_validator
    );

    super::redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &dest_validator,
        current_epoch,
        amount_redelegate,
    )
    .unwrap();

    println!("\nAFTER REDELEGATION\n");
    println!("\nDELEGATOR\n");
    let bonds_src = bond_handle(&delegator, &src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let bonds_dest = bond_handle(&delegator, &dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let unbonds_src = unbond_handle(&delegator, &src_validator)
        .collect_map(&storage)
        .unwrap();
    let unbonds_dest = unbond_handle(&delegator, &dest_validator)
        .collect_map(&storage)
        .unwrap();
    let redel_bonds = delegator_redelegated_bonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();
    let redel_unbonds = delegator_redelegated_unbonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();

    dbg!(
        &bonds_src,
        &bonds_dest,
        &unbonds_src,
        &unbonds_dest,
        &redel_bonds,
        &redel_unbonds
    );

    // Dest val
    println!("\nDEST VALIDATOR\n");

    let incoming_redels_dest =
        validator_incoming_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let outgoing_redels_dest =
        validator_outgoing_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_bonds_dest = total_bonded_handle(&dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds_dest = total_unbonded_handle(&dest_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_redel_bonds_dest =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_redel_unbonds_dest =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    dbg!(
        &incoming_redels_dest,
        &outgoing_redels_dest,
        &tot_bonds_dest,
        &tot_unbonds_dest,
        &tot_redel_bonds_dest,
        &tot_redel_unbonds_dest
    );

    // Src val
    println!("\nSRC VALIDATOR\n");

    let incoming_redels_src =
        validator_incoming_redelegations_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    let outgoing_redels_src =
        validator_outgoing_redelegations_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_bonds_src = total_bonded_handle(&src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds_src = total_unbonded_handle(&src_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_redel_bonds_src =
        validator_total_redelegated_bonded_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_redel_unbonds_src =
        validator_total_redelegated_unbonded_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    dbg!(
        &incoming_redels_src,
        &outgoing_redels_src,
        &tot_bonds_src,
        &tot_unbonds_src,
        &tot_redel_bonds_src,
        &tot_redel_unbonds_src
    );

    // Checks
    let redelegated = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&(current_epoch + params.pipeline_len))
        .at(&src_validator)
        .get(&storage, &(init_epoch + params.pipeline_len))
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    let redel_start_epoch =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap()
            .unwrap();
    assert_eq!(redel_start_epoch, current_epoch + params.pipeline_len);

    let redelegated = validator_outgoing_redelegations_handle(&src_validator)
        .at(&dest_validator)
        .at(&current_epoch.prev())
        .get(&storage, &current_epoch)
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    // Unbond in epoch 5 from dest_validator
    println!(
        "\nUNBONDING {} TOKENS FROM {}\n",
        amount_unbond.to_string_native(),
        &dest_validator
    );
    let _ = unbond_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        amount_unbond,
        current_epoch,
        false,
    )
    .unwrap();

    println!("\nAFTER UNBONDING\n");
    println!("\nDELEGATOR\n");

    let bonds_src = bond_handle(&delegator, &src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let bonds_dest = bond_handle(&delegator, &dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let unbonds_src = unbond_handle(&delegator, &src_validator)
        .collect_map(&storage)
        .unwrap();
    let unbonds_dest = unbond_handle(&delegator, &dest_validator)
        .collect_map(&storage)
        .unwrap();
    let redel_bonds = delegator_redelegated_bonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();
    let redel_unbonds = delegator_redelegated_unbonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();

    dbg!(
        &bonds_src,
        &bonds_dest,
        &unbonds_src,
        &unbonds_dest,
        &redel_bonds,
        &redel_unbonds
    );

    println!("\nDEST VALIDATOR\n");

    let incoming_redels_dest =
        validator_incoming_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let outgoing_redels_dest =
        validator_outgoing_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_bonds_dest = total_bonded_handle(&dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds_dest = total_unbonded_handle(&dest_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_redel_bonds_dest =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_redel_unbonds_dest =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    dbg!(
        &incoming_redels_dest,
        &outgoing_redels_dest,
        &tot_bonds_dest,
        &tot_unbonds_dest,
        &tot_redel_bonds_dest,
        &tot_redel_unbonds_dest
    );

    let bond_start = init_epoch + params.pipeline_len;
    let redelegation_end = bond_start + params.pipeline_len + 1u64;
    let unbond_end =
        redelegation_end + params.withdrawable_epoch_offset() + 1u64;
    let unbond_materialized = redelegation_end + params.pipeline_len + 1u64;

    // Checks
    let redelegated_remaining = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(redelegated_remaining, amount_redelegate - amount_unbond);

    let redel_unbonded = delegator_redelegated_unbonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&unbond_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap();
    assert_eq!(redel_unbonded, amount_unbond);

    dbg!(unbond_materialized, redelegation_end, bond_start);
    let total_redel_unbonded =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .at(&unbond_materialized)
            .at(&redelegation_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap();
    assert_eq!(total_redel_unbonded, amount_unbond);

    // Advance to withdrawal epoch
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        super::process_slashes(&mut storage, current_epoch).unwrap();
        if current_epoch == unbond_end {
            break;
        }
    }

    // Withdraw
    withdraw_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        current_epoch,
    )
    .unwrap();

    assert!(
        delegator_redelegated_unbonds_handle(&delegator)
            .at(&dest_validator)
            .is_empty(&storage)
            .unwrap()
    );

    let delegator_balance = storage
        .read::<token::Amount>(&token::balance_key(&staking_token, &delegator))
        .unwrap()
        .unwrap_or_default();
    assert_eq!(
        delegator_balance,
        del_balance - amount_delegate + amount_unbond
    );
}

fn test_redelegation_with_slashing_aux(
    mut validators: Vec<GenesisValidator>,
    amount_delegate: token::Amount,
    amount_redelegate: token::Amount,
    amount_unbond: token::Amount,
) {
    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let src_validator = validators[0].address.clone();
    let dest_validator = validators[1].address.clone();

    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        // Avoid empty consensus set by removing the threshold
        validator_stake_threshold: token::Amount::zero(),
        ..Default::default()
    };

    // Genesis
    let mut current_epoch = storage.storage.block.epoch;
    init_genesis(
        &mut storage,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    storage.commit_block().unwrap();

    // Get a delegator with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator = address::testing::gen_implicit_address();
    let del_balance = token::Amount::from_uint(1_000_000, 0).unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator, del_balance)
        .unwrap();

    for _ in 0..5 {
        current_epoch = advance_epoch(&mut storage, &params);
        super::process_slashes(&mut storage, current_epoch).unwrap();
    }

    let init_epoch = current_epoch;

    // Delegate in epoch 5 to src_validator
    println!(
        "\nBONDING {} TOKENS TO {}\n",
        amount_delegate.to_string_native(),
        &src_validator
    );
    super::bond_tokens(
        &mut storage,
        Some(&delegator),
        &src_validator,
        amount_delegate,
        current_epoch,
    )
    .unwrap();

    println!("\nAFTER DELEGATION\n");
    let bonds = bond_handle(&delegator, &src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let bonds_dest = bond_handle(&delegator, &dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let unbonds = unbond_handle(&delegator, &src_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_bonds = total_bonded_handle(&src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds = total_unbonded_handle(&src_validator)
        .collect_map(&storage)
        .unwrap();
    dbg!(&bonds, &bonds_dest, &unbonds, &tot_bonds, &tot_unbonds);

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    // Redelegate in epoch 8
    println!(
        "\nREDELEGATING {} TOKENS TO {}\n",
        amount_redelegate.to_string_native(),
        &dest_validator
    );

    super::redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &dest_validator,
        current_epoch,
        amount_redelegate,
    )
    .unwrap();

    println!("\nAFTER REDELEGATION\n");
    println!("\nDELEGATOR\n");
    let bonds_src = bond_handle(&delegator, &src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let bonds_dest = bond_handle(&delegator, &dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let unbonds_src = unbond_handle(&delegator, &src_validator)
        .collect_map(&storage)
        .unwrap();
    let unbonds_dest = unbond_handle(&delegator, &dest_validator)
        .collect_map(&storage)
        .unwrap();
    let redel_bonds = delegator_redelegated_bonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();
    let redel_unbonds = delegator_redelegated_unbonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();

    dbg!(
        &bonds_src,
        &bonds_dest,
        &unbonds_src,
        &unbonds_dest,
        &redel_bonds,
        &redel_unbonds
    );

    // Dest val
    println!("\nDEST VALIDATOR\n");

    let incoming_redels_dest =
        validator_incoming_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let outgoing_redels_dest =
        validator_outgoing_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_bonds_dest = total_bonded_handle(&dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds_dest = total_unbonded_handle(&dest_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_redel_bonds_dest =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_redel_unbonds_dest =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    dbg!(
        &incoming_redels_dest,
        &outgoing_redels_dest,
        &tot_bonds_dest,
        &tot_unbonds_dest,
        &tot_redel_bonds_dest,
        &tot_redel_unbonds_dest
    );

    // Src val
    println!("\nSRC VALIDATOR\n");

    let incoming_redels_src =
        validator_incoming_redelegations_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    let outgoing_redels_src =
        validator_outgoing_redelegations_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_bonds_src = total_bonded_handle(&src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds_src = total_unbonded_handle(&src_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_redel_bonds_src =
        validator_total_redelegated_bonded_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_redel_unbonds_src =
        validator_total_redelegated_unbonded_handle(&src_validator)
            .collect_map(&storage)
            .unwrap();
    dbg!(
        &incoming_redels_src,
        &outgoing_redels_src,
        &tot_bonds_src,
        &tot_unbonds_src,
        &tot_redel_bonds_src,
        &tot_redel_unbonds_src
    );

    // Checks
    let redelegated = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&(current_epoch + params.pipeline_len))
        .at(&src_validator)
        .get(&storage, &(init_epoch + params.pipeline_len))
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    let redel_start_epoch =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap()
            .unwrap();
    assert_eq!(redel_start_epoch, current_epoch + params.pipeline_len);

    let redelegated = validator_outgoing_redelegations_handle(&src_validator)
        .at(&dest_validator)
        .at(&current_epoch.prev())
        .get(&storage, &current_epoch)
        .unwrap()
        .unwrap();
    assert_eq!(redelegated, amount_redelegate);

    // Advance three epochs
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    // Unbond in epoch 11 from dest_validator
    println!(
        "\nUNBONDING {} TOKENS FROM {}\n",
        amount_unbond.to_string_native(),
        &dest_validator
    );
    let _ = unbond_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        amount_unbond,
        current_epoch,
        false,
    )
    .unwrap();

    println!("\nAFTER UNBONDING\n");
    println!("\nDELEGATOR\n");

    let bonds_src = bond_handle(&delegator, &src_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let bonds_dest = bond_handle(&delegator, &dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let unbonds_src = unbond_handle(&delegator, &src_validator)
        .collect_map(&storage)
        .unwrap();
    let unbonds_dest = unbond_handle(&delegator, &dest_validator)
        .collect_map(&storage)
        .unwrap();
    let redel_bonds = delegator_redelegated_bonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();
    let redel_unbonds = delegator_redelegated_unbonds_handle(&delegator)
        .collect_map(&storage)
        .unwrap();

    dbg!(
        &bonds_src,
        &bonds_dest,
        &unbonds_src,
        &unbonds_dest,
        &redel_bonds,
        &redel_unbonds
    );

    println!("\nDEST VALIDATOR\n");

    let incoming_redels_dest =
        validator_incoming_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let outgoing_redels_dest =
        validator_outgoing_redelegations_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_bonds_dest = total_bonded_handle(&dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    let tot_unbonds_dest = total_unbonded_handle(&dest_validator)
        .collect_map(&storage)
        .unwrap();
    let tot_redel_bonds_dest =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    let tot_redel_unbonds_dest =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .collect_map(&storage)
            .unwrap();
    dbg!(
        &incoming_redels_dest,
        &outgoing_redels_dest,
        &tot_bonds_dest,
        &tot_unbonds_dest,
        &tot_redel_bonds_dest,
        &tot_redel_unbonds_dest
    );

    // Advance one epoch
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    // Discover evidence
    slash(
        &mut storage,
        &params,
        current_epoch,
        init_epoch + 2 * params.pipeline_len,
        0u64,
        SlashType::DuplicateVote,
        &src_validator,
        current_epoch.next(),
    )
    .unwrap();

    let bond_start = init_epoch + params.pipeline_len;
    let redelegation_end = bond_start + params.pipeline_len + 1u64;
    let unbond_end =
        redelegation_end + params.withdrawable_epoch_offset() + 1u64;
    let unbond_materialized = redelegation_end + params.pipeline_len + 1u64;

    // Checks
    let redelegated_remaining = delegator_redelegated_bonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(redelegated_remaining, amount_redelegate - amount_unbond);

    let redel_unbonded = delegator_redelegated_unbonds_handle(&delegator)
        .at(&dest_validator)
        .at(&redelegation_end)
        .at(&unbond_end)
        .at(&src_validator)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap();
    assert_eq!(redel_unbonded, amount_unbond);

    dbg!(unbond_materialized, redelegation_end, bond_start);
    let total_redel_unbonded =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .at(&unbond_materialized)
            .at(&redelegation_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap();
    assert_eq!(total_redel_unbonded, amount_unbond);

    // Advance to withdrawal epoch
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        super::process_slashes(&mut storage, current_epoch).unwrap();
        if current_epoch == unbond_end {
            break;
        }
    }

    // Withdraw
    withdraw_tokens(
        &mut storage,
        Some(&delegator),
        &dest_validator,
        current_epoch,
    )
    .unwrap();

    assert!(
        delegator_redelegated_unbonds_handle(&delegator)
            .at(&dest_validator)
            .is_empty(&storage)
            .unwrap()
    );

    let delegator_balance = storage
        .read::<token::Amount>(&token::balance_key(&staking_token, &delegator))
        .unwrap()
        .unwrap_or_default();
    assert_eq!(delegator_balance, del_balance - amount_delegate);
}

fn test_chain_redelegations_aux(mut validators: Vec<GenesisValidator>) {
    validators.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let src_validator = validators[0].address.clone();
    let _init_stake_src = validators[0].tokens;
    let dest_validator = validators[1].address.clone();
    let _init_stake_dest = validators[1].tokens;
    let dest_validator_2 = validators[2].address.clone();
    let _init_stake_dest_2 = validators[2].tokens;

    let mut storage = TestWlStorage::default();
    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    // Genesis
    let mut current_epoch = storage.storage.block.epoch;
    init_genesis(
        &mut storage,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    storage.commit_block().unwrap();

    // Get a delegator with some tokens
    let staking_token = staking_token_address(&storage);
    let delegator = address::testing::gen_implicit_address();
    let del_balance = token::Amount::from_uint(1_000_000, 0).unwrap();
    credit_tokens(&mut storage, &staking_token, &delegator, del_balance)
        .unwrap();

    // Delegate in epoch 0 to src_validator
    let bond_amount: token::Amount = 100.into();
    super::bond_tokens(
        &mut storage,
        Some(&delegator),
        &src_validator,
        bond_amount,
        current_epoch,
    )
    .unwrap();

    let bond_start = current_epoch + params.pipeline_len;

    // Advance one epoch
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    // Redelegate in epoch 1 to dest_validator
    let redel_amount_1: token::Amount = 58.into();
    super::redelegate_tokens(
        &mut storage,
        &delegator,
        &src_validator,
        &dest_validator,
        current_epoch,
        redel_amount_1,
    )
    .unwrap();

    let redel_start = current_epoch;
    let redel_end = current_epoch + params.pipeline_len;

    // Checks ----------------

    // Dest validator should have an incoming redelegation
    let incoming_redelegation =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap();
    assert_eq!(incoming_redelegation, Some(redel_end));

    // Src validator should have an outoging redelegation
    let outgoing_redelegation =
        validator_outgoing_redelegations_handle(&src_validator)
            .at(&dest_validator)
            .at(&bond_start)
            .get(&storage, &redel_start)
            .unwrap();
    assert_eq!(outgoing_redelegation, Some(redel_amount_1));

    // Delegator should have redelegated bonds
    let del_total_redelegated_bonded =
        delegator_redelegated_bonds_handle(&delegator)
            .at(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(del_total_redelegated_bonded, redel_amount_1);

    // There should be delegator bonds for both src and dest validators
    let bonded_src = bond_handle(&delegator, &src_validator);
    let bonded_dest = bond_handle(&delegator, &dest_validator);
    assert_eq!(
        bonded_src
            .get_delta_val(&storage, bond_start)
            .unwrap()
            .unwrap_or_default(),
        bond_amount - redel_amount_1
    );
    assert_eq!(
        bonded_dest
            .get_delta_val(&storage, redel_end)
            .unwrap()
            .unwrap_or_default(),
        redel_amount_1
    );

    // The dest validator should have total redelegated bonded tokens
    let dest_total_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(dest_total_redelegated_bonded, redel_amount_1);

    // The dest validator's total bonded should have an entry for the genesis
    // bond and the redelegation
    let dest_total_bonded = total_bonded_handle(&dest_validator)
        .get_data_handler()
        .collect_map(&storage)
        .unwrap();
    assert!(
        dest_total_bonded.len() == 2
            && dest_total_bonded.contains_key(&Epoch::default())
    );
    assert_eq!(
        dest_total_bonded
            .get(&redel_end)
            .cloned()
            .unwrap_or_default(),
        redel_amount_1
    );

    // The src validator should have a total bonded entry for the original bond
    // accounting for the redelegation
    assert_eq!(
        total_bonded_handle(&src_validator)
            .get_delta_val(&storage, bond_start)
            .unwrap()
            .unwrap_or_default(),
        bond_amount - redel_amount_1
    );

    // The src validator should have a total unbonded entry due to the
    // redelegation
    let src_total_unbonded = total_unbonded_handle(&src_validator)
        .at(&redel_end)
        .get(&storage, &bond_start)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(src_total_unbonded, redel_amount_1);

    // Attempt to redelegate in epoch 3 to dest_validator
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    let redel_amount_2: token::Amount = 23.into();
    let redel_att = super::redelegate_tokens(
        &mut storage,
        &delegator,
        &dest_validator,
        &dest_validator_2,
        current_epoch,
        redel_amount_2,
    );
    assert!(redel_att.is_err());

    // Advance to right before the redelegation can be redelegated again
    assert_eq!(redel_end, current_epoch);
    let epoch_can_redel =
        redel_end.prev() + params.slash_processing_epoch_offset();
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        super::process_slashes(&mut storage, current_epoch).unwrap();
        if current_epoch == epoch_can_redel.prev() {
            break;
        }
    }

    // Attempt to redelegate in epoch before we actually are able to
    let redel_att = super::redelegate_tokens(
        &mut storage,
        &delegator,
        &dest_validator,
        &dest_validator_2,
        current_epoch,
        redel_amount_2,
    );
    assert!(redel_att.is_err());

    // Advance one more epoch
    current_epoch = advance_epoch(&mut storage, &params);
    super::process_slashes(&mut storage, current_epoch).unwrap();

    // Redelegate from dest_validator to dest_validator_2 now
    super::redelegate_tokens(
        &mut storage,
        &delegator,
        &dest_validator,
        &dest_validator_2,
        current_epoch,
        redel_amount_2,
    )
    .unwrap();

    let redel_2_start = current_epoch;
    let redel_2_end = current_epoch + params.pipeline_len;

    // Checks -----------------------------------

    // Both the dest validator and dest validator 2 should have incoming
    // redelegations
    let incoming_redelegation_1 =
        validator_incoming_redelegations_handle(&dest_validator)
            .get(&storage, &delegator)
            .unwrap();
    assert_eq!(incoming_redelegation_1, Some(redel_end));
    let incoming_redelegation_2 =
        validator_incoming_redelegations_handle(&dest_validator_2)
            .get(&storage, &delegator)
            .unwrap();
    assert_eq!(incoming_redelegation_2, Some(redel_2_end));

    // Both the src validator and dest validator should have outgoing
    // redelegations
    let outgoing_redelegation_1 =
        validator_outgoing_redelegations_handle(&src_validator)
            .at(&dest_validator)
            .at(&bond_start)
            .get(&storage, &redel_start)
            .unwrap();
    assert_eq!(outgoing_redelegation_1, Some(redel_amount_1));

    let outgoing_redelegation_2 =
        validator_outgoing_redelegations_handle(&dest_validator)
            .at(&dest_validator_2)
            .at(&redel_end)
            .get(&storage, &redel_2_start)
            .unwrap();
    assert_eq!(outgoing_redelegation_2, Some(redel_amount_2));

    // All three validators should have bonds
    let bonded_dest2 = bond_handle(&delegator, &dest_validator_2);
    assert_eq!(
        bonded_src
            .get_delta_val(&storage, bond_start)
            .unwrap()
            .unwrap_or_default(),
        bond_amount - redel_amount_1
    );
    assert_eq!(
        bonded_dest
            .get_delta_val(&storage, redel_end)
            .unwrap()
            .unwrap_or_default(),
        redel_amount_1 - redel_amount_2
    );
    assert_eq!(
        bonded_dest2
            .get_delta_val(&storage, redel_2_end)
            .unwrap()
            .unwrap_or_default(),
        redel_amount_2
    );

    // There should be no unbond entries
    let unbond_src = unbond_handle(&delegator, &src_validator);
    let unbond_dest = unbond_handle(&delegator, &dest_validator);
    assert!(unbond_src.is_empty(&storage).unwrap());
    assert!(unbond_dest.is_empty(&storage).unwrap());

    // The dest validator should have some total unbonded due to the second
    // redelegation
    let dest_total_unbonded = total_unbonded_handle(&dest_validator)
        .at(&redel_2_end)
        .get(&storage, &redel_end)
        .unwrap();
    assert_eq!(dest_total_unbonded, Some(redel_amount_2));

    // Delegator should have redelegated bonds due to both redelegations
    let del_redelegated_bonds = delegator_redelegated_bonds_handle(&delegator);
    assert_eq!(
        Some(redel_amount_1 - redel_amount_2),
        del_redelegated_bonds
            .at(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
    );
    assert_eq!(
        Some(redel_amount_2),
        del_redelegated_bonds
            .at(&dest_validator_2)
            .at(&redel_2_end)
            .at(&dest_validator)
            .get(&storage, &redel_end)
            .unwrap()
    );

    // Delegator redelegated unbonds should be empty
    assert!(
        delegator_redelegated_unbonds_handle(&delegator)
            .is_empty(&storage)
            .unwrap()
    );

    // Both the dest validator and dest validator 2 should have total
    // redelegated bonds
    let dest_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&dest_validator)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    let dest2_redelegated_bonded =
        validator_total_redelegated_bonded_handle(&dest_validator_2)
            .at(&redel_2_end)
            .at(&dest_validator)
            .get(&storage, &redel_end)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(dest_redelegated_bonded, redel_amount_1 - redel_amount_2);
    assert_eq!(dest2_redelegated_bonded, redel_amount_2);

    // Total redelegated unbonded should be empty for src_validator and
    // dest_validator_2
    assert!(
        validator_total_redelegated_unbonded_handle(&dest_validator_2)
            .is_empty(&storage)
            .unwrap()
    );
    assert!(
        validator_total_redelegated_unbonded_handle(&src_validator)
            .is_empty(&storage)
            .unwrap()
    );

    // The dest_validator should have total_redelegated unbonded
    let tot_redel_unbonded =
        validator_total_redelegated_unbonded_handle(&dest_validator)
            .at(&redel_2_end)
            .at(&redel_end)
            .at(&src_validator)
            .get(&storage, &bond_start)
            .unwrap()
            .unwrap_or_default();
    assert_eq!(tot_redel_unbonded, redel_amount_2);
}

/// SM test case 1 from Brent
#[test]
fn test_from_sm_case_1() {
    use namada_core::types::address::testing::established_address_4;

    let mut storage = TestWlStorage::default();
    let validator = established_address_1();
    let redeleg_src_1 = established_address_2();
    let redeleg_src_2 = established_address_3();
    let owner = established_address_4();
    let unbond_amount = token::Amount::from(3130688);
    println!(
        "Owner: {owner}\nValidator: {validator}\nRedeleg src 1: \
         {redeleg_src_1}\nRedeleg src 2: {redeleg_src_2}"
    );

    // Validator's incoming redelegations
    let outer_epoch_1 = Epoch(27);
    // from redeleg_src_1
    let epoch_1_redeleg_1 = token::Amount::from(8516);
    // from redeleg_src_2
    let epoch_1_redeleg_2 = token::Amount::from(5704386);
    let outer_epoch_2 = Epoch(30);
    // from redeleg_src_2
    let epoch_2_redeleg_2 = token::Amount::from(1035191);

    // Insert the data - bonds and redelegated bonds
    let bonds_handle = bond_handle(&owner, &validator);
    bonds_handle
        .add(
            &mut storage,
            epoch_1_redeleg_1 + epoch_1_redeleg_2,
            outer_epoch_1,
            0,
        )
        .unwrap();
    bonds_handle
        .add(&mut storage, epoch_2_redeleg_2, outer_epoch_2, 0)
        .unwrap();

    let redelegated_bonds_map_1 = delegator_redelegated_bonds_handle(&owner)
        .at(&validator)
        .at(&outer_epoch_1);
    redelegated_bonds_map_1
        .at(&redeleg_src_1)
        .insert(&mut storage, Epoch(14), epoch_1_redeleg_1)
        .unwrap();
    redelegated_bonds_map_1
        .at(&redeleg_src_2)
        .insert(&mut storage, Epoch(18), epoch_1_redeleg_2)
        .unwrap();
    let redelegated_bonds_map_1 = delegator_redelegated_bonds_handle(&owner)
        .at(&validator)
        .at(&outer_epoch_1);

    let redelegated_bonds_map_2 = delegator_redelegated_bonds_handle(&owner)
        .at(&validator)
        .at(&outer_epoch_2);
    redelegated_bonds_map_2
        .at(&redeleg_src_2)
        .insert(&mut storage, Epoch(18), epoch_2_redeleg_2)
        .unwrap();

    // Find the modified redelegation the same way as `unbond_tokens`
    let bonds_to_unbond = find_bonds_to_remove(
        &storage,
        &bonds_handle.get_data_handler(),
        unbond_amount,
    )
    .unwrap();
    dbg!(&bonds_to_unbond);

    let (new_entry_epoch, new_bond_amount) = bonds_to_unbond.new_entry.unwrap();
    assert_eq!(outer_epoch_1, new_entry_epoch);
    // The modified bond should be sum of all redelegations less the unbonded
    // amouunt
    assert_eq!(
        epoch_1_redeleg_1 + epoch_1_redeleg_2 + epoch_2_redeleg_2
            - unbond_amount,
        new_bond_amount
    );
    // The current bond should be sum of redelegations fom the modified epoch
    let cur_bond_amount = bonds_handle
        .get_delta_val(&storage, new_entry_epoch)
        .unwrap()
        .unwrap_or_default();
    assert_eq!(epoch_1_redeleg_1 + epoch_1_redeleg_2, cur_bond_amount);

    let mr = compute_modified_redelegation(
        &storage,
        &redelegated_bonds_map_1,
        new_entry_epoch,
        cur_bond_amount - new_bond_amount,
    )
    .unwrap();

    let exp_mr = ModifiedRedelegation {
        epoch: Some(Epoch(27)),
        validators_to_remove: BTreeSet::from_iter([redeleg_src_2.clone()]),
        validator_to_modify: Some(redeleg_src_2),
        epochs_to_remove: BTreeSet::from_iter([Epoch(18)]),
        epoch_to_modify: Some(Epoch(18)),
        new_amount: Some(token::Amount::from(3608889)),
    };

    pretty_assertions::assert_eq!(mr, exp_mr);
}

/// Test precisely that we are not overslashing, as originally discovered by Tomas in this issue: https://github.com/informalsystems/partnership-heliax/issues/74
fn test_overslashing_aux(mut validators: Vec<GenesisValidator>) {
    assert_eq!(validators.len(), 4);

    let params = PosParams {
        unbonding_len: 4,
        ..Default::default()
    };

    let offending_stake = token::Amount::native_whole(110);
    let other_stake = token::Amount::native_whole(100);

    // Set stakes so we know we will get a slashing rate between 0.5 -1.0
    validators[0].tokens = offending_stake;
    validators[1].tokens = other_stake;
    validators[2].tokens = other_stake;
    validators[3].tokens = other_stake;

    // Get the offending validator
    let validator = validators[0].address.clone();

    println!("\nTest inputs: {params:?}, genesis validators: {validators:#?}");
    let mut storage = TestWlStorage::default();

    // Genesis
    let mut current_epoch = storage.storage.block.epoch;
    init_genesis(
        &mut storage,
        &params,
        validators.clone().into_iter(),
        current_epoch,
    )
    .unwrap();
    storage.commit_block().unwrap();

    // Get a delegator with some tokens
    let staking_token = storage.storage.native_token.clone();
    let delegator = address::testing::gen_implicit_address();
    let amount_del = token::Amount::native_whole(5);
    credit_tokens(&mut storage, &staking_token, &delegator, amount_del)
        .unwrap();

    // Delegate tokens in epoch 0 to validator
    bond_tokens(
        &mut storage,
        Some(&delegator),
        &validator,
        amount_del,
        current_epoch,
    )
    .unwrap();

    let self_bond_epoch = current_epoch;
    let delegation_epoch = current_epoch + params.pipeline_len;

    // Advance to pipeline epoch
    for _ in 0..params.pipeline_len {
        current_epoch = advance_epoch(&mut storage, &params);
    }
    assert_eq!(delegation_epoch, current_epoch);

    // Find a misbehavior committed in epoch 0
    slash(
        &mut storage,
        &params,
        current_epoch,
        self_bond_epoch,
        0_u64,
        SlashType::DuplicateVote,
        &validator,
        current_epoch.next(),
    )
    .unwrap();

    // Find a misbehavior committed in current epoch
    slash(
        &mut storage,
        &params,
        current_epoch,
        delegation_epoch,
        0_u64,
        SlashType::DuplicateVote,
        &validator,
        current_epoch.next(),
    )
    .unwrap();

    let processing_epoch_1 =
        self_bond_epoch + params.slash_processing_epoch_offset();
    let processing_epoch_2 =
        delegation_epoch + params.slash_processing_epoch_offset();

    // Advance to processing epoch 1
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        super::process_slashes(&mut storage, current_epoch).unwrap();
        if current_epoch == processing_epoch_1 {
            break;
        }
    }

    let total_stake_1 = offending_stake + 3 * other_stake;
    let stake_frac = Dec::from(offending_stake) / Dec::from(total_stake_1);
    let slash_rate_1 = Dec::from_str("9.0").unwrap() * stake_frac * stake_frac;
    dbg!(&slash_rate_1);

    let exp_slashed_1 = offending_stake.mul_ceil(slash_rate_1);

    // Check that the proper amount was slashed
    let epoch = current_epoch.next();
    let validator_stake =
        read_validator_stake(&storage, &params, &validator, epoch).unwrap();
    let exp_validator_stake = offending_stake - exp_slashed_1 + amount_del;
    assert_eq!(validator_stake, exp_validator_stake);

    let total_stake = read_total_stake(&storage, &params, epoch).unwrap();
    let exp_total_stake =
        offending_stake - exp_slashed_1 + amount_del + 3 * other_stake;
    assert_eq!(total_stake, exp_total_stake);

    let self_bond_id = BondId {
        source: validator.clone(),
        validator: validator.clone(),
    };
    let bond_amount =
        crate::bond_amount(&storage, &self_bond_id, epoch).unwrap();
    let exp_bond_amount = offending_stake - exp_slashed_1;
    assert_eq!(bond_amount, exp_bond_amount);

    // Advance to processing epoch 2
    loop {
        current_epoch = advance_epoch(&mut storage, &params);
        super::process_slashes(&mut storage, current_epoch).unwrap();
        if current_epoch == processing_epoch_2 {
            break;
        }
    }

    let total_stake_2 = offending_stake + amount_del + 3 * other_stake;
    let stake_frac =
        Dec::from(offending_stake + amount_del) / Dec::from(total_stake_2);
    let slash_rate_2 = Dec::from_str("9.0").unwrap() * stake_frac * stake_frac;
    dbg!(&slash_rate_2);

    let exp_slashed_from_delegation = amount_del.mul_ceil(slash_rate_2);

    // Check that the proper amount was slashed. We expect that all of the
    // validator self-bond has been slashed and some of the delegation has been
    // slashed due to the second infraction.
    let epoch = current_epoch.next();

    let validator_stake =
        read_validator_stake(&storage, &params, &validator, epoch).unwrap();
    let exp_validator_stake = amount_del - exp_slashed_from_delegation;
    assert_eq!(validator_stake, exp_validator_stake);

    let total_stake = read_total_stake(&storage, &params, epoch).unwrap();
    let exp_total_stake =
        amount_del - exp_slashed_from_delegation + 3 * other_stake;
    assert_eq!(total_stake, exp_total_stake);

    let delegation_id = BondId {
        source: delegator.clone(),
        validator: validator.clone(),
    };
    let delegation_amount =
        crate::bond_amount(&storage, &delegation_id, epoch).unwrap();
    let exp_del_amount = amount_del - exp_slashed_from_delegation;
    assert_eq!(delegation_amount, exp_del_amount);

    let self_bond_amount =
        crate::bond_amount(&storage, &self_bond_id, epoch).unwrap();
    let exp_bond_amount = token::Amount::zero();
    assert_eq!(self_bond_amount, exp_bond_amount);
}
