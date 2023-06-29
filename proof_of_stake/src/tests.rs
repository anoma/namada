//! PoS system tests

mod state_machine;

use std::cmp::min;
use std::ops::Range;

use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::collections::lazy_map;
use namada_core::ledger::storage_api::token::{credit_tokens, read_balance};
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::address::testing::{
    address_from_simple_seed, arb_established_address,
};
use namada_core::types::address::{Address, EstablishedAddressGen};
use namada_core::types::key::common::{PublicKey, SecretKey};
use namada_core::types::key::testing::{
    arb_common_keypair, common_sk_from_simple_seed,
};
use namada_core::types::key::RefTo;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::{address, key, token};
use proptest::prelude::*;
use proptest::test_runner::Config;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use crate::parameters::testing::arb_pos_params;
use crate::parameters::PosParams;
use crate::types::{
    decimal_mult_amount, into_tm_voting_power, BondDetails, BondId,
    BondsAndUnbondsDetails, ConsensusValidator, GenesisValidator, Position,
    ReverseOrdTokenAmount, SlashType, UnbondDetails, ValidatorSetUpdate,
    ValidatorState, WeightedValidator,
};
use crate::{
    become_validator, below_capacity_validator_set_handle, bond_handle,
    bond_tokens, bonds_and_unbonds, consensus_validator_set_handle,
    copy_validator_sets_and_positions, find_validator_by_raw_hash,
    get_num_consensus_validators, init_genesis,
    insert_validator_into_validator_set, process_slashes,
    read_below_capacity_validator_set_addresses_with_stake,
    read_consensus_validator_set_addresses_with_stake, read_total_stake,
    read_validator_delta_value, read_validator_stake, slash,
    staking_token_address, total_deltas_handle, unbond_handle, unbond_tokens,
    unjail_validator, update_validator_deltas, update_validator_set,
    validator_consensus_key_handle, validator_set_update_tendermint,
    validator_slashes_handle, validator_state_handle, withdraw_tokens,
    write_validator_address_raw_hash, BecomeValidator,
};

proptest! {
    // Generate arb valid input for `test_init_genesis_aux`
    #![proptest_config(Config {
        cases: 1,
        .. Config::default()
    })]
    #[test]
    fn test_init_genesis(

    pos_params in arb_pos_params(Some(5)),
    start_epoch in (0_u64..1000).prop_map(Epoch),
    genesis_validators in arb_genesis_validators(1..10),

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

    pos_params in arb_pos_params(Some(5)),
    genesis_validators in arb_genesis_validators(1..3),

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

    pos_params in arb_pos_params(Some(5)),
    new_validator in arb_established_address().prop_map(Address::Established),
    new_validator_consensus_key in arb_common_keypair(),
    genesis_validators in arb_genesis_validators(1..3),

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

fn test_slashes_with_unbonding_params()
-> impl Strategy<Value = (PosParams, Vec<GenesisValidator>, u64)> {
    let params = arb_pos_params(Some(5));
    params.prop_flat_map(|params| {
        let unbond_delay = 0..(params.slash_processing_epoch_offset() * 2);
        // Must have at least 4 validators so we can slash one and the cubic
        // slash rate will be less than 100%
        let validators = arb_genesis_validators(4..10);
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
        if (i as u64) < params.max_validator_slots {
            // should be in consensus set
            let handle = consensus_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
            assert_eq!(state, Some(ValidatorState::Consensus));
        } else {
            // TODO: one more set once we have `below_threshold`

            // should be in below-capacity set
            let handle = below_capacity_validator_set_handle().at(&start_epoch);
            assert!(handle.at(&validator.tokens.into()).iter(&s).unwrap().any(
                |result| {
                    let (_pos, addr) = result.unwrap();
                    addr == validator.address
                }
            ));
            assert_eq!(state, Some(ValidatorState::BelowCapacity));
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
    let amount_self_bond = token::Amount::from(100_500_000);
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
    let delta = self_bond
        .get_delta_val(&s, pipeline_epoch, &params)
        .unwrap();
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

    let val_deltas = read_validator_delta_value(
        &s,
        &params,
        &validator.address,
        pipeline_epoch,
    )
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
    let amount_del = token::Amount::from(201_000_000);
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
        amount_self_bond + (u64::from(validator.tokens) / 2).into();
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

    let val_delta = read_validator_delta_value(
        &s,
        &params,
        &validator.address,
        pipeline_epoch,
    )
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
    let amount_undel = token::Amount::from(1_000_000);
    unbond_tokens(
        &mut s,
        Some(&delegator),
        &validator.address,
        amount_undel,
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
    let val_delta = read_validator_delta_value(
        &s,
        &params,
        &validator.address,
        pipeline_epoch,
    )
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
    assert_eq!(
        min(validators.len() as u64, params.max_validator_slots),
        num_consensus_before
    );

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
        commission_rate: Decimal::new(5, 2),
        max_commission_rate_change: Decimal::new(5, 2),
    })
    .unwrap();

    let num_consensus_after =
        get_num_consensus_validators(&s, current_epoch + params.pipeline_len)
            .unwrap();
    assert_eq!(
        if validators.len() as u64 >= params.max_validator_slots {
            num_consensus_before
        } else {
            num_consensus_before + 1
        },
        num_consensus_after
    );

    // Advance to epoch 2
    current_epoch = advance_epoch(&mut s, &params);

    // Self-bond to the new validator
    let staking_token = staking_token_address(&s);
    let amount = token::Amount::from(100_500_000);
    credit_tokens(&mut s, &staking_token, &new_validator, amount).unwrap();
    bond_tokens(&mut s, None, &new_validator, amount, current_epoch).unwrap();

    // Check the bond delta
    let bond_handle = bond_handle(&new_validator, &new_validator);
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let delta = bond_handle
        .get_delta_val(&s, pipeline_epoch, &params)
        .unwrap();
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
    unbond_tokens(&mut s, None, &new_validator, amount, current_epoch).unwrap();

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
        "Validator that will misbehave addr {val_addr}, tokens {val_tokens}"
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
    let unbond_amount = decimal_mult_amount(dec!(0.5), val_tokens);
    println!("Going to unbond {unbond_amount}");
    let unbond_epoch = current_epoch;
    unbond_tokens(&mut s, None, val_addr, unbond_amount, unbond_epoch).unwrap();

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

    withdraw_tokens(&mut s, None, val_addr, current_epoch).unwrap();

    let val_balance_post = read_balance(&s, &token, val_addr).unwrap();
    let withdrawn_tokens = val_balance_post - val_balance_pre;

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
    println!("Slash 0 rate {slash_rate_0}, slash 1 {slash_rate_1}");

    let expected_withdrawn_amount = decimal_mult_amount(
        dec!(1) - slash_rate_1,
        decimal_mult_amount(dec!(1) - slash_rate_0, unbond_amount),
    );
    // Allow some rounding error, 1 NAMNAM per each slash
    let rounding_error_tolerance = 2;
    assert!(
        dbg!(
            (expected_withdrawn_amount.change() - withdrawn_tokens.change())
                .abs()
        ) <= rounding_error_tolerance
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
            &params,
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

    // Start with two genesis validators with 1 NAM stake
    let epoch = Epoch::default();
    let ((val1, pk1), stake1) = (gen_validator(), token::Amount::whole(1));
    let ((val2, pk2), stake2) = (gen_validator(), token::Amount::whole(1));
    let ((val3, pk3), stake3) = (gen_validator(), token::Amount::whole(10));
    let ((val4, pk4), stake4) = (gen_validator(), token::Amount::whole(1));
    let ((val5, pk5), stake5) = (gen_validator(), token::Amount::whole(100));
    let ((val6, pk6), stake6) = (gen_validator(), token::Amount::whole(1));
    let ((val7, pk7), stake7) = (gen_validator(), token::Amount::whole(1));
    println!("val1: {val1}, {pk1}, {stake1}");
    println!("val2: {val2}, {pk2}, {stake2}");
    println!("val3: {val3}, {pk3}, {stake3}");
    println!("val4: {val4}, {pk4}, {stake4}");
    println!("val5: {val5}, {pk5}, {stake5}");
    println!("val6: {val6}, {pk6}, {stake6}");
    println!("val7: {val7}, {pk7}, {stake7}");

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
                commission_rate: Decimal::new(1, 1),
                max_commission_rate_change: Decimal::new(1, 1),
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
                commission_rate: Decimal::new(1, 1),
                max_commission_rate_change: Decimal::new(1, 1),
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
            bonded_stake: stake3.into(),
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
            bonded_stake: stake5.into(),
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk2));

    // Unbond some stake from val1, it should be be swapped with the greatest
    // below-capacity validator val2 into the below-capacity set
    let unbond = token::Amount::from(500_000);
    let stake1 = stake1 - unbond;
    println!("val1 {val1} new stake {stake1}");
    // Because `update_validator_set` and `update_validator_deltas` are
    // effective from pipeline offset, we use pipeline epoch for the rest of the
    // checks
    update_validator_set(&mut s, &params, &val1, -unbond.change(), epoch)
        .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
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
        if address == &val1 && stake == &stake1 && *position == Position(0)
    ));

    // Advance to EPOCH 5
    let epoch = advance_epoch(&mut s, &params);
    let pipeline_epoch = epoch + params.pipeline_len;

    // Check tendermint validator set updates
    assert_eq!(val6_epoch, epoch, "val6 is in the validator sets now");
    let tm_updates = get_tendermint_set_updates(&s, &params, epoch);
    assert!(tm_updates.is_empty());

    // Insert another validator with stake 1 - it should be added to below
    // capacity set after val1
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

    assert_eq!(below_capacity_vals.len(), 4);
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
    assert!(matches!(
        &below_capacity_vals[3],
        (
            lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
            },
            address
        )
        if address == &val1 && stake == &stake1 && *position == Position(0)
    ));

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
            bonded_stake: stake4.into(),
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk1));

    // Bond some stake to val6, it should be be swapped with the lowest
    // consensus validator val2 into the consensus set
    let bond = token::Amount::from(500_000);
    let stake6 = stake6 + bond;
    println!("val6 {val6} new stake {stake6}");
    update_validator_set(&mut s, &params, &val6, bond.change(), epoch).unwrap();
    update_validator_deltas(
        &mut s,
        &params,
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

    assert_eq!(below_capacity_vals.len(), 4);
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
    assert!(matches!(
        &below_capacity_vals[3],
        (
            lazy_map::NestedSubKey::Data {
                key: ReverseOrdTokenAmount(stake),
                nested_sub_key: lazy_map::SubKey::Data(position),
            },
            address
        )
        if address == &val1 && stake == &stake1 && *position == Position(0)
    ));

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
            bonded_stake: stake6.into(),
        })
    );
    assert_eq!(tm_updates[1], ValidatorSetUpdate::Deactivated(pk4));
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
        // Set 0.1 votes per token
        tm_votes_per_token: dec!(0.1),
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
            &params,
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
    let ((val1, pk1), stake1) = (gen_validator(), token::Amount::whole(10));
    // 0 voting power
    let ((val2, pk2), stake2) = (gen_validator(), token::Amount::from(5));
    // 0 voting power
    let ((val3, pk3), stake3) = (gen_validator(), token::Amount::from(5));
    println!("val1: {val1}, {pk1}, {stake1}");
    println!("val2: {val2}, {pk2}, {stake2}");
    println!("val3: {val3}, {pk3}, {stake3}");

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
                commission_rate: Decimal::new(1, 1),
                max_commission_rate_change: Decimal::new(1, 1),
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
                commission_rate: Decimal::new(1, 1),
                max_commission_rate_change: Decimal::new(1, 1),
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
    let bond2 = token::Amount::from(1);
    let stake2 = stake2 + bond2;
    let bond3 = token::Amount::from(4);
    let stake3 = stake3 + bond3;

    assert!(stake2 < stake3);
    assert_eq!(into_tm_voting_power(params.tm_votes_per_token, stake2), 0);
    assert_eq!(into_tm_voting_power(params.tm_votes_per_token, stake3), 0);

    update_validator_set(&mut s, &params, &val2, bond2.change(), epoch)
        .unwrap();
    update_validator_deltas(
        &mut s,
        &params,
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
        &params,
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
    let bonds = token::Amount::whole(1);
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
        &params,
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
        &params,
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
            bonded_stake: stake3.into(),
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
    copy_validator_sets_and_positions(
        s,
        current_epoch,
        current_epoch + params.pipeline_len,
        &consensus_validator_set_handle(),
        &below_capacity_validator_set_handle(),
    )
    .unwrap();
    // process_slashes(s, current_epoch).unwrap();
    // dbg!(current_epoch);
    current_epoch
}

fn arb_genesis_validators(
    size: Range<usize>,
) -> impl Strategy<Value = Vec<GenesisValidator>> {
    let tokens: Vec<_> = (0..size.end)
        .map(|_| (1..=10_000_000_u64).prop_map(token::Amount::from))
        .collect();
    (size, tokens).prop_map(|(size, token_amounts)| {
        // use unique seeds to generate validators' address and consensus key
        let seeds = (0_u64..).take(size);
        seeds
            .zip(token_amounts)
            .map(|(seed, tokens)| {
                let address = address_from_simple_seed(seed);
                let consensus_sk = common_sk_from_simple_seed(seed);
                let consensus_key = consensus_sk.to_public();

                let eth_hot_key = key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                );
                let eth_cold_key = key::common::PublicKey::Secp256k1(
                    key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                        .ref_to(),
                );

                let commission_rate = Decimal::new(5, 2);
                let max_commission_rate_change = Decimal::new(1, 2);
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
}
