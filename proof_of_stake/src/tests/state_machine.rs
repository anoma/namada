//! Test PoS transitions with a state machine

use std::cmp;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use itertools::Itertools;
use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::collections::lazy_map::NestedSubKey;
use namada_core::ledger::storage_api::{token, StorageRead};
use namada_core::types::address::{self, Address};
use namada_core::types::key;
use namada_core::types::key::common::PublicKey;
use namada_core::types::storage::Epoch;
use proptest::prelude::*;
use proptest::prop_state_machine;
use proptest::state_machine::{AbstractStateMachine, StateMachineTest};
use proptest::test_runner::Config;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use super::arb_genesis_validators;
use crate::parameters::testing::{arb_pos_params, arb_rate};
use crate::parameters::PosParams;
use crate::types::{
    decimal_mult_amount, decimal_mult_i128, BondId, GenesisValidator,
    ReverseOrdTokenAmount, Slash, SlashType, SlashedAmount, UnbondRecord,
    ValidatorState, WeightedValidator,
};
use crate::{
    below_capacity_validator_set_handle, consensus_validator_set_handle,
    enqueued_slashes_handle, read_pos_params, validator_slashes_handle,
    validator_state_handle,
};

prop_state_machine! {
    #![proptest_config(Config {
        cases: 5,
        .. Config::default()
    })]
    #[test]
    /// A `StateMachineTest` implemented on `PosState`
    fn pos_state_machine_test(sequential 1..200 => ConcretePosState);
}

/// Abstract representation of a state of PoS system
#[derive(Clone, Debug)]
struct AbstractPosState {
    /// Current epoch
    epoch: Epoch,
    /// Parameters
    params: PosParams,
    /// Genesis validator
    genesis_validators: Vec<GenesisValidator>,
    /// Bonds delta values. The outer key for Epoch is pipeline offset from
    /// epoch in which the bond is applied
    bonds: BTreeMap<Epoch, HashMap<BondId, token::Change>>,
    /// Validator stakes delta values (sum of all their bonds deltas).
    /// Pipelined.
    validator_stakes: BTreeMap<Epoch, HashMap<Address, token::Change>>,
    /// Consensus validator set. Pipelined.
    consensus_set: BTreeMap<Epoch, BTreeMap<token::Amount, VecDeque<Address>>>,
    /// Below-capacity validator set. Pipelined.
    below_capacity_set:
        BTreeMap<Epoch, BTreeMap<ReverseOrdTokenAmount, VecDeque<Address>>>,
    /// Validator states. Pipelined.
    validator_states: BTreeMap<Epoch, HashMap<Address, ValidatorState>>,
    /// Unbonded bonds. The outer key for Epoch is pipeline + unbonding offset
    /// from epoch in which the unbond is applied.
    unbonds: BTreeMap<Epoch, HashMap<BondId, token::Amount>>,
    /// Validator slashes post-processing
    validator_slashes: BTreeMap<Address, Vec<Slash>>,
    /// Enqueued slashes pre-processing
    enqueued_slashes: BTreeMap<Epoch, BTreeMap<Address, Vec<Slash>>>,
    /// The last epoch in which a validator committed an infraction
    validator_last_slash_epochs: BTreeMap<Address, Epoch>,
    /// Unbond records required for slashing
    unbond_records: BTreeMap<Address, BTreeMap<Epoch, Vec<UnbondRecord>>>,
}

/// The PoS system under test
#[derive(Debug)]
struct ConcretePosState {
    /// Storage - contains all the PoS state
    s: TestWlStorage,
}

/// State machine transitions
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum Transition {
    NextEpoch,
    InitValidator {
        address: Address,
        consensus_key: PublicKey,
        commission_rate: Decimal,
        max_commission_rate_change: Decimal,
    },
    Bond {
        id: BondId,
        amount: token::Amount,
    },
    Unbond {
        id: BondId,
        amount: token::Amount,
    },
    Withdraw {
        id: BondId,
    },
    Misbehavior {
        address: Address,
        slash_type: SlashType,
        infraction_epoch: Epoch,
        height: u64,
    },
    UnjailValidator {
        address: Address,
    },
}

impl StateMachineTest for ConcretePosState {
    type Abstract = AbstractPosState;
    type ConcreteState = Self;

    fn init_test(
        initial_state: <Self::Abstract as AbstractStateMachine>::State,
    ) -> Self::ConcreteState {
        println!();
        println!("New test case");
        println!(
            "Genesis validators: {:#?}",
            initial_state
                .genesis_validators
                .iter()
                .map(|val| &val.address)
                .collect::<Vec<_>>()
        );
        let mut s = TestWlStorage::default();
        crate::init_genesis(
            &mut s,
            &initial_state.params,
            initial_state.genesis_validators.clone().into_iter(),
            initial_state.epoch,
        )
        .unwrap();
        Self { s }
    }

    fn apply_concrete(
        mut state: Self::ConcreteState,
        transition: <Self::Abstract as AbstractStateMachine>::Transition,
    ) -> Self::ConcreteState {
        let params = crate::read_pos_params(&state.s).unwrap();
        match transition {
            Transition::NextEpoch => {
                super::advance_epoch(&mut state.s, &params);

                // Need to apply some slashing
                let current_epoch = state.s.storage.block.epoch;
                super::process_slashes(&mut state.s, current_epoch).unwrap();

                state.check_next_epoch_post_conditions(&params);
            }
            Transition::InitValidator {
                address,
                consensus_key,
                commission_rate,
                max_commission_rate_change,
            } => {
                let epoch = state.current_epoch();

                super::become_validator(
                    &mut state.s,
                    &params,
                    &address,
                    &consensus_key,
                    epoch,
                    commission_rate,
                    max_commission_rate_change,
                )
                .unwrap();

                state.check_init_validator_post_conditions(
                    epoch, &params, &address,
                )
            }
            Transition::Bond { id, amount } => {
                let epoch = state.current_epoch();
                let pipeline = epoch + params.pipeline_len;
                let validator_stake_before_bond_cur =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        epoch,
                    )
                    .unwrap()
                    .unwrap_or_default();
                let validator_stake_before_bond_pipeline =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        pipeline,
                    )
                    .unwrap()
                    .unwrap_or_default();

                // Credit tokens to ensure we can apply the bond
                let native_token = state.s.get_native_token().unwrap();
                let pos = address::POS;
                token::credit_tokens(
                    &mut state.s,
                    &native_token,
                    &id.source,
                    amount,
                )
                .unwrap();

                let src_balance_pre =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_pre =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // This must be ensured by both transitions generator and
                // pre-conditions!
                assert!(
                    crate::is_validator(
                        &state.s,
                        &id.validator,
                        &params,
                        pipeline,
                    )
                    .unwrap(),
                    "{} is not a validator",
                    id.validator
                );

                // Apply the bond
                super::bond_tokens(
                    &mut state.s,
                    Some(&id.source),
                    &id.validator,
                    amount,
                    epoch,
                )
                .unwrap();

                state.check_bond_post_conditions(
                    epoch,
                    &params,
                    id.clone(),
                    amount,
                    validator_stake_before_bond_cur,
                    validator_stake_before_bond_pipeline,
                );

                let src_balance_post =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_post =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // Post-condition: PoS balance should increase
                assert!(pos_balance_pre < pos_balance_post);
                // Post-condition: The difference in PoS balance should be the
                // same as in the source
                assert_eq!(
                    pos_balance_post - pos_balance_pre,
                    src_balance_pre - src_balance_post
                );
            }
            Transition::Unbond { id, amount } => {
                let epoch = state.current_epoch();
                let pipeline = epoch + params.pipeline_len;
                let native_token = state.s.get_native_token().unwrap();
                let pos = address::POS;
                let src_balance_pre =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_pre =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                let validator_stake_before_bond_cur =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        epoch,
                    )
                    .unwrap()
                    .unwrap_or_default();
                let validator_stake_before_bond_pipeline =
                    crate::read_validator_stake(
                        &state.s,
                        &params,
                        &id.validator,
                        pipeline,
                    )
                    .unwrap()
                    .unwrap_or_default();

                // Apply the unbond
                super::unbond_tokens(
                    &mut state.s,
                    Some(&id.source),
                    &id.validator,
                    amount,
                    epoch,
                )
                .unwrap();

                state.check_unbond_post_conditions(
                    epoch,
                    &params,
                    id.clone(),
                    amount,
                    validator_stake_before_bond_cur,
                    validator_stake_before_bond_pipeline,
                );

                let src_balance_post =
                    token::read_balance(&state.s, &native_token, &id.source)
                        .unwrap();
                let pos_balance_post =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // Post-condition: PoS balance should not change
                assert_eq!(pos_balance_pre, pos_balance_post);
                // Post-condition: Source balance should not change
                assert_eq!(src_balance_post, src_balance_pre);
            }
            Transition::Withdraw {
                id: BondId { source, validator },
            } => {
                let epoch = state.current_epoch();
                let native_token = state.s.get_native_token().unwrap();
                let pos = address::POS;
                let src_balance_pre =
                    token::read_balance(&state.s, &native_token, &source)
                        .unwrap();
                let pos_balance_pre =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // Apply the withdrawal
                let withdrawn = super::withdraw_tokens(
                    &mut state.s,
                    Some(&source),
                    &validator,
                    epoch,
                )
                .unwrap();

                let src_balance_post =
                    token::read_balance(&state.s, &native_token, &source)
                        .unwrap();
                let pos_balance_post =
                    token::read_balance(&state.s, &native_token, &pos).unwrap();

                // Post-condition: PoS balance should decrease or not change if
                // nothing was withdrawn
                assert!(pos_balance_pre >= pos_balance_post);
                // Post-condition: The difference in PoS balance should be the
                // same as in the source
                assert_eq!(
                    pos_balance_pre - pos_balance_post,
                    src_balance_post - src_balance_pre
                );
                // Post-condition: The increment in source balance should be
                // equal to the withdrawn amount
                assert_eq!(src_balance_post - src_balance_pre, withdrawn,);
            }
            Transition::Misbehavior {
                address,
                slash_type,
                infraction_epoch,
                height,
            } => {
                let current_epoch = state.current_epoch();
                // Record the slash evidence
                super::slash(
                    &mut state.s,
                    &params,
                    current_epoch,
                    infraction_epoch,
                    height,
                    slash_type,
                    &address,
                )
                .unwrap();

                // Apply some post-conditions
                state.check_misbehavior_post_conditions(
                    &params,
                    current_epoch,
                    infraction_epoch,
                    slash_type,
                    &address,
                );

                // TODO: Any others?
            }
            Transition::UnjailValidator { address } => {
                let current_epoch = state.current_epoch();

                // Unjail the validator
                super::unjail_validator(&mut state.s, &address, current_epoch)
                    .unwrap();

                // Post-conditions
                let params = read_pos_params(&state.s).unwrap();
                state.check_unjail_validator_post_conditions(&params, &address);
            }
        }
        state
    }

    fn invariants(_state: &Self::ConcreteState) {}

    // Overridden to add some logging, but same behavior as original
    fn test_sequential(
        initial_state: <Self::Abstract as AbstractStateMachine>::State,
        transitions: Vec<<Self::Abstract as AbstractStateMachine>::Transition>,
    ) {
        println!("\nTEST SEQUENTIAL");
        let mut state = Self::init_test(initial_state);
        println!("Transitions {}", transitions.len());
        for (i, transition) in transitions.into_iter().enumerate() {
            println!(
                "Apply transition {} in epoch {}: {:#?}",
                i,
                state.current_epoch(),
                transition
            );
            state = Self::apply_concrete(state, transition);
            Self::invariants(&state);
        }
    }
}

impl ConcretePosState {
    fn current_epoch(&self) -> Epoch {
        self.s.storage.block.epoch
    }

    fn check_next_epoch_post_conditions(&self, params: &PosParams) {
        let pipeline = self.current_epoch() + params.pipeline_len;
        let before_pipeline = pipeline - 1;

        // Post-condition: Consensus validator sets at pipeline offset
        // must be the same as at the epoch before it.
        let consensus_set_before_pipeline =
            crate::read_consensus_validator_set_addresses_with_stake(
                &self.s,
                before_pipeline,
            )
            .unwrap();
        let consensus_set_at_pipeline =
            crate::read_consensus_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap();
        itertools::assert_equal(
            consensus_set_before_pipeline.into_iter().sorted(),
            consensus_set_at_pipeline.into_iter().sorted(),
        );

        // Post-condition: Below-capacity validator sets at pipeline
        // offset must be the same as at the epoch before it.
        let below_cap_before_pipeline =
            crate::read_below_capacity_validator_set_addresses_with_stake(
                &self.s,
                before_pipeline,
            )
            .unwrap();
        let below_cap_at_pipeline =
            crate::read_below_capacity_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap();
        itertools::assert_equal(
            below_cap_before_pipeline.into_iter().sorted(),
            below_cap_at_pipeline.into_iter().sorted(),
        );

        // TODO: post-conditions for processing of slashes, just throwing things
        // here atm
        let slashed_validators = enqueued_slashes_handle()
            .at(&self.current_epoch())
            .iter(&self.s)
            .unwrap()
            .map(|a| {
                let (
                    NestedSubKey::Data {
                        key: address,
                        nested_sub_key: _,
                    },
                    _b,
                ) = a.unwrap();
                address
            })
            .collect::<HashSet<Address>>();

        for validator in &slashed_validators {
            assert!(
                !validator_slashes_handle(validator)
                    .is_empty(&self.s)
                    .unwrap()
            );
            assert_eq!(
                validator_state_handle(validator)
                    .get(&self.s, self.current_epoch(), params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
        }
    }

    fn check_bond_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        id: BondId,
        amount: token::Amount,
        validator_stake_before_bond_cur: token::Amount,
        validator_stake_before_bond_pipeline: token::Amount,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;

        let cur_stake = super::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            submit_epoch,
        )
        .unwrap()
        .unwrap_or_default();

        // Post-condition: the validator stake at the current epoch should not
        // change
        assert_eq!(cur_stake, validator_stake_before_bond_cur);

        let stake_at_pipeline = super::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            pipeline,
        )
        .unwrap()
        .unwrap_or_default();

        // Post-condition: the validator stake at the pipeline should be
        // incremented by the bond amount
        assert_eq!(
            stake_at_pipeline,
            validator_stake_before_bond_pipeline + amount
        );

        self.check_bond_and_unbond_post_conditions(
            submit_epoch,
            params,
            id,
            stake_at_pipeline,
        );
    }

    fn check_unbond_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        id: BondId,
        amount: token::Amount,
        validator_stake_before_bond_cur: token::Amount,
        validator_stake_before_bond_pipeline: token::Amount,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;

        let cur_stake = super::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            submit_epoch,
        )
        .unwrap()
        .unwrap_or_default();

        // Post-condition: the validator stake at the current epoch should not
        // change
        assert_eq!(cur_stake, validator_stake_before_bond_cur);

        let stake_at_pipeline = super::read_validator_stake(
            &self.s,
            params,
            &id.validator,
            pipeline,
        )
        .unwrap()
        .unwrap_or_default();

        // Post-condition: the validator stake at the pipeline should be
        // decremented by the bond amount
        assert_eq!(
            stake_at_pipeline,
            validator_stake_before_bond_pipeline - amount
        );

        self.check_bond_and_unbond_post_conditions(
            submit_epoch,
            params,
            id,
            stake_at_pipeline,
        );
    }

    /// These post-conditions apply to bonding and unbonding
    fn check_bond_and_unbond_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        id: BondId,
        stake_at_pipeline: token::Amount,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;
        // Read the consensus sets data using iterator
        let consensus_set = crate::consensus_validator_set_handle()
            .at(&pipeline)
            .iter(&self.s)
            .unwrap()
            .map(|res| res.unwrap())
            .collect::<Vec<_>>();
        let below_cap_set = crate::below_capacity_validator_set_handle()
            .at(&pipeline)
            .iter(&self.s)
            .unwrap()
            .map(|res| res.unwrap())
            .collect::<Vec<_>>();
        let num_occurrences = consensus_set
            .iter()
            .filter(|(_keys, addr)| addr == &id.validator)
            .count()
            + below_cap_set
                .iter()
                .filter(|(_keys, addr)| addr == &id.validator)
                .count();

        // Post-condition: There must only be one instance of this validator
        // with some stake across all validator sets
        assert!(num_occurrences == 1);

        let consensus_set =
            crate::read_consensus_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap();
        let below_cap_set =
            crate::read_below_capacity_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap();
        let weighted = WeightedValidator {
            bonded_stake: stake_at_pipeline,
            address: id.validator,
        };
        let consensus_val = consensus_set.get(&weighted);
        let below_cap_val = below_cap_set.get(&weighted);

        // Post-condition: The validator should be updated in exactly once in
        // the validator sets
        assert!(consensus_val.is_some() ^ below_cap_val.is_some());

        // Post-condition: The stake of the validators in the consensus set is
        // greater than or equal to below-capacity validators
        for WeightedValidator {
            bonded_stake: consensus_stake,
            address: consensus_addr,
        } in consensus_set.iter()
        {
            for WeightedValidator {
                bonded_stake: below_cap_stake,
                address: below_cap_addr,
            } in below_cap_set.iter()
            {
                assert!(
                    consensus_stake >= below_cap_stake,
                    "Consensus validator {consensus_addr} with stake \
                     {consensus_stake} and below-capacity {below_cap_addr} \
                     with stake {below_cap_stake} should be swapped."
                );
            }
        }
    }

    fn check_init_validator_post_conditions(
        &self,
        submit_epoch: Epoch,
        params: &PosParams,
        address: &Address,
    ) {
        let pipeline = submit_epoch + params.pipeline_len;

        // Post-condition: the validator should not be in the validator set
        // until the pipeline epoch
        for epoch in submit_epoch.iter_range(params.pipeline_len) {
            assert!(
                !crate::read_all_validator_addresses(&self.s, epoch)
                    .unwrap()
                    .contains(address)
            );
        }
        let weighted = WeightedValidator {
            bonded_stake: Default::default(),
            address: address.clone(),
        };
        let in_consensus =
            crate::read_consensus_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap()
            .contains(&weighted);
        let in_bc =
            crate::read_below_capacity_validator_set_addresses_with_stake(
                &self.s, pipeline,
            )
            .unwrap()
            .contains(&weighted);
        assert!(in_consensus ^ in_bc);
    }

    fn check_misbehavior_post_conditions(
        &self,
        params: &PosParams,
        current_epoch: Epoch,
        infraction_epoch: Epoch,
        slash_type: SlashType,
        validator: &Address,
    ) {
        // Validator state jailed and validator removed from the consensus set
        for offset in 0..=params.pipeline_len {
            assert_eq!(
                validator_state_handle(validator)
                    .get(&self.s, current_epoch + offset, params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            let in_consensus = consensus_validator_set_handle()
                .at(&(dbg!(current_epoch + offset)))
                .iter(&self.s)
                .unwrap()
                .any(|res| {
                    let (_, val_address) = res.unwrap();
                    dbg!(&val_address);
                    val_address == validator.clone()
                });
            assert!(!in_consensus);
        }

        // `enqueued_slashes` contains the slash element just added
        let processing_epoch = infraction_epoch + params.unbonding_len;
        let slash = enqueued_slashes_handle()
            .at(&processing_epoch)
            .at(validator)
            .back(&self.s)
            .unwrap();
        if let Some(slash) = slash {
            assert_eq!(slash.epoch, infraction_epoch);
            assert_eq!(slash.r#type, slash_type);
            assert_eq!(slash.rate, Decimal::ZERO);
        } else {
            panic!("Could not find the slash enqueued");
        }

        // TODO: Any others?
    }

    fn check_unjail_validator_post_conditions(
        &self,
        params: &PosParams,
        validator: &Address,
    ) {
        let current_epoch = self.s.storage.block.epoch;

        // Make sure the validator is not in either set until the pipeline epoch
        for epoch in current_epoch.iter_range(params.pipeline_len) {
            let in_consensus = consensus_validator_set_handle()
                .at(&epoch)
                .iter(&self.s)
                .unwrap()
                .any(|res| {
                    let (_, val_address) = res.unwrap();
                    val_address == validator.clone()
                });

            let in_bc = below_capacity_validator_set_handle()
                .at(&epoch)
                .iter(&self.s)
                .unwrap()
                .any(|res| {
                    let (_, val_address) = res.unwrap();
                    val_address == validator.clone()
                });
            assert!(!in_consensus && !in_bc);

            let val_state = validator_state_handle(validator)
                .get(&self.s, epoch, params)
                .unwrap();
            assert_eq!(val_state, Some(ValidatorState::Jailed));
        }
        let in_consensus = consensus_validator_set_handle()
            .at(&(current_epoch + params.pipeline_len))
            .iter(&self.s)
            .unwrap()
            .any(|res| {
                let (_, val_address) = res.unwrap();
                val_address == validator.clone()
            });

        let in_bc = below_capacity_validator_set_handle()
            .at(&(current_epoch + params.pipeline_len))
            .iter(&self.s)
            .unwrap()
            .any(|res| {
                let (_, val_address) = res.unwrap();
                val_address == validator.clone()
            });
        assert!(in_consensus ^ in_bc);

        let val_state = validator_state_handle(validator)
            .get(&self.s, current_epoch + params.pipeline_len, params)
            .unwrap();
        assert!(
            val_state == Some(ValidatorState::Consensus)
                || val_state == Some(ValidatorState::BelowCapacity)
        );
    }
}

impl AbstractStateMachine for AbstractPosState {
    type State = Self;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
        println!("Initializing abstract state machine");
        (arb_pos_params(Some(5)), arb_genesis_validators(1..10))
            .prop_map(|(params, genesis_validators)| {
                let epoch = Epoch::default();
                let mut state = Self {
                    epoch,
                    params,
                    genesis_validators: genesis_validators
                        .into_iter()
                        // Sorted by stake to fill in the consensus set first
                        .sorted_by(|a, b| Ord::cmp(&a.tokens, &b.tokens))
                        .rev()
                        .collect(),
                    bonds: Default::default(),
                    unbonds: Default::default(),
                    validator_stakes: Default::default(),
                    consensus_set: Default::default(),
                    below_capacity_set: Default::default(),
                    validator_states: Default::default(),
                    validator_slashes: Default::default(),
                    enqueued_slashes: Default::default(),
                    validator_last_slash_epochs: Default::default(),
                    unbond_records: Default::default(),
                };

                for GenesisValidator {
                    address,
                    tokens,
                    consensus_key: _,
                    commission_rate: _,
                    max_commission_rate_change: _,
                } in state.genesis_validators.clone()
                {
                    let bonds = state.bonds.entry(epoch).or_default();
                    bonds.insert(
                        BondId {
                            source: address.clone(),
                            validator: address.clone(),
                        },
                        token::Change::from(tokens),
                    );

                    let total_stakes =
                        state.validator_stakes.entry(epoch).or_default();
                    total_stakes
                        .insert(address.clone(), token::Change::from(tokens));

                    let consensus_set =
                        state.consensus_set.entry(epoch).or_default();
                    let consensus_vals_len = consensus_set
                        .iter()
                        .map(|(_stake, validators)| validators.len() as u64)
                        .sum();
                    let deque = if state.params.max_validator_slots
                        > consensus_vals_len
                    {
                        state
                            .validator_states
                            .entry(epoch)
                            .or_default()
                            .insert(address.clone(), ValidatorState::Consensus);
                        consensus_set.entry(tokens).or_default()
                    } else {
                        state
                            .validator_states
                            .entry(epoch)
                            .or_default()
                            .insert(
                                address.clone(),
                                ValidatorState::BelowCapacity,
                            );
                        let below_cap_set =
                            state.below_capacity_set.entry(epoch).or_default();
                        below_cap_set
                            .entry(ReverseOrdTokenAmount(tokens))
                            .or_default()
                    };
                    deque.push_back(address)
                }
                // Ensure that below-capacity set is initialized even if empty
                state.below_capacity_set.entry(epoch).or_default();

                // Copy validator sets up to pipeline epoch
                for epoch in epoch.next().iter_range(state.params.pipeline_len)
                {
                    state.copy_discrete_epoched_data(epoch)
                }
                dbg!(&state);
                state
            })
            .boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let unbondable = state
            .bond_sums()
            .into_iter()
            .filter(|(bond_id, _)| {
                let val_state = state
                    .validator_states
                    .get(&state.epoch)
                    .unwrap()
                    .get(&bond_id.validator)
                    .unwrap();
                *val_state != ValidatorState::Jailed
            })
            .collect::<Vec<_>>();
        let withdrawable =
            state.withdrawable_unbonds().into_iter().collect::<Vec<_>>();

        let eligible_for_unjail = state
            .validator_states
            .get(&(state.epoch + state.params.pipeline_len))
            .unwrap()
            .iter()
            .filter(|(addr, &val_state)| {
                let addr = *addr;
                let last_slash_epoch =
                    state.validator_last_slash_epochs.get(addr);

                if let Some(last_slash_epoch) = last_slash_epoch {
                    val_state == ValidatorState::Jailed
                        // `last_slash_epoch` must be unbonding_len or more epochs
                        // before the current
                        && state.epoch.0 - last_slash_epoch.0
                            > state.params.unbonding_len
                } else {
                    false
                }
            })
            .map(|(validator, _)| validator.clone())
            .collect::<Vec<_>>();

        // TODO: need to get list of jailed validators eligible to be
        // unjailed given their last slash epoch and the current epoch, not
        // just the list of jailed validators at pipeline alone

        // Transitions that can be applied if there are no bonds and unbonds
        let basic = prop_oneof![
            Just(Transition::NextEpoch),
            add_arb_bond_amount(state),
            arb_delegation(state),
            arb_slash(state),
            (
                address::testing::arb_established_address(),
                key::testing::arb_common_keypair(),
                arb_rate(),
                arb_rate(),
            )
                .prop_map(
                    |(
                        addr,
                        consensus_key,
                        commission_rate,
                        max_commission_rate_change,
                    )| {
                        Transition::InitValidator {
                            address: Address::Established(addr),
                            consensus_key: consensus_key.to_public(),
                            commission_rate,
                            max_commission_rate_change,
                        }
                    },
                ),
        ];

        if unbondable.is_empty() {
            if eligible_for_unjail.is_empty() {
                basic.boxed()
            } else {
                prop_oneof![
                    basic,
                    prop::sample::select(eligible_for_unjail).prop_map(
                        |address| { Transition::UnjailValidator { address } }
                    )
                ]
                .boxed()
            }
        } else {
            let arb_unbondable = prop::sample::select(unbondable);
            let arb_unbond =
                arb_unbondable.prop_flat_map(|(id, deltas_sum)| {
                    // Generate an amount to unbond, up to the sum
                    assert!(deltas_sum > 0);
                    (0..deltas_sum).prop_map(move |to_unbond| {
                        let id = id.clone();
                        let amount = token::Amount::from_change(to_unbond);
                        Transition::Unbond { id, amount }
                    })
                });

            if withdrawable.is_empty() {
                if eligible_for_unjail.is_empty() {
                    prop_oneof![basic, arb_unbond].boxed()
                } else {
                    prop_oneof![
                        basic,
                        arb_unbond,
                        prop::sample::select(eligible_for_unjail).prop_map(
                            |address| {
                                Transition::UnjailValidator { address }
                            }
                        )
                    ]
                    .boxed()
                }
            } else {
                let arb_withdrawable = prop::sample::select(withdrawable);
                let arb_withdrawal = arb_withdrawable
                    .prop_map(|(id, _)| Transition::Withdraw { id });

                if eligible_for_unjail.is_empty() {
                    prop_oneof![basic, arb_unbond, arb_withdrawal].boxed()
                } else {
                    prop_oneof![
                        basic,
                        arb_unbond,
                        arb_withdrawal,
                        prop::sample::select(eligible_for_unjail).prop_map(
                            |address| {
                                Transition::UnjailValidator { address }
                            }
                        )
                    ]
                    .boxed()
                }
            }
        }
    }

    fn apply_abstract(
        mut state: Self::State,
        transition: &Self::Transition,
    ) -> Self::State {
        match transition {
            Transition::NextEpoch => {
                println!("\nABSTRACT Next Epoch");

                state.epoch = state.epoch.next();

                // Copy the non-delta data into pipeline epoch from its pred.
                state.copy_discrete_epoched_data(
                    state.epoch + state.params.pipeline_len,
                );

                // Process enqueued slashes
                let slashes_this_epoch = state
                    .enqueued_slashes
                    .get(&state.epoch)
                    .cloned()
                    .unwrap_or_default();
                if !slashes_this_epoch.is_empty() {
                    // Now need to basically do the end_of_epoch() procedure
                    // from the Informal Systems model
                    let cubic_rate = state.cubic_slash_rate();
                    for (validator, slashes) in slashes_this_epoch {
                        let stake = state
                            .validator_stakes
                            .get(&state.epoch)
                            .unwrap()
                            .get(&validator)
                            .cloned()
                            .unwrap_or_default();

                        for slash in slashes {
                            let rate = cmp::max(
                                slash.r#type.get_slash_rate(&state.params),
                                cubic_rate,
                            );
                            let processed_slash = Slash {
                                epoch: slash.epoch,
                                block_height: slash.block_height,
                                r#type: slash.r#type,
                                rate,
                            };
                            let cur_slashes = state
                                .validator_slashes
                                .entry(validator.clone())
                                .or_default();
                            cur_slashes.push(processed_slash.clone());

                            let mut total_unbonded = token::Amount::default();
                            for epoch in (slash.epoch.0 + 1)..=state.epoch.0 {
                                let unbond_records = state
                                    .unbond_records
                                    .entry(validator.clone())
                                    .or_default()
                                    .get(&Epoch(epoch))
                                    .cloned()
                                    .unwrap_or_default();
                                for record in unbond_records {
                                    if record.start > slash.epoch {
                                        continue;
                                    }
                                    let mut slashes_for_this_unbond = state
                                        .validator_slashes
                                        .get(&validator)
                                        .cloned()
                                        .unwrap_or_default()
                                        .iter()
                                        .filter(|&s| {
                                            record.start <= s.epoch
                                                && s.epoch
                                                    + state.params.unbonding_len
                                                    < slash.epoch
                                        })
                                        .cloned()
                                        .collect::<Vec<Slash>>();

                                    total_unbonded += state
                                        .compute_amount_after_slashing(
                                            &mut slashes_for_this_unbond,
                                            record.amount,
                                        );
                                }
                            }
                            let mut last_slash = token::Change::default();
                            for offset in 1..=state.params.pipeline_len {
                                let unbond_records = state
                                    .unbond_records
                                    .get(&validator)
                                    .unwrap()
                                    .get(&(state.epoch + offset))
                                    .cloned()
                                    .unwrap_or_default();
                                for record in unbond_records {
                                    let mut slashes_for_this_unbond = state
                                        .validator_slashes
                                        .get(&validator)
                                        .cloned()
                                        .unwrap_or_default()
                                        .iter()
                                        .filter(|&s| {
                                            record.start <= s.epoch
                                                && s.epoch
                                                    + state.params.unbonding_len
                                                    < slash.epoch
                                        })
                                        .cloned()
                                        .collect::<Vec<Slash>>();

                                    total_unbonded += state
                                        .compute_amount_after_slashing(
                                            &mut slashes_for_this_unbond,
                                            record.amount,
                                        );
                                }
                                let this_slash = decimal_mult_i128(
                                    slash.rate,
                                    stake - total_unbonded.change(),
                                );
                                let diff_slashed_amount =
                                    this_slash - last_slash;
                                last_slash = this_slash;
                                total_unbonded = token::Amount::default();

                                // Update the voting powers
                                let validator_stake = state
                                    .validator_stakes
                                    .entry(state.epoch + offset)
                                    .or_default()
                                    .entry(validator.clone())
                                    .or_default();
                                *validator_stake -= diff_slashed_amount;
                            }
                        }
                    }
                }
                // print-out the state
                dbg!(&state.validator_stakes);
                dbg!(&state.validator_states);
                dbg!(&state.consensus_set);
                dbg!(&state.below_capacity_set);
            }
            Transition::InitValidator {
                address,
                consensus_key: _,
                commission_rate: _,
                max_commission_rate_change: _,
            } => {
                println!("\nABSTRACT Init Validator");

                // Insert into validator set at pipeline
                let pipeline = state.pipeline();
                let consensus_set =
                    state.consensus_set.entry(pipeline).or_default();

                let consensus_vals_len = consensus_set
                    .iter()
                    .map(|(_stake, validators)| validators.len() as u64)
                    .sum();

                let deque = if state.params.max_validator_slots
                    > consensus_vals_len
                {
                    state
                        .validator_states
                        .entry(pipeline)
                        .or_default()
                        .insert(address.clone(), ValidatorState::Consensus);
                    consensus_set.entry(token::Amount::default()).or_default()
                } else {
                    state
                        .validator_states
                        .entry(pipeline)
                        .or_default()
                        .insert(address.clone(), ValidatorState::BelowCapacity);
                    let below_cap_set =
                        state.below_capacity_set.entry(pipeline).or_default();
                    below_cap_set
                        .entry(ReverseOrdTokenAmount(token::Amount::default()))
                        .or_default()
                };
                deque.push_back(address.clone());
            }
            Transition::Bond { id, amount } => {
                println!("\nABSTRACT Bond {} tokens, id = {}", amount, id);

                if *amount != token::Amount::default() {
                    let change = token::Change::from(*amount);
                    // Validator sets need to be updated first!!
                    state.update_validator_sets(&id.validator, change);
                    state.update_bond(id, change);
                    state.update_validator_total_stake(&id.validator, change);
                }
                dbg!(&state.validator_stakes);
                dbg!(&state.validator_states);
                dbg!(&state.consensus_set);
                dbg!(&state.below_capacity_set);
            }
            Transition::Unbond { id, amount } => {
                println!("\nABSTRACT Unbond {} tokens, id = {}", amount, id);

                if *amount != token::Amount::default() {
                    let change = -token::Change::from(*amount);
                    // Validator sets need to be updated first!!
                    state.update_validator_sets(&id.validator, change);
                    state.update_bond(id, change);
                    state.update_validator_total_stake(&id.validator, change);

                    let withdrawal_epoch = state.epoch
                        + state.params.pipeline_len
                        + state.params.unbonding_len;
                    // + 1_u64;
                    let unbonds =
                        state.unbonds.entry(withdrawal_epoch).or_default();
                    let unbond = unbonds.entry(id.clone()).or_default();
                    *unbond += *amount;
                }
                dbg!(&state.validator_stakes);
                dbg!(&state.validator_states);
                dbg!(&state.consensus_set);
                dbg!(&state.below_capacity_set);
            }
            Transition::Withdraw { id } => {
                println!("\nABSTRACT Withdraw, id = {}", id);

                // Remove all withdrawable unbonds with this bond ID
                for (epoch, unbonds) in state.unbonds.iter_mut() {
                    if *epoch <= state.epoch {
                        unbonds.remove(id);
                    }
                }
                // Remove any epochs that have no unbonds left
                state.unbonds.retain(|_epoch, unbonds| !unbonds.is_empty());
            }
            Transition::Misbehavior {
                address,
                slash_type,
                infraction_epoch,
                height,
            } => {
                println!(
                    "\nABSTRACT Misbehavior in epoch {} by validator {}",
                    infraction_epoch, address
                );

                let current_epoch = state.epoch;
                let processing_epoch =
                    *infraction_epoch + state.params.unbonding_len;
                let slash = Slash {
                    epoch: *infraction_epoch,
                    block_height: *height,
                    r#type: *slash_type,
                    rate: Decimal::ZERO,
                };

                // Enqueue the slash for future processing
                state
                    .enqueued_slashes
                    .entry(processing_epoch)
                    .or_default()
                    .entry(address.clone())
                    .or_default()
                    .push(slash);

                // Remove the validator from either the consensus or
                // below-capacity set and place it into the jailed validator set

                // Remove from the validator set for every epoch up thru the
                // pipeline
                for offset in 0..=state.params.pipeline_len {
                    let real_stake = token::Amount::from_change(
                        state
                            .validator_stakes
                            .get(&(current_epoch + offset))
                            .unwrap()
                            .get(address)
                            .cloned()
                            .unwrap_or_default(),
                    );

                    if let Some((index, stake)) = state
                        .is_in_consensus_w_info(address, current_epoch + offset)
                    {
                        debug_assert_eq!(stake, real_stake);

                        let vals = state
                            .consensus_set
                            .entry(current_epoch + offset)
                            .or_default()
                            .entry(stake)
                            .or_default();
                        let removed = vals.remove(index);
                        debug_assert_eq!(removed, Some(address.clone()));
                        if vals.is_empty() {
                            state
                                .consensus_set
                                .entry(current_epoch + offset)
                                .or_default()
                                .remove(&stake);
                        }

                        // At pipeline epoch, if was consensus, replace it with
                        // a below-capacity validator
                        if offset == state.params.pipeline_len {
                            let below_cap_pipeline = state
                                .below_capacity_set
                                .entry(current_epoch + offset)
                                .or_default();

                            if let Some(mut max_below_cap) =
                                below_cap_pipeline.last_entry()
                            {
                                let max_bc_stake = *max_below_cap.key();
                                let vals = max_below_cap.get_mut();
                                let first_val = vals.pop_front().unwrap();
                                if vals.is_empty() {
                                    below_cap_pipeline.remove(&max_bc_stake);
                                }
                                state
                                    .consensus_set
                                    .entry(current_epoch + offset)
                                    .or_default()
                                    .entry(max_bc_stake.into())
                                    .or_default()
                                    .push_back(first_val.clone());
                                state
                                    .validator_states
                                    .entry(current_epoch + offset)
                                    .or_default()
                                    .insert(
                                        first_val.clone(),
                                        ValidatorState::Consensus,
                                    );
                            }
                        }
                    } else if let Some((index, stake)) = state
                        .is_in_below_capacity_w_info(
                            address,
                            current_epoch + offset,
                        )
                    {
                        debug_assert_eq!(stake, real_stake);

                        let vals = state
                            .below_capacity_set
                            .entry(current_epoch + offset)
                            .or_default()
                            .entry(stake.into())
                            .or_default();

                        let removed = vals.remove(index);
                        debug_assert_eq!(removed, Some(address.clone()));
                        if vals.is_empty() {
                            state
                                .below_capacity_set
                                .entry(current_epoch + offset)
                                .or_default()
                                .remove(&stake.into());
                        }
                    } else {
                        // Just make sure the validator is already jailed
                        debug_assert_eq!(
                            state
                                .validator_states
                                .get(&(current_epoch + offset))
                                .unwrap()
                                .get(address)
                                .cloned()
                                .unwrap(),
                            ValidatorState::Jailed
                        );
                    }

                    state
                        .validator_states
                        .entry(current_epoch + offset)
                        .or_default()
                        .insert(address.clone(), ValidatorState::Jailed);
                }

                // Update the most recent infraction epoch for the validator
                if let Some(last_epoch) =
                    state.validator_last_slash_epochs.get(address)
                {
                    if infraction_epoch > last_epoch {
                        state
                            .validator_last_slash_epochs
                            .insert(address.clone(), *infraction_epoch);
                    }
                } else {
                    state
                        .validator_last_slash_epochs
                        .insert(address.clone(), *infraction_epoch);
                }

                dbg!(&state.validator_stakes);
                dbg!(&state.validator_states);
                dbg!(&state.consensus_set);
                dbg!(&state.below_capacity_set);
            }
            Transition::UnjailValidator { address } => {
                let pipeline_epoch = state.epoch + state.params.pipeline_len;

                println!(
                    "\nABSTRACT Unjail validator {} starting in epoch {}",
                    address.clone(),
                    pipeline_epoch
                );

                let consensus_set_pipeline =
                    state.consensus_set.entry(pipeline_epoch).or_default();
                let pipeline_stake = state
                    .validator_stakes
                    .get(&pipeline_epoch)
                    .unwrap()
                    .get(address)
                    .cloned()
                    .unwrap_or_default();
                let validator_states_pipeline =
                    state.validator_states.entry(pipeline_epoch).or_default();

                // Insert the validator back into the appropriate validator set
                // and update its state
                let num_consensus = consensus_set_pipeline
                    .iter()
                    .fold(0, |sum, (_, validators)| {
                        sum + validators.len() as u64
                    });

                if num_consensus < state.params.max_validator_slots {
                    // Place directly into the consensus set
                    debug_assert!(
                        state
                            .below_capacity_set
                            .get(&pipeline_epoch)
                            .unwrap()
                            .is_empty()
                    );
                    consensus_set_pipeline
                        .entry(token::Amount::from_change(pipeline_stake))
                        .or_default()
                        .push_back(address.clone());
                    validator_states_pipeline
                        .insert(address.clone(), ValidatorState::Consensus);
                } else if let Some(mut min_consensus) =
                    consensus_set_pipeline.last_entry()
                {
                    let below_capacity_set_pipeline = state
                        .below_capacity_set
                        .entry(pipeline_epoch)
                        .or_default();

                    let min_consensus_stake = *min_consensus.key();
                    if pipeline_stake > min_consensus_stake.change() {
                        // Place into the consensus set and demote the last
                        // min_consensus validator
                        let min_validators = min_consensus.get_mut();
                        let last_val = min_validators.pop_back().unwrap();
                        // Remove the key if there's nothing left
                        if min_validators.is_empty() {
                            consensus_set_pipeline.remove(&min_consensus_stake);
                        }
                        // Do the swap
                        below_capacity_set_pipeline
                            .entry(min_consensus_stake.into())
                            .or_default()
                            .push_back(last_val);
                        validator_states_pipeline.insert(
                            address.clone(),
                            ValidatorState::BelowCapacity,
                        );

                        consensus_set_pipeline
                            .entry(token::Amount::from_change(pipeline_stake))
                            .or_default()
                            .push_back(address.clone());
                        validator_states_pipeline
                            .insert(address.clone(), ValidatorState::Consensus);
                    } else {
                        // Just place into the below-capacity set
                        below_capacity_set_pipeline
                            .entry(
                                token::Amount::from_change(pipeline_stake)
                                    .into(),
                            )
                            .or_default()
                            .push_back(address.clone());
                        validator_states_pipeline.insert(
                            address.clone(),
                            ValidatorState::BelowCapacity,
                        );
                    }
                } else {
                    panic!("Should not reach here I don't think")
                }
                dbg!(&state.validator_stakes);
                dbg!(&state.validator_states);
                dbg!(&state.consensus_set);
                dbg!(&state.below_capacity_set);
            }
        }
        state
    }

    fn preconditions(
        state: &Self::State,
        transition: &Self::Transition,
    ) -> bool {
        match transition {
            // TODO: should there be any slashing preconditions for `NextEpoch`?
            Transition::NextEpoch => true,
            Transition::InitValidator {
                address,
                consensus_key: _,
                commission_rate: _,
                max_commission_rate_change: _,
            } => {
                let pipeline = state.epoch + state.params.pipeline_len;
                // The address must not belong to an existing validator
                !state.is_validator(address, pipeline) &&
                   // There must be no delegations from this address
                   !state.bond_sums().into_iter().any(|(id, _sum)|
                        &id.source != address)
            }
            Transition::Bond { id, amount: _ } => {
                let pipeline = state.epoch + state.params.pipeline_len;
                // The validator must be known
                if !state.is_validator(&id.validator, pipeline) {
                    return false;
                }
                // The validator must not be jailed currently
                let is_jailed = state
                    .validator_states
                    .get(&state.epoch)
                    .unwrap()
                    .get(&id.validator)
                    .cloned()
                    == Some(ValidatorState::Jailed);

                !is_jailed
                    && (id.validator == id.source
                        // If it's not a self-bond, the source must not be a validator
                        || !state.is_validator(&id.source, pipeline))
            }
            Transition::Unbond { id, amount } => {
                let pipeline = state.epoch + state.params.pipeline_len;

                let is_unbondable = state
                    .bond_sums()
                    .get(id)
                    .map(|sum| *sum >= token::Change::from(*amount))
                    .unwrap_or_default();

                // The validator must not be frozen currently
                let is_frozen = if let Some(last_epoch) =
                    state.validator_last_slash_epochs.get(&id.validator)
                {
                    *last_epoch + state.params.unbonding_len > state.epoch
                } else {
                    false
                };

                // The validator must be known
                state.is_validator(&id.validator, pipeline)
                    // The amount must be available to unbond and the validator not jailed
                    && is_unbondable && !is_frozen
            }
            Transition::Withdraw { id } => {
                let pipeline = state.epoch + state.params.pipeline_len;

                let is_withdrawable = state
                    .withdrawable_unbonds()
                    .get(id)
                    .map(|amount| *amount >= token::Amount::default())
                    .unwrap_or_default();

                // The validator must not be jailed currently
                let is_jailed = state
                    .validator_states
                    .get(&state.epoch)
                    .unwrap()
                    .get(&id.validator)
                    .cloned()
                    == Some(ValidatorState::Jailed);

                // The validator must be known
                state.is_validator(&id.validator, pipeline)
                    // The amount must be available to unbond
                    && is_withdrawable && !is_jailed
            }
            Transition::Misbehavior {
                address,
                slash_type: _,
                infraction_epoch,
                height: _,
            } => {
                let is_validator =
                    state.is_validator(address, *infraction_epoch);

                // The infraction epoch cannot be in the future or more than
                // unbonding_len epochs in the past
                let current_epoch = state.epoch;
                let valid_epoch = *infraction_epoch <= current_epoch
                    && current_epoch.0 - infraction_epoch.0
                        <= state.params.unbonding_len;

                is_validator && valid_epoch

                // TODO: any others conditions?
            }
            Transition::UnjailValidator { address } => {
                // Validator address must be jailed thru the pipeline epoch
                for epoch in Epoch::iter_bounds_inclusive(
                    state.epoch,
                    state.epoch + state.params.pipeline_len,
                ) {
                    if state
                        .validator_states
                        .get(&epoch)
                        .unwrap()
                        .get(address)
                        .cloned()
                        .unwrap()
                        != ValidatorState::Jailed
                    {
                        return false;
                    }
                }
                // Most recent misbehavior is >= unbonding_len epochs away from
                // current epoch
                if let Some(last_slash_epoch) =
                    state.validator_last_slash_epochs.get(address)
                {
                    if state.epoch.0 - last_slash_epoch.0
                        < state.params.unbonding_len
                    {
                        return false;
                    }
                }

                true
                // TODO: any others?
            }
        }
    }
}

impl AbstractPosState {
    /// Copy validator sets and validator states at the given epoch from its
    /// predecessor
    fn copy_discrete_epoched_data(&mut self, epoch: Epoch) {
        let prev_epoch = epoch.prev();
        // Copy the non-delta data from the last epoch into the new one
        self.consensus_set.insert(
            epoch,
            self.consensus_set.get(&prev_epoch).unwrap().clone(),
        );
        self.below_capacity_set.insert(
            epoch,
            self.below_capacity_set.get(&prev_epoch).unwrap().clone(),
        );
        self.validator_states.insert(
            epoch,
            self.validator_states.get(&prev_epoch).unwrap().clone(),
        );
        self.validator_stakes.insert(
            epoch,
            self.validator_stakes.get(&prev_epoch).unwrap().clone(),
        );
    }

    /// Update a bond with bonded or unbonded change
    fn update_bond(&mut self, id: &BondId, change: token::Change) {
        let bonds = self.bonds.entry(self.pipeline()).or_default();
        let bond = bonds.entry(id.clone()).or_default();
        *bond += change;
        // Remove fully unbonded entries
        if *bond == 0 {
            bonds.remove(id);
        }
    }

    /// Update validator's total stake with bonded or unbonded change
    fn update_validator_total_stake(
        &mut self,
        validator: &Address,
        change: token::Change,
    ) {
        let total_stakes = self
            .validator_stakes
            .entry(self.pipeline())
            .or_default()
            .entry(validator.clone())
            .or_default();
        *total_stakes += change;
    }

    /// Update validator in sets with bonded or unbonded change
    fn update_validator_sets(
        &mut self,
        validator: &Address,
        change: token::Change,
    ) {
        let pipeline = self.pipeline();
        let consensus_set = self.consensus_set.entry(pipeline).or_default();
        let below_cap_set =
            self.below_capacity_set.entry(pipeline).or_default();
        let validator_stakes = self.validator_stakes.get(&pipeline).unwrap();
        let validator_states =
            self.validator_states.get_mut(&pipeline).unwrap();

        let state = validator_states.get(validator).unwrap();

        let this_val_stake_pre = *validator_stakes.get(validator).unwrap();
        let this_val_stake_post =
            token::Amount::from_change(this_val_stake_pre + change);
        let this_val_stake_pre = token::Amount::from_change(
            *validator_stakes.get(validator).unwrap(),
        );

        match state {
            ValidatorState::Consensus => {
                println!("Validator initially in consensus");
                // Remove from the prior stake
                let vals =
                    consensus_set.entry(dbg!(this_val_stake_pre)).or_default();
                dbg!(&vals);
                vals.retain(|addr| addr != validator);
                dbg!(&vals);

                if vals.is_empty() {
                    consensus_set.remove(&this_val_stake_pre);
                }

                // If unbonding, check the max below-cap validator's state if we
                // need to do a swap
                if change < token::Change::default() {
                    if let Some(mut max_below_cap) = below_cap_set.last_entry()
                    {
                        let max_below_cap_stake = *max_below_cap.key();
                        if max_below_cap_stake.0 > this_val_stake_post {
                            // Swap this validator with the max below-cap
                            let vals = max_below_cap.get_mut();
                            let first_val = vals.pop_front().unwrap();
                            // Remove the key if there's nothing left
                            if vals.is_empty() {
                                below_cap_set.remove(&max_below_cap_stake);
                            }
                            // Do the swap in the validator sets
                            consensus_set
                                .entry(max_below_cap_stake.0)
                                .or_default()
                                .push_back(first_val.clone());
                            below_cap_set
                                .entry(this_val_stake_post.into())
                                .or_default()
                                .push_back(validator.clone());

                            // Change the validator states
                            validator_states
                                .insert(first_val, ValidatorState::Consensus);
                            validator_states.insert(
                                validator.clone(),
                                ValidatorState::BelowCapacity,
                            );

                            // And we're done here
                            return;
                        }
                    }
                }

                // Insert with the posterior stake
                consensus_set
                    .entry(this_val_stake_post)
                    .or_default()
                    .push_back(validator.clone());
            }
            ValidatorState::BelowCapacity => {
                println!("Validator initially in below-cap");

                // Remove from the prior stake
                let vals =
                    below_cap_set.entry(this_val_stake_pre.into()).or_default();
                vals.retain(|addr| addr != validator);
                if dbg!(vals).is_empty() {
                    below_cap_set.remove(&this_val_stake_pre.into());
                }

                // If bonding, check the min consensus validator's state if we
                // need to do a swap
                if change >= token::Change::default() {
                    // dbg!(&consensus_set);
                    if let Some(mut min_consensus) = consensus_set.last_entry()
                    {
                        // dbg!(&min_consensus);
                        let min_consensus_stake = *min_consensus.key();
                        if dbg!(min_consensus_stake) > dbg!(this_val_stake_post)
                        {
                            // Swap this validator with the max consensus
                            let vals = min_consensus.get_mut();
                            let last_val = vals.pop_back().unwrap();
                            // Remove the key if there's nothing left
                            if vals.is_empty() {
                                consensus_set.remove(&min_consensus_stake);
                            }
                            // Do the swap in the validator sets
                            below_cap_set
                                .entry(min_consensus_stake.into())
                                .or_default()
                                .push_back(last_val.clone());
                            consensus_set
                                .entry(this_val_stake_post)
                                .or_default()
                                .push_back(validator.clone());

                            // Change the validator states
                            validator_states.insert(
                                validator.clone(),
                                ValidatorState::Consensus,
                            );
                            validator_states.insert(
                                last_val,
                                ValidatorState::BelowCapacity,
                            );

                            // And we're done here
                            return;
                        }
                    }
                }

                // Insert with the posterior stake
                below_cap_set
                    .entry(this_val_stake_post.into())
                    .or_default()
                    .push_back(validator.clone());
            }
            ValidatorState::Inactive => {
                panic!("unexpected state")
            }
            ValidatorState::Jailed => {
                panic!("unexpected state (jailed)")
            }
        }
    }

    /// Get the pipeline epoch
    fn pipeline(&self) -> Epoch {
        self.epoch + self.params.pipeline_len
    }

    /// Check if the given address is of a known validator
    fn is_validator(&self, validator: &Address, epoch: Epoch) -> bool {
        let is_in_consensus = self
            .consensus_set
            .get(&epoch)
            .unwrap()
            .iter()
            .any(|(_stake, vals)| vals.iter().any(|val| val == validator));
        if is_in_consensus {
            return true;
        }
        self.below_capacity_set
            .get(&epoch)
            .unwrap()
            .iter()
            .any(|(_stake, vals)| vals.iter().any(|val| val == validator))
    }

    fn is_in_consensus_w_info(
        &self,
        validator: &Address,
        epoch: Epoch,
    ) -> Option<(usize, token::Amount)> {
        let mut is_in_consensus: Option<(usize, token::Amount)> = None;
        for (stake, vals) in self.consensus_set.get(&epoch).unwrap() {
            if let Some(index) = vals.iter().position(|val| val == validator) {
                is_in_consensus = Some((index, *stake));
                break;
            }
        }
        is_in_consensus
    }

    fn is_in_below_capacity_w_info(
        &self,
        validator: &Address,
        epoch: Epoch,
    ) -> Option<(usize, token::Amount)> {
        let mut is_in_bc: Option<(usize, token::Amount)> = None;
        for (stake, vals) in self.below_capacity_set.get(&epoch).unwrap() {
            if let Some(index) = vals.iter().position(|val| val == validator) {
                is_in_bc = Some((index, (*stake).into()));
                break;
            }
        }
        is_in_bc
    }

    /// Find the sums of the bonds across all epochs
    fn bond_sums(&self) -> HashMap<BondId, token::Change> {
        self.bonds.iter().fold(
            HashMap::<BondId, token::Change>::new(),
            |mut acc, (_epoch, bonds)| {
                for (id, delta) in bonds {
                    let entry = acc.entry(id.clone()).or_default();
                    *entry += delta;
                    // Remove entries that are fully unbonded
                    if *entry == 0 {
                        acc.remove(id);
                    }
                }
                acc
            },
        )
    }

    /// Find the sums of withdrawable unbonds
    fn withdrawable_unbonds(&self) -> HashMap<BondId, token::Amount> {
        self.unbonds.iter().fold(
            HashMap::<BondId, token::Amount>::new(),
            |mut acc, (epoch, unbonds)| {
                if *epoch <= self.epoch {
                    for (id, amount) in unbonds {
                        if *amount > token::Amount::default() {
                            *acc.entry(id.clone()).or_default() += *amount;
                        }
                    }
                }
                acc
            },
        )
    }

    /// Conpute the cubic slashing rate for the current epoch
    fn cubic_slash_rate(&self) -> Decimal {
        let window_width = self.params.cubic_slashing_window_length;
        let epoch_start = Epoch::from(
            self.epoch.0.checked_sub(window_width).unwrap_or_default(),
        );
        let epoch_end = self.epoch + window_width;

        // Calculate cubic slashing rate with the concrete state
        let mut vp_frac_sum = Decimal::default();
        for epoch in Epoch::iter_bounds_inclusive(epoch_start, epoch_end) {
            let total_stake =
                self.validator_stakes.get(&epoch).unwrap().iter().fold(
                    token::Amount::default(),
                    |sum, (_, val_stake)| {
                        sum + token::Amount::from_change(*val_stake)
                    },
                );
            let enqueued_slashes = self.enqueued_slashes.get(&epoch);
            if let Some(enqueued_slashes) = enqueued_slashes {
                for (validator, slashes) in enqueued_slashes.iter() {
                    let val_stake = token::Amount::from_change(
                        self.validator_stakes
                            .get(&self.epoch)
                            .unwrap()
                            .get(validator)
                            .cloned()
                            .unwrap_or_default(),
                    );
                    vp_frac_sum += Decimal::from(slashes.len())
                        * Decimal::from(val_stake)
                        / Decimal::from(total_stake);
                }
            }
        }
        let vp_frac_sum = cmp::min(Decimal::ONE, vp_frac_sum);

        cmp::min(dec!(9) * vp_frac_sum * vp_frac_sum, Decimal::ONE)
    }

    fn compute_amount_after_slashing(
        &self,
        slashes: &mut Vec<Slash>,
        amount: token::Amount,
    ) -> token::Amount {
        let mut computed_amounts = Vec::<SlashedAmount>::new();
        let mut updated_amount = amount;
        // Sort slashes by epoch
        slashes.sort_by(|s1, s2| s1.epoch.cmp(&s2.epoch));

        let mut indices_to_remove = Vec::<usize>::new();
        let mut computed_to_add = Vec::<SlashedAmount>::new();
        for slash in slashes {
            for (idx, slashed_amount) in computed_amounts.iter().enumerate() {
                if slashed_amount.epoch + self.params.unbonding_len
                    < slash.epoch
                {
                    updated_amount -= slashed_amount.amount;
                    indices_to_remove.push(idx);
                }
                computed_to_add.push(SlashedAmount {
                    amount: decimal_mult_amount(slash.rate, updated_amount),
                    epoch: slash.epoch,
                });
            }
        }
        for slashed_amount in computed_to_add.into_iter() {
            computed_amounts.push(slashed_amount);
        }
        updated_amount
            - computed_amounts
                .iter()
                .fold(token::Amount::default(), |sum, computed| {
                    sum + computed.amount
                })
    }
}

/// Arbitrary bond transition that adds tokens to an existing bond
fn add_arb_bond_amount(
    state: &AbstractPosState,
) -> impl Strategy<Value = Transition> {
    let bond_ids = state
        .bonds
        .iter()
        .flat_map(|(_epoch, bonds)| {
            bonds.keys().cloned().collect::<HashSet<_>>()
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let arb_bond_id = prop::sample::select(bond_ids);
    (arb_bond_id, arb_bond_amount())
        .prop_map(|(id, amount)| Transition::Bond { id, amount })
}

/// Arbitrary delegation to one of the validators
fn arb_delegation(
    state: &AbstractPosState,
) -> impl Strategy<Value = Transition> {
    // Ensure that no bond can be generated to a jailed validator
    let validators = state.consensus_set.iter().fold(
        HashSet::new(),
        |mut acc, (_epoch, vals)| {
            for vals in vals.values() {
                for validator in vals {
                    if *state
                        .validator_states
                        .get(&state.epoch)
                        .unwrap()
                        .get(validator)
                        .unwrap()
                        != ValidatorState::Jailed
                    {
                        acc.insert(validator.clone());
                    }
                }
            }
            acc
        },
    );
    let validator_vec = validators.clone().into_iter().collect::<Vec<_>>();
    let arb_source = address::testing::arb_non_internal_address()
        .prop_filter("Must be a non-validator address", move |addr| {
            !validators.contains(addr)
        });
    let arb_validator = prop::sample::select(validator_vec);
    (arb_source, arb_validator, arb_bond_amount()).prop_map(
        |(source, validator, amount)| Transition::Bond {
            id: BondId { source, validator },
            amount,
        },
    )
}

// Bond up to 10 tokens (10M micro units) to avoid overflows
pub fn arb_bond_amount() -> impl Strategy<Value = token::Amount> {
    (1_u64..10).prop_map(token::Amount::from)
}

/// Arbitrary validator misbehavior
fn arb_slash(state: &AbstractPosState) -> impl Strategy<Value = Transition> {
    let validators = state.consensus_set.iter().fold(
        Vec::new(),
        |mut acc, (_epoch, vals)| {
            for vals in vals.values() {
                for validator in vals {
                    acc.push(validator.clone());
                }
            }
            acc
        },
    );
    let current_epoch = state.epoch.0;

    let arb_validator = prop::sample::select(validators);
    let slash_types =
        vec![SlashType::LightClientAttack, SlashType::DuplicateVote];
    let arb_type = prop::sample::select(slash_types);
    let arb_epoch = (current_epoch
        .checked_sub(state.params.unbonding_len)
        .unwrap_or_default()..=current_epoch)
        .prop_map(Epoch::from);
    (arb_validator, arb_type, arb_epoch).prop_map(
        |(validator, slash_type, infraction_epoch)| Transition::Misbehavior {
            address: validator,
            slash_type,
            infraction_epoch,
            height: 0,
        },
    )
}
