//! Test PoS transitions with a state machine

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use itertools::Itertools;
use namada_core::ledger::storage::testing::TestWlStorage;
use namada_core::ledger::storage_api::{token, StorageRead};
use namada_core::types::address::Address;
use namada_core::types::key::common::PublicKey;
use namada_core::types::storage::Epoch;
use proptest::prelude::*;
use proptest::prop_state_machine;
use proptest::state_machine::{AbstractStateMachine, StateMachineTest};
use proptest::test_runner::Config;
use rust_decimal::Decimal;
// Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to see
// `tracing` logs from tests
use test_log::test;

use super::arb_genesis_validators;
use crate::parameters::testing::arb_pos_params;
use crate::parameters::PosParams;
use crate::types::{
    BondId, GenesisValidator, ReverseOrdTokenAmount, ValidatorState,
    WeightedValidator,
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
    /// Bonds delta values
    bonds: BTreeMap<Epoch, HashMap<BondId, token::Change>>,
    /// Validator stakes delta values (sum of all their bonds deltas)
    total_stakes: BTreeMap<Epoch, HashMap<Address, token::Change>>,
    /// Consensus validator set
    consensus_set: BTreeMap<Epoch, BTreeMap<token::Amount, VecDeque<Address>>>,
    /// Below-capacity validator set
    below_capacity_set:
        BTreeMap<Epoch, BTreeMap<ReverseOrdTokenAmount, VecDeque<Address>>>,
    /// Validator states
    validator_states: BTreeMap<Epoch, HashMap<Address, ValidatorState>>,
}

/// The PoS system under test
#[derive(Debug)]
struct ConcretePosState {
    /// Storage - contains all the PoS state
    s: TestWlStorage,
}

/// State machine transitions
#[allow(clippy::large_enum_variant)]
// TODO: remove once all the transitions are being covered
#[allow(dead_code)]
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
                token::credit_tokens(
                    &mut state.s,
                    &native_token,
                    &id.source,
                    amount,
                )
                .unwrap();

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
                    id,
                    amount,
                    validator_stake_before_bond_cur,
                    validator_stake_before_bond_pipeline,
                );
            }
            Transition::Unbond { id: _, amount: _ } => todo!(),
            Transition::Withdraw { id: _ } => todo!(),
        }
        state
    }

    fn invariants(_state: &Self::ConcreteState) {}

    // Overridden to add some logging, but same behavior as original
    fn test_sequential(
        initial_state: <Self::Abstract as AbstractStateMachine>::State,
        transitions: Vec<<Self::Abstract as AbstractStateMachine>::Transition>,
    ) {
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

        // Post-condition: The validator should be updated in exactly one of the
        // validator sets
        assert!(consensus_val.is_some() ^ below_cap_val.is_some());
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
}

impl AbstractStateMachine for AbstractPosState {
    type State = Self;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
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
                        .collect(),
                    bonds: Default::default(),
                    total_stakes: Default::default(),
                    consensus_set: Default::default(),
                    below_capacity_set: Default::default(),
                    validator_states: Default::default(),
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
                        state.total_stakes.entry(epoch).or_default();
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

                state
            })
            .boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        prop_oneof![
            Just(Transition::NextEpoch),
            add_arb_bond_amount(state),
            // TODO: add other transitions
        ]
        .boxed()
    }

    fn apply_abstract(
        mut state: Self::State,
        transition: &Self::Transition,
    ) -> Self::State {
        match transition {
            Transition::NextEpoch => {
                state.epoch = state.epoch.next();

                // Copy the non-delta data into pipeline epoch from its pred.
                state.copy_discrete_epoched_data(
                    state.epoch + state.params.pipeline_len,
                );
            }
            Transition::InitValidator {
                address,
                consensus_key: _,
                commission_rate: _,
                max_commission_rate_change: _,
            } => {
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
                let change = token::Change::from(*amount);
                state.update_bond(id, change);
                state.update_validator_total_stake(&id.validator, change);
                state.update_validator_sets(&id.validator, change);
            }
            Transition::Unbond { id, amount } => {
                let change = -token::Change::from(*amount);
                state.update_bond(id, change);
                state.update_validator_total_stake(&id.validator, change);
                state.update_validator_sets(&id.validator, change);
            }
            Transition::Withdraw { id: _ } => todo!(),
        }
        state
    }

    fn preconditions(
        state: &Self::State,
        transition: &Self::Transition,
    ) -> bool {
        match transition {
            Transition::NextEpoch => true,
            Transition::InitValidator {
                address,
                consensus_key: _,
                commission_rate: _,
                max_commission_rate_change: _,
            } => {
                let pipeline = state.epoch + state.params.pipeline_len;
                // The address must not belong to an existing validator
                !state.is_validator(address, pipeline)
            }
            Transition::Bond { id, amount: _ } => {
                let pipeline = state.epoch + state.params.pipeline_len;
                // A bond's validator must be known
                state.is_validator(&id.validator, pipeline)
            }
            Transition::Unbond { id: _, amount: _ } => todo!(),
            Transition::Withdraw { id: _ } => todo!(),
        }
    }
}

impl AbstractPosState {
    /// Copy validator sets and validator states at the given epoch from its
    /// predecessor
    fn copy_discrete_epoched_data(&mut self, epoch: Epoch) {
        let prev_epoch = Epoch(epoch.0 - 1);
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
    }

    /// Update a bond with bonded or unbonded change
    fn update_bond(&mut self, id: &BondId, change: token::Change) {
        let bonds = self.bonds.entry(self.pipeline()).or_default();
        bonds.insert(id.clone(), change);
    }

    /// Update validator's total stake with bonded or unbonded change
    fn update_validator_total_stake(
        &mut self,
        validator: &Address,
        change: token::Change,
    ) {
        let total_stakes = self
            .total_stakes
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
        let total_stakes = self.total_stakes.get(&pipeline).unwrap();
        let state = self
            .validator_states
            .get(&pipeline)
            .unwrap()
            .get(validator)
            .unwrap();

        let this_val_stake_pre = *total_stakes.get(validator).unwrap();
        let this_val_stake_post =
            token::Amount::from_change(this_val_stake_pre + change);
        let this_val_stake_pre =
            token::Amount::from_change(*total_stakes.get(validator).unwrap());

        match state {
            ValidatorState::Consensus => {
                // Remove from the prior stake
                let vals = consensus_set.entry(this_val_stake_pre).or_default();
                vals.retain(|addr| addr != validator);
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
                            // Remove the key is there's nothing left
                            if vals.is_empty() {
                                below_cap_set.remove(&max_below_cap_stake);
                            }
                            // Do the swap
                            consensus_set
                                .entry(max_below_cap_stake.0)
                                .or_default()
                                .push_back(first_val);
                            below_cap_set
                                .entry(this_val_stake_post.into())
                                .or_default()
                                .push_back(validator.clone());
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
                // Remove from the prior stake
                let vals =
                    below_cap_set.entry(this_val_stake_pre.into()).or_default();
                vals.retain(|addr| addr != validator);
                if vals.is_empty() {
                    below_cap_set.remove(&this_val_stake_pre.into());
                }

                // If bonding, check the min consensus validator's state if we
                // need to do a swap
                if change >= token::Change::default() {
                    if let Some(mut min_below_cap) = consensus_set.last_entry()
                    {
                        let min_consensus_stake = *min_below_cap.key();
                        if min_consensus_stake > this_val_stake_post {
                            // Swap this validator with the max consensus
                            let vals = min_below_cap.get_mut();
                            let last_val = vals.pop_back().unwrap();
                            // Remove the key is there's nothing left
                            if vals.is_empty() {
                                consensus_set.remove(&min_consensus_stake);
                            }
                            // Do the swap
                            below_cap_set
                                .entry(min_consensus_stake.into())
                                .or_default()
                                .push_back(last_val);
                            consensus_set
                                .entry(this_val_stake_post)
                                .or_default()
                                .push_back(validator.clone());
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

// Bond up to 10 tokens (10M micro units) to avoid overflows
pub fn arb_bond_amount() -> impl Strategy<Value = token::Amount> {
    (1_u64..10_000_000).prop_map(token::Amount::from)
}
