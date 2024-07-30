#[cfg(test)]
mod tests {

    use borsh::{BorshDeserialize, BorshSerialize};
    use namada_sdk::address::{self, Address};
    use namada_sdk::storage;
    use namada_tx_prelude::collections::{lazy_vec, LazyCollection, LazyVec};
    use namada_tx_prelude::storage::KeySeg;
    use namada_vp_prelude::collection_validation::{self, LazyCollectionExt};
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use proptest_state_machine::{
        prop_state_machine, ReferenceStateMachine, StateMachineTest,
    };
    use test_log::test;

    use crate::tx::tx_host_env;
    use crate::vp::vp_host_env;

    prop_state_machine! {
        #![proptest_config(Config {
            // Instead of the default 256, we only run 5 because otherwise it
            // takes too long and it's preferable to crank up the number of
            // transitions instead, to allow each case to run for more epochs as
            // some issues only manifest once the model progresses further.
            // Additionally, more cases will be explored every time this test is
            // executed in the CI.
            cases: 5,
            verbose: 1,
            .. Config::default()
        })]
        #[test]
        fn lazy_vec_api_state_machine_test(sequential 1..100 => ConcreteLazyVecState);
    }

    /// Some borsh-serializable type with arbitrary fields to be used inside
    /// LazyVec state machine test
    #[derive(
        Clone,
        Debug,
        BorshSerialize,
        BorshDeserialize,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
    )]
    struct TestVecItem {
        x: u64,
        y: bool,
    }

    /// A `StateMachineTest` implemented on this struct manipulates it with
    /// `Transition`s, which are also being accumulated into
    /// `current_transitions`. It then:
    ///
    /// - checks its state against an in-memory `std::collections::Vec`
    /// - runs validation and checks that the `LazyVec::Action`s reported from
    ///   validation match with transitions that were applied
    ///
    /// Additionally, one of the transitions is to commit a block and/or
    /// transaction, during which the currently accumulated state changes are
    /// persisted, or promoted from transaction write log to block's write log.
    #[derive(Debug)]
    struct ConcreteLazyVecState {
        /// Address is used to prefix the storage key of the `lazy_vec` in
        /// order to simulate a transaction and a validity predicate
        /// check from changes on the `lazy_vec`
        address: Address,
        /// In the test, we apply the same transitions on the `lazy_vec` as on
        /// `eager_vec` to check that `lazy_vec`'s state is consistent with
        /// `eager_vec`.
        eager_vec: Vec<TestVecItem>,
        /// Handle to a lazy vec
        lazy_vec: LazyVec<TestVecItem>,
        /// Valid LazyVec changes in the current transaction
        current_transitions: Vec<Transition<TestVecItem>>,
    }

    #[derive(Clone, Debug)]
    struct AbstractLazyVecState {
        /// Valid LazyVec changes in the current transaction
        valid_transitions: Vec<Transition<TestVecItem>>,
        /// Valid LazyVec changes committed to storage
        committed_transitions: Vec<Transition<TestVecItem>>,
    }

    /// Possible transitions that can modify a [`LazyVec`]. This roughly
    /// corresponds to the methods that have `StorageWrite` access and is very
    /// similar to [`Action`]
    #[derive(Clone, Debug)]
    pub enum Transition<T> {
        /// Commit all valid transitions in the current transaction
        CommitTx,
        /// Commit all valid transitions in the current transaction and also
        /// commit the current block
        CommitTxAndBlock,
        /// Push a value `T` into a [`LazyVec<T>`]
        Push(T),
        /// Pop a value from a [`LazyVec<T>`]
        Pop,
        /// Update a value `T` at index from pre to post state in a
        /// [`LazyVec<T>`]
        Update {
            /// index at which the value is updated
            index: lazy_vec::Index,
            /// value to update the element to
            value: T,
        },
    }

    impl ReferenceStateMachine for AbstractLazyVecState {
        type State = Self;
        type Transition = Transition<TestVecItem>;

        fn init_state() -> BoxedStrategy<Self::State> {
            Just(Self {
                valid_transitions: vec![],
                committed_transitions: vec![],
            })
            .boxed()
        }

        // Apply a random transition to the state
        fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
            let length = state.len();
            if length == 0 {
                prop_oneof![
                    1 => Just(Transition::CommitTx),
                    1 => Just(Transition::CommitTxAndBlock),
                    3 => arb_test_vec_item().prop_map(Transition::Push)
                ]
                .boxed()
            } else {
                let arb_index = || {
                    let indices: Vec<lazy_vec::Index> = (0..length).collect();
                    proptest::sample::select(indices)
                };
                prop_oneof![
		    1 => Just(Transition::CommitTx),
		    1 => Just(Transition::CommitTxAndBlock),
		    3 => (arb_index(), arb_test_vec_item()).prop_map(
                             |(index, value)| Transition::Update { index, value }
                         ),
		    3 => Just(Transition::Pop),
		    5 => arb_test_vec_item().prop_map(Transition::Push),
		]
                .boxed()
            }
        }

        fn apply(
            mut state: Self::State,
            transition: &Self::Transition,
        ) -> Self::State {
            match transition {
                Transition::CommitTx => {
                    let valid_actions_to_commit =
                        std::mem::take(&mut state.valid_transitions);
                    state.committed_transitions.extend(valid_actions_to_commit);
                }
                _ => state.valid_transitions.push(transition.clone()),
            }
            state
        }

        fn preconditions(
            state: &Self::State,
            transition: &Self::Transition,
        ) -> bool {
            let length = state.len();
            if length == 0 {
                // Ensure that the pop or update transitions are not applied to
                // an empty state
                !matches!(
                    transition,
                    Transition::Pop | Transition::Update { .. }
                )
            } else if let Transition::Update { index, .. } = transition {
                // Ensure that the update index is a valid one
                *index < (length - 1)
            } else {
                true
            }
        }
    }

    impl StateMachineTest for ConcreteLazyVecState {
        type Reference = AbstractLazyVecState;
        type SystemUnderTest = Self;

        fn init_test(
            _initial_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            // Init transaction env in which we'll be applying the transitions
            tx_host_env::init();

            // The lazy_vec's path must be prefixed by the address to be able
            // to trigger a validity predicate on it
            let address = address::testing::established_address_1();
            tx_host_env::with(|env| env.spawn_accounts([&address]));
            let lazy_vec_prefix: storage::Key = address.to_db_key().into();

            Self {
                address,
                eager_vec: vec![],
                lazy_vec: LazyVec::open(
                    lazy_vec_prefix.push(&"arbitrary".to_string()).unwrap(),
                ),
                current_transitions: vec![],
            }
        }

        fn apply(
            mut state: Self::SystemUnderTest,
            _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
            transition: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            // Apply transitions in transaction env
            let ctx = tx_host_env::ctx();

            // Persist the transitions in the current tx, or clear previous ones
            // if we're committing a tx
            match &transition {
                Transition::CommitTx | Transition::CommitTxAndBlock => {
                    state.current_transitions = vec![];
                }
                _ => {
                    state.current_transitions.push(transition.clone());
                }
            }

            // Transition application on lazy vec and post-conditions:
            match &transition {
                Transition::CommitTx => {
                    // commit the tx without committing the block
                    tx_host_env::with(|env| env.state.commit_tx_batch());
                }
                Transition::CommitTxAndBlock => {
                    // commit the tx and the block
                    tx_host_env::commit_tx_and_block();
                }
                Transition::Push(value) => {
                    let old_len = state.lazy_vec.len(ctx).unwrap();

                    state.lazy_vec.push(ctx, value.clone()).unwrap();

                    // Post-conditions:
                    let new_len = state.lazy_vec.len(ctx).unwrap();
                    let stored_value =
                        state.lazy_vec.get(ctx, new_len - 1).unwrap().unwrap();
                    assert_eq!(
                        &stored_value, value,
                        "the new item must be added to the back"
                    );
                    assert_eq!(old_len + 1, new_len, "length must increment");

                    state.assert_validation_accepted(new_len);
                }
                Transition::Pop => {
                    let old_len = state.lazy_vec.len(ctx).unwrap();

                    let popped = state.lazy_vec.pop(ctx).unwrap().unwrap();

                    // Post-conditions:
                    let new_len = state.lazy_vec.len(ctx).unwrap();
                    assert_eq!(old_len, new_len + 1, "length must decrement");
                    assert_eq!(
                        &popped,
                        state.eager_vec.last().unwrap(),
                        "popped element matches the last element in eager vec \
                         before it's updated"
                    );

                    state.assert_validation_accepted(new_len);
                }
                Transition::Update { index, value } => {
                    let old_len = state.lazy_vec.len(ctx).unwrap();
                    let old_val =
                        state.lazy_vec.get(ctx, *index).unwrap().unwrap();

                    state.lazy_vec.update(ctx, *index, value.clone()).unwrap();

                    // Post-conditions:
                    let new_len = state.lazy_vec.len(ctx).unwrap();
                    let new_val =
                        state.lazy_vec.get(ctx, *index).unwrap().unwrap();
                    assert_eq!(old_len, new_len, "length must not change");
                    assert_eq!(
                        &old_val,
                        state.eager_vec.get(*index as usize).unwrap(),
                        "old value must match the value at the same index in \
                         the eager vec before it's updated"
                    );
                    assert_eq!(
                        &new_val, value,
                        "new value must match that which was passed into the \
                         Transition::Update"
                    );

                    state.assert_validation_accepted(new_len);
                }
            }

            // Apply transition in the eager vec for comparison
            apply_transition_on_eager_vec(&mut state.eager_vec, &transition);

            // Global post-conditions:

            // All items in eager vec must be present in lazy vec
            for (ix, expected_item) in state.eager_vec.iter().enumerate() {
                let got = state
                    .lazy_vec
                    .get(ctx, ix as lazy_vec::Index)
                    .unwrap()
                    .expect("The expected item must be present in lazy vec");
                assert_eq!(expected_item, &got, "at index {ix}");
            }

            // All items in lazy vec must be present in eager vec
            for (ix, expected_item) in
                state.lazy_vec.iter(ctx).unwrap().enumerate()
            {
                let expected_item = expected_item.unwrap();
                let got = state
                    .eager_vec
                    .get(ix)
                    .expect("The expected item must be present in eager vec");
                assert_eq!(&expected_item, got, "at index {ix}");
            }

            state
        }
    }

    impl AbstractLazyVecState {
        /// Find the length of the vector from the applied transitions
        fn len(&self) -> u64 {
            (vec_len_diff_from_transitions(self.committed_transitions.iter())
                + vec_len_diff_from_transitions(self.valid_transitions.iter()))
            .try_into()
            .expect(
                "It shouldn't be possible to underflow length from all \
                 transactions applied in abstract state",
            )
        }
    }

    /// Find the difference in length of the vector from the applied transitions
    fn vec_len_diff_from_transitions<'a>(
        all_transitions: impl Iterator<Item = &'a Transition<TestVecItem>>,
    ) -> i64 {
        let mut push_count: i64 = 0;
        let mut pop_count: i64 = 0;

        for trans in all_transitions {
            match trans {
                Transition::CommitTx
                | Transition::CommitTxAndBlock
                | Transition::Update { .. } => {}
                Transition::Push(_) => push_count += 1,
                Transition::Pop => pop_count += 1,
            }
        }
        push_count - pop_count
    }

    impl ConcreteLazyVecState {
        fn assert_validation_accepted(&self, new_vec_len: u64) {
            // Init the VP env from tx env in which we applied the vec
            // transitions
            let tx_env = tx_host_env::take();
            vp_host_env::init_from_tx(self.address.clone(), tx_env, |_| {});

            // Simulate a validity predicate run using the lazy vec's validation
            // helpers
            let changed_keys =
                vp_host_env::with(|env| env.all_touched_storage_keys());

            let mut validation_builder = None;

            // Push followed by pop is a no-op, in which case we'd still see the
            // changed keys for these actions, but they wouldn't affect the
            // validation result and they never get persisted, but we'd still
            // them as changed key here. To guard against this case,
            // we check that `vec_len_from_transitions` is not empty.
            let vec_len_diff =
                vec_len_diff_from_transitions(self.current_transitions.iter());

            // To help debug validation issues...
            dbg!(
                &self.current_transitions,
                &changed_keys
                    .iter()
                    .map(storage::Key::to_string)
                    .collect::<Vec<_>>()
            );

            for key in &changed_keys {
                let is_sub_key = self
                    .lazy_vec
                    .accumulate(
                        vp_host_env::ctx(),
                        &mut validation_builder,
                        key,
                    )
                    .unwrap();

                assert!(
                    is_sub_key,
                    "We're only modifying the lazy_vec's keys here. Key: \
                     \"{key}\", vec length diff {vec_len_diff}"
                );
            }
            if !changed_keys.is_empty() && vec_len_diff != 0 {
                assert!(
                    validation_builder.is_some(),
                    "If some keys were changed, the builder must get filled in"
                );
                let actions = LazyVec::<TestVecItem>::validate(
                    validation_builder.unwrap(),
                )
                .expect(
                    "With valid transitions only, validation should always \
                     pass",
                );
                let mut actions_to_check = actions.clone();

                // Check that every transition has a corresponding action from
                // validation. We drop the found actions to check that all
                // actions are matched too.
                let current_transitions = normalize_transitions(
                    &self.current_transitions,
                    new_vec_len,
                );
                for transition in &current_transitions {
                    use collection_validation::lazy_vec::Action;
                    match transition {
                        Transition::CommitTx | Transition::CommitTxAndBlock => {
                        }
                        Transition::Push(expected_val) => {
                            let mut ix = 0;
                            while ix < actions_to_check.len() {
                                if let Action::Push(val) = &actions_to_check[ix]
                                {
                                    if expected_val == val {
                                        actions_to_check.remove(ix);
                                        break;
                                    }
                                }
                                ix += 1;
                            }
                        }
                        Transition::Pop => {
                            let mut ix = 0;
                            while ix < actions_to_check.len() {
                                if let Action::Pop(_val) = &actions_to_check[ix]
                                {
                                    actions_to_check.remove(ix);
                                    break;
                                }
                                ix += 1;
                            }
                        }
                        Transition::Update {
                            index: expected_index,
                            value,
                        } => {
                            let mut ix = 0;
                            while ix < actions_to_check.len() {
                                if let Action::Update {
                                    index,
                                    pre: _,
                                    post,
                                } = &actions_to_check[ix]
                                {
                                    if expected_index == index && post == value
                                    {
                                        actions_to_check.remove(ix);
                                        break;
                                    }
                                }
                                ix += 1;
                            }
                        }
                    }
                }

                assert!(
                    actions_to_check.is_empty(),
                    "All the actions reported from validation {actions:#?} \
                     should have been matched with SM transitions \
                     {current_transitions:#?}, but these actions didn't \
                     match: {actions_to_check:#?}",
                )
            }

            // Put the tx_env back before checking the result
            tx_host_env::set_from_vp_env(vp_host_env::take());
        }
    }

    /// Generate an arbitrary `TestVecItem`
    fn arb_test_vec_item() -> impl Strategy<Value = TestVecItem> {
        (any::<u64>(), any::<bool>()).prop_map(|(x, y)| TestVecItem { x, y })
    }

    /// Apply `Transition` on an eager `Vec`.
    fn apply_transition_on_eager_vec(
        vec: &mut Vec<TestVecItem>,
        transition: &Transition<TestVecItem>,
    ) {
        match transition {
            Transition::CommitTx | Transition::CommitTxAndBlock => {}
            Transition::Push(value) => vec.push(value.clone()),
            Transition::Pop => {
                let _popped = vec.pop();
            }
            Transition::Update { index, value } => {
                let entry = vec.get_mut(*index as usize).unwrap();
                *entry = value.clone();
            }
        }
    }

    /// Normalize transitions:
    /// - pop at ix + push(val) at ix -> update(ix, val)
    /// - push(val) at ix + update(ix, new_val) -> push(new_val) at ix
    /// - update(ix, val) + update(ix, new_val) -> update(ix, new_val)
    ///
    /// Note that the normalizable transitions pairs do not have to be directly
    /// next to each other, but their order does matter.
    fn normalize_transitions(
        transitions: &[Transition<TestVecItem>],
        new_vec_len: u64,
    ) -> Vec<Transition<TestVecItem>> {
        let stack_start_pos = ((new_vec_len as i64)
            - vec_len_diff_from_transitions(transitions.iter()))
            as u64;
        let mut stack_pos = stack_start_pos;
        let mut collapsed = vec![];
        'outer: for transition in transitions {
            match transition {
                Transition::CommitTx | Transition::CommitTxAndBlock => {
                    collapsed.push(transition.clone())
                }
                Transition::Push(value) => {
                    // If there are some pops, the last one can be collapsed
                    // with this push
                    if stack_pos < stack_start_pos {
                        // Find the pop from the back
                        let mut found_ix = None;
                        for (ix, transition) in
                            collapsed.iter().enumerate().rev()
                        {
                            if let Transition::Pop = transition {
                                found_ix = Some(ix);
                                break;
                            }
                        }
                        let ix = found_ix.expect("Pop must be found");
                        // pop at ix + push(val) at ix -> update(ix, val)

                        // Replace the Pop with an Update and don't insert the
                        // Push
                        *collapsed.get_mut(ix).unwrap() = Transition::Update {
                            index: stack_pos,
                            value: value.clone(),
                        };
                    } else {
                        collapsed.push(transition.clone());
                    }
                    stack_pos += 1;
                }
                Transition::Pop => {
                    collapsed.push(transition.clone());
                    stack_pos -= 1;
                }
                Transition::Update { index, value } => {
                    // If there are some pushes, check if one of them is at the
                    // same index as this update
                    if stack_pos > stack_start_pos {
                        let mut current_pos = stack_start_pos;
                        for (ix, collapsed_transition) in
                            collapsed.iter().enumerate()
                        {
                            match collapsed_transition {
                                Transition::CommitTx
                                | Transition::CommitTxAndBlock => {}
                                Transition::Push(_) => {
                                    if &current_pos == index {
                                        // push(val) at `ix` + update(ix,
                                        // new_val) ->
                                        // push(new_val) at `ix`

                                        // Replace the Push with the new Push of
                                        // Update's
                                        // value and don't insert the Update
                                        *collapsed.get_mut(ix).unwrap() =
                                            Transition::Push(value.clone());
                                        continue 'outer;
                                    }
                                    current_pos += 1;
                                }
                                Transition::Pop => {
                                    current_pos -= 1;
                                }
                                Transition::Update {
                                    index: prev_update_index,
                                    value: _,
                                } => {
                                    if index == prev_update_index {
                                        // update(ix, val) + update(ix, new_val)
                                        // -> update(ix, new_val)

                                        // Replace the Update with the new
                                        // Update instead of inserting it
                                        *collapsed.get_mut(ix).unwrap() =
                                            transition.clone();
                                        continue 'outer;
                                    }
                                }
                            }
                        }
                    }
                    collapsed.push(transition.clone())
                }
            }
        }
        collapsed
    }
}
