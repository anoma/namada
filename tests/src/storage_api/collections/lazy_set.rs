#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::convert::TryInto;

    use namada::types::address::{self, Address};
    use namada::types::storage;
    use namada_tx_prelude::collections::{LazyCollection, LazySet};
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
        fn lazy_set_api_state_machine_test(sequential 1..100 => ConcreteLazySetState);
    }

    /// Type of key used in the set
    type TestKey = u64;

    /// A `StateMachineTest` implemented on this struct manipulates it with
    /// `Transition`s, which are also being accumulated into
    /// `current_transitions`. It then:
    ///
    /// - checks its state against an in-memory `std::collections::BTreeSet`
    /// - runs validation and checks that the `LazySet::Action`s reported from
    ///   validation match with transitions that were applied
    ///
    /// Additionally, one of the transitions is to commit a block and/or
    /// transaction, during which the currently accumulated state changes are
    /// persisted, or promoted from transaction write log to block's write log.
    #[derive(Debug)]
    struct ConcreteLazySetState {
        /// Address is used to prefix the storage key of the `lazy_set` in
        /// order to simulate a transaction and a validity predicate
        /// check from changes on the `lazy_set`
        address: Address,
        /// In the test, we apply the same transitions on the `lazy_set` as on
        /// `eager_set` to check that `lazy_set`'s state is consistent with
        /// `eager_set`.
        eager_set: BTreeSet<TestKey>,
        /// Handle to a lazy set
        lazy_set: LazySet<TestKey>,
        /// Valid LazySet changes in the current transaction
        current_transitions: Vec<Transition>,
    }

    #[derive(Clone, Debug, Default)]
    struct AbstractLazySetState {
        /// Valid LazySet changes in the current transaction
        valid_transitions: Vec<Transition>,
        /// Valid LazySet changes committed to storage
        committed_transitions: Vec<Transition>,
    }

    /// Possible transitions that can modify a [`LazySet<TestKey>`].
    /// This roughly corresponds to the methods that have `StorageWrite`
    /// access and is very similar to [`Action`]
    #[derive(Clone, Debug)]
    enum Transition {
        /// Commit all valid transitions in the current transaction
        CommitTx,
        /// Commit all valid transitions in the current transaction and also
        /// commit the current block
        CommitTxAndBlock,
        /// Insert a key-val into a [`LazySet`]
        Insert(TestKey),
        /// Remove a key-val from a [`LazySet`]
        Remove(TestKey),
        /// Insert a key-val into a [`LazySet`]
        TryInsert { key: TestKey, is_present: bool },
    }

    impl ReferenceStateMachine for AbstractLazySetState {
        type State = Self;
        type Transition = Transition;

        fn init_state() -> BoxedStrategy<Self::State> {
            Just(Self::default()).boxed()
        }

        // Apply a random transition to the state
        fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
            let length = state.len();
            if length == 0 {
                prop_oneof![
                    1 => Just(Transition::CommitTx),
                    1 => Just(Transition::CommitTxAndBlock),
                    3 => arb_set_key().prop_map(Transition::Insert)
                ]
                .boxed()
            } else {
                let keys = state.find_existing_keys();
                let keys_clone = keys.clone();
                let arb_existing_set_key =
                    || proptest::sample::select(keys.clone());
                prop_oneof![
                    1 => Just(Transition::CommitTx),
                    1 => Just(Transition::CommitTxAndBlock),
                    3 => arb_existing_set_key().prop_map(Transition::Remove),
                    3 => arb_existing_set_key().prop_map(|key|
                            Transition::TryInsert {key, is_present: true}),
                    5 => (arb_set_key().prop_filter("insert on non-existing keys only", 
                        move |key| !keys.contains(key)))
                        .prop_map(Transition::Insert),
                    5 => (arb_set_key().prop_filter("try_insert on non-existing keys only", 
                        move |key| !keys_clone.contains(key)))
                        .prop_map(|key|
                            Transition::TryInsert {key, is_present: false}),
                ]
                .boxed()
            }
        }

        fn apply(
            mut state: Self::State,
            transition: &Self::Transition,
        ) -> Self::State {
            match transition {
                Transition::CommitTx | Transition::CommitTxAndBlock => {
                    let valid_actions_to_commit =
                        std::mem::take(&mut state.valid_transitions);
                    state
                        .committed_transitions
                        .extend(valid_actions_to_commit.into_iter());
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
            // Ensure that the remove or update transitions are not applied
            // to an empty state
            if length == 0 && matches!(transition, Transition::Remove(_)) {
                return false;
            }
            match transition {
                Transition::Remove(key) => {
                    let keys = state.find_existing_keys();
                    // Ensure that the update/remove key is an existing one
                    keys.contains(key)
                }
                Transition::Insert(key) => {
                    let keys = state.find_existing_keys();
                    // Ensure that the insert key is not an existing one
                    !keys.contains(key)
                }
                Transition::TryInsert { key, is_present } => {
                    let keys = state.find_existing_keys();
                    // Ensure that the `is_present` flag is correct
                    if *is_present {
                        keys.contains(key)
                    } else {
                        !keys.contains(key)
                    }
                }
                _ => true,
            }
        }
    }

    impl StateMachineTest for ConcreteLazySetState {
        type Reference = AbstractLazySetState;
        type SystemUnderTest = Self;

        fn init_test(
            _initial_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            // Init transaction env in which we'll be applying the transitions
            tx_host_env::init();

            // The lazy_set's path must be prefixed by the address to be able
            // to trigger a validity predicate on it
            let address = address::testing::established_address_1();
            tx_host_env::with(|env| env.spawn_accounts([&address]));
            let lazy_set_prefix: storage::Key = address.to_db_key().into();

            Self {
                address,
                eager_set: BTreeSet::new(),
                lazy_set: LazySet::open(
                    lazy_set_prefix.push(&"arbitrary".to_string()).unwrap(),
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

            // Transition application on lazy set and post-conditions:
            match &transition {
                Transition::CommitTx => {
                    // commit the tx without committing the block
                    tx_host_env::with(|env| env.wl_storage.commit_tx());
                }
                Transition::CommitTxAndBlock => {
                    // commit the tx and the block
                    tx_host_env::commit_tx_and_block();
                }
                Transition::Insert(key) => {
                    state.lazy_set.insert(ctx, *key).unwrap();

                    // Post-conditions:
                    let present = state.lazy_set.contains(ctx, key).unwrap();
                    assert!(present, "the new item must be added to the set");

                    state.assert_validation_accepted();
                }
                Transition::TryInsert { key, is_present } => {
                    let result = state.lazy_set.try_insert(ctx, *key);

                    // Post-conditions:
                    if *is_present {
                        assert!(result.is_err());
                    } else {
                        assert!(result.is_ok());
                        state.assert_validation_accepted();
                    }
                }
                Transition::Remove(key) => {
                    let removed = state.lazy_set.remove(ctx, key).unwrap();

                    // Post-conditions:
                    assert!(removed, "removed element");

                    state.assert_validation_accepted();
                }
            }

            // Apply transition in the eager set for comparison
            apply_transition_on_eager_set(&mut state.eager_set, &transition);

            // Global post-conditions:

            // All items in eager set must be present in lazy set
            for key in state.eager_set.iter() {
                let present = state.lazy_set.contains(ctx, key).unwrap();
                assert!(present, "at key {key}");
            }

            // All items in lazy set must be present in eager set
            for key in state.lazy_set.iter(ctx).unwrap() {
                let key = key.unwrap();
                let present = state.eager_set.contains(&key);
                assert!(present, "at key {key}");
            }

            state
        }
    }

    impl AbstractLazySetState {
        /// Find the length of the set from the applied transitions
        fn len(&self) -> u64 {
            (set_len_diff_from_transitions(self.committed_transitions.iter())
                + set_len_diff_from_transitions(self.valid_transitions.iter()))
            .try_into()
            .expect(
                "It shouldn't be possible to underflow length from all \
                 transactions applied in abstract state",
            )
        }

        /// Build an eager set from the committed and current transitions
        fn eager_set(&self) -> BTreeSet<TestKey> {
            let mut eager_set = BTreeSet::new();
            for transition in &self.committed_transitions {
                apply_transition_on_eager_set(&mut eager_set, transition);
            }
            for transition in &self.valid_transitions {
                apply_transition_on_eager_set(&mut eager_set, transition);
            }
            eager_set
        }

        /// Find the keys currently present in the set
        fn find_existing_keys(&self) -> Vec<TestKey> {
            self.eager_set().iter().cloned().collect()
        }
    }

    /// Find the difference in length of the set from the applied transitions
    fn set_len_diff_from_transitions<'a>(
        transitions: impl Iterator<Item = &'a Transition>,
    ) -> i64 {
        let mut insert_count: i64 = 0;
        let mut remove_count: i64 = 0;

        for trans in transitions {
            match trans {
                Transition::CommitTx | Transition::CommitTxAndBlock => {}
                Transition::Insert(_) => insert_count += 1,
                Transition::TryInsert { key: _, is_present } => {
                    if !is_present {
                        insert_count += 1
                    }
                }
                Transition::Remove(_) => remove_count += 1,
            }
        }
        insert_count - remove_count
    }

    impl ConcreteLazySetState {
        fn assert_validation_accepted(&self) {
            // Init the VP env from tx env in which we applied the set
            // transitions
            let tx_env = tx_host_env::take();
            vp_host_env::init_from_tx(self.address.clone(), tx_env, |_| {});

            // Simulate a validity predicate run using the lazy set's validation
            // helpers
            let changed_keys =
                vp_host_env::with(|env| env.all_touched_storage_keys());

            let mut validation_builder = None;

            // Push followed by pop is a no-op, in which case we'd still see the
            // changed keys for these actions, but they wouldn't affect the
            // validation result and they never get persisted, but we'd still
            // them as changed key here. To guard against this case,
            // we check that `set_len_from_transitions` is not empty.
            let set_len_diff =
                set_len_diff_from_transitions(self.current_transitions.iter());

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
                    .lazy_set
                    .accumulate(
                        vp_host_env::ctx(),
                        &mut validation_builder,
                        key,
                    )
                    .unwrap();

                assert!(
                    is_sub_key,
                    "We're only modifying the lazy_set's keys here. Key: \
                     \"{key}\", set length diff {set_len_diff}"
                );
            }
            if !changed_keys.is_empty() && set_len_diff != 0 {
                assert!(
                    validation_builder.is_some(),
                    "If some keys were changed, the builder must get filled in"
                );
                let actions =
                    LazySet::<TestKey>::validate(validation_builder.unwrap())
                        .unwrap();
                let mut actions_to_check = actions.clone();

                // Check that every transition has a corresponding action from
                // validation. We drop the found actions to check that all
                // actions are matched too.
                let current_transitions =
                    normalize_transitions(&self.current_transitions);
                for transition in &current_transitions {
                    use collection_validation::lazy_set::Action;
                    match transition {
                        Transition::CommitTx | Transition::CommitTxAndBlock => {
                        }
                        Transition::Insert(expected_key) => {
                            for (ix, action) in
                                actions_to_check.iter().enumerate()
                            {
                                if let Action::Insert(key) = action {
                                    if expected_key == key {
                                        actions_to_check.remove(ix);
                                        break;
                                    }
                                }
                            }
                        }
                        Transition::TryInsert {
                            key: expected_key,
                            is_present,
                        } => {
                            if !is_present {
                                for (ix, action) in
                                    actions_to_check.iter().enumerate()
                                {
                                    if let Action::Insert(key) = action {
                                        if expected_key == key {
                                            actions_to_check.remove(ix);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Transition::Remove(expected_key) => {
                            for (ix, action) in
                                actions_to_check.iter().enumerate()
                            {
                                if let Action::Remove(key) = action {
                                    if expected_key == key {
                                        actions_to_check.remove(ix);
                                        break;
                                    }
                                }
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

    /// Generate an arbitrary `TestKey`
    fn arb_set_key() -> impl Strategy<Value = TestKey> {
        any::<u64>()
    }

    /// Apply `Transition` on an eager `Set`.
    fn apply_transition_on_eager_set(
        set: &mut BTreeSet<TestKey>,
        transition: &Transition,
    ) {
        match transition {
            Transition::CommitTx | Transition::CommitTxAndBlock => {}
            Transition::Insert(key) => {
                set.insert(*key);
            }
            Transition::Remove(key) => {
                let _popped = set.remove(key);
            }
            Transition::TryInsert { key, is_present } => {
                if !is_present {
                    set.insert(*key);
                }
            }
        }
    }

    /// Normalize transitions:
    /// - remove(key) + insert(key) -> no change
    /// - remove(key) + try_insert{key, is_present: false} -> no change
    /// - try_insert{is_present: true} -> no change
    ///
    /// Note that the normalizable transitions pairs do not have to be directly
    /// next to each other, but their order does matter.
    fn normalize_transitions(transitions: &[Transition]) -> Vec<Transition> {
        let mut collapsed = vec![];
        'outer: for transition in transitions {
            match transition {
                Transition::CommitTx
                | Transition::CommitTxAndBlock
                | Transition::Remove(_) => collapsed.push(transition.clone()),
                Transition::Insert(key) => {
                    for (ix, collapsed_transition) in
                        collapsed.iter().enumerate()
                    {
                        if let Transition::Remove(remove_key) =
                            collapsed_transition
                        {
                            if key == remove_key {
                                // remove(key) + insert(key) -> no change

                                // Delete the `Remove` transition
                                collapsed.remove(ix);
                                continue 'outer;
                            }
                        }
                    }
                    collapsed.push(transition.clone());
                }
                Transition::TryInsert { key, is_present } => {
                    if !is_present {
                        for (ix, collapsed_transition) in
                            collapsed.iter().enumerate()
                        {
                            if let Transition::Remove(remove_key) =
                                collapsed_transition
                            {
                                if key == remove_key {
                                    // remove(key) + try_insert{key,
                                    // is_present:false) -> no
                                    // change

                                    // Delete the `Remove` transition
                                    collapsed.remove(ix);
                                    continue 'outer;
                                }
                            }
                        }
                        collapsed.push(transition.clone());
                    } else {
                        // In else case we don't do anything to omit the
                        // transition:
                        // try_insert{is_present: true} -> no
                        // change
                    }
                }
            }
        }
        collapsed
    }
}
