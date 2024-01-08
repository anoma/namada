#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    use borsh::{BorshDeserialize, BorshSerialize};
    use namada::types::address::{self, Address};
    use namada::types::storage;
    use namada_tx_prelude::collections::lazy_map::{
        NestedMap, NestedSubKey, SubKey,
    };
    use namada_tx_prelude::collections::{LazyCollection, LazyMap};
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
        fn nested_lazy_map_api_state_machine_test(sequential 1..100 => ConcreteLazyMapState);
    }

    /// Some borsh-serializable type with arbitrary fields to be used inside
    /// LazyMap state machine test
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
    struct TestVal {
        x: u64,
        y: bool,
    }

    type KeyOuter = u64;
    type KeyMiddle = i32;
    type KeyInner = i8;

    type NestedTestMap =
        NestedMap<KeyOuter, NestedMap<KeyMiddle, LazyMap<KeyInner, TestVal>>>;

    type NestedEagerMap =
        BTreeMap<KeyOuter, BTreeMap<KeyMiddle, BTreeMap<KeyInner, TestVal>>>;

    /// A `StateMachineTest` implemented on this struct manipulates it with
    /// `Transition`s, which are also being accumulated into
    /// `current_transitions`. It then:
    ///
    /// - checks its state against an in-memory `std::collections::HashMap`
    /// - runs validation and checks that the `LazyMap::Action`s reported from
    ///   validation match with transitions that were applied
    ///
    /// Additionally, one of the transitions is to commit a block and/or
    /// transaction, during which the currently accumulated state changes are
    /// persisted, or promoted from transaction write log to block's write log.
    #[derive(Debug)]
    struct ConcreteLazyMapState {
        /// Address is used to prefix the storage key of the `lazy_map` in
        /// order to simulate a transaction and a validity predicate
        /// check from changes on the `lazy_map`
        address: Address,
        /// In the test, we apply the same transitions on the `lazy_map` as on
        /// `eager_map` to check that `lazy_map`'s state is consistent with
        /// `eager_map`.
        eager_map: NestedEagerMap,
        /// Handle to a lazy map with nested lazy collections
        lazy_map: NestedTestMap,
        /// Valid LazyMap changes in the current transaction
        current_transitions: Vec<Transition>,
    }

    #[derive(Clone, Debug, Default)]
    struct AbstractLazyMapState {
        /// Valid LazyMap changes in the current transaction
        valid_transitions: Vec<Transition>,
        /// Valid LazyMap changes committed to storage
        committed_transitions: Vec<Transition>,
    }

    /// Possible transitions that can modify a [`NestedTestMap`].
    /// This roughly corresponds to the methods that have `StorageWrite`
    /// access and is very similar to [`Action`]
    #[derive(Clone, Debug)]
    enum Transition {
        /// Commit all valid transitions in the current transaction
        CommitTx,
        /// Commit all valid transitions in the current transaction and also
        /// commit the current block
        CommitTxAndBlock,
        /// Insert a key-val into a [`LazyMap`]
        Insert(Key, TestVal),
        /// Remove a key-val from a [`LazyMap`]
        Remove(Key),
        /// Update a value at key from pre to post state in a
        /// [`LazyMap`]
        Update(Key, TestVal),
    }

    /// A key for transition
    type Key = (KeyOuter, KeyMiddle, KeyInner);

    impl ReferenceStateMachine for AbstractLazyMapState {
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
                    3 => (arb_map_key(), arb_map_val()).prop_map(|(key, val)| Transition::Insert(key, val))
                ]
                .boxed()
            } else {
                let keys = state.find_existing_keys();
                let arb_existing_map_key =
                    || proptest::sample::select(keys.clone());
                prop_oneof![
                    1 => Just(Transition::CommitTx),
                    1 => Just(Transition::CommitTxAndBlock),
                    3 => (arb_existing_map_key(), arb_map_val()).prop_map(|(key, val)|
                            Transition::Update(key, val)),
                    3 => arb_existing_map_key().prop_map(Transition::Remove),
                    5 => (arb_map_key().prop_filter(
                            "insert on non-existing keys only",
                            move |key| !keys.contains(key)), arb_map_val())
                            .prop_map(|(key, val)| Transition::Insert(key, val))
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
            if length == 0
                && matches!(
                    transition,
                    Transition::Remove(_) | Transition::Update(_, _)
                )
            {
                return false;
            }
            match transition {
                Transition::Update(key, _) | Transition::Remove(key) => {
                    let keys = state.find_existing_keys();
                    // Ensure that the update/remove key is an existing one
                    keys.contains(key)
                }
                Transition::Insert(key, _) => {
                    let keys = state.find_existing_keys();
                    // Ensure that the insert key is not an existing one
                    !keys.contains(key)
                }
                _ => true,
            }
        }
    }

    impl StateMachineTest for ConcreteLazyMapState {
        type Reference = AbstractLazyMapState;
        type SystemUnderTest = Self;

        fn init_test(
            _initial_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            // Init transaction env in which we'll be applying the transitions
            tx_host_env::init();

            // The lazy_map's path must be prefixed by the address to be able
            // to trigger a validity predicate on it
            let address = address::testing::established_address_1();
            tx_host_env::with(|env| env.spawn_accounts([&address]));
            let lazy_map_prefix: storage::Key = address.to_db_key().into();

            Self {
                address,
                eager_map: BTreeMap::new(),
                lazy_map: NestedTestMap::open(
                    lazy_map_prefix.push(&"arbitrary".to_string()).unwrap(),
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

            // Transition application on lazy map and post-conditions:
            match &transition {
                Transition::CommitTx => {
                    // commit the tx without committing the block
                    tx_host_env::with(|env| env.wl_storage.commit_tx());
                }
                Transition::CommitTxAndBlock => {
                    // commit the tx and the block
                    tx_host_env::commit_tx_and_block();
                }
                Transition::Insert(
                    (key_outer, key_middle, key_inner),
                    value,
                ) => {
                    let inner = state.lazy_map.at(key_outer).at(key_middle);

                    inner.insert(ctx, *key_inner, value.clone()).unwrap();

                    // Post-conditions:
                    let stored_value =
                        inner.get(ctx, key_inner).unwrap().unwrap();
                    assert_eq!(
                        &stored_value, value,
                        "the new item must be added to the back"
                    );

                    state.assert_validation_accepted();
                }
                Transition::Remove((key_outer, key_middle, key_inner)) => {
                    let inner = state.lazy_map.at(key_outer).at(key_middle);

                    let removed =
                        inner.remove(ctx, key_inner).unwrap().unwrap();

                    // Post-conditions:
                    assert_eq!(
                        &removed,
                        state
                            .eager_map
                            .get(key_outer)
                            .unwrap()
                            .get(key_middle)
                            .unwrap()
                            .get(key_inner)
                            .unwrap(),
                        "removed element matches the value in eager map \
                         before it's updated"
                    );

                    state.assert_validation_accepted();
                }
                Transition::Update(
                    (key_outer, key_middle, key_inner),
                    value,
                ) => {
                    let inner = state.lazy_map.at(key_outer).at(key_middle);

                    let old_val = inner.get(ctx, key_inner).unwrap().unwrap();

                    inner.insert(ctx, *key_inner, value.clone()).unwrap();

                    // Post-conditions:
                    let new_val = inner.get(ctx, key_inner).unwrap().unwrap();
                    assert_eq!(
                        &old_val,
                        state
                            .eager_map
                            .get(key_outer)
                            .unwrap()
                            .get(key_middle)
                            .unwrap()
                            .get(key_inner)
                            .unwrap(),
                        "old value must match the value at the same key in \
                         the eager map before it's updated"
                    );
                    assert_eq!(
                        &new_val, value,
                        "new value must match that which was passed into the \
                         Transition::Update"
                    );

                    state.assert_validation_accepted();
                }
            }

            // Apply transition in the eager map for comparison
            apply_transition_on_eager_map(&mut state.eager_map, &transition);

            // Global post-conditions:

            // All items in eager map must be present in lazy map
            for (key_outer, middle) in state.eager_map.iter() {
                for (key_middle, inner) in middle {
                    for (key_inner, expected_item) in inner {
                        let got = state
                            .lazy_map
                            .at(key_outer)
                            .at(key_middle)
                            .get(ctx, key_inner)
                            .unwrap()
                            .expect(
                                "The expected item must be present in lazy map",
                            );
                        assert_eq!(
                            expected_item, &got,
                            "at key {key_outer}, {key_middle} {key_inner}"
                        );
                    }
                }
            }

            // All items in lazy map must be present in eager map
            for key_val in state.lazy_map.iter(ctx).unwrap() {
                let (
                    NestedSubKey::Data {
                        key: key_outer,
                        nested_sub_key:
                            NestedSubKey::Data {
                                key: key_middle,
                                nested_sub_key: SubKey::Data(key_inner),
                            },
                    },
                    expected_val,
                ) = key_val.unwrap();
                let got = state
                    .eager_map
                    .get(&key_outer)
                    .unwrap()
                    .get(&key_middle)
                    .unwrap()
                    .get(&key_inner)
                    .expect("The expected item must be present in eager map");
                assert_eq!(
                    &expected_val, got,
                    "at key {key_outer}, {key_middle} {key_inner})"
                );
            }

            state
        }
    }

    impl AbstractLazyMapState {
        /// Find the length of the map from the applied transitions
        fn len(&self) -> u64 {
            (map_len_diff_from_transitions(self.committed_transitions.iter())
                + map_len_diff_from_transitions(self.valid_transitions.iter()))
            .try_into()
            .expect(
                "It shouldn't be possible to underflow length from all \
                 transactions applied in abstract state",
            )
        }

        /// Build an eager map from the committed and current transitions
        fn eager_map(&self) -> NestedEagerMap {
            let mut eager_map = BTreeMap::new();
            for transition in &self.committed_transitions {
                apply_transition_on_eager_map(&mut eager_map, transition);
            }
            for transition in &self.valid_transitions {
                apply_transition_on_eager_map(&mut eager_map, transition);
            }
            eager_map
        }

        /// Find the keys currently present in the map
        fn find_existing_keys(&self) -> Vec<Key> {
            let outer_map = self.eager_map();
            outer_map
                .into_iter()
                .fold(vec![], |acc, (outer, middle_map)| {
                    middle_map.into_iter().fold(
                        acc,
                        |mut acc, (middle, inner_map)| {
                            acc.extend(
                                inner_map
                                    .into_keys()
                                    .map(|inner| (outer, middle, inner)),
                            );
                            acc
                        },
                    )
                })
        }
    }

    /// Find the difference in length of the map from the applied transitions
    fn map_len_diff_from_transitions<'a>(
        transitions: impl Iterator<Item = &'a Transition>,
    ) -> i64 {
        let mut insert_count: i64 = 0;
        let mut remove_count: i64 = 0;

        for trans in transitions {
            match trans {
                Transition::CommitTx
                | Transition::CommitTxAndBlock
                | Transition::Update(_, _) => {}
                Transition::Insert(_, _) => insert_count += 1,
                Transition::Remove(_) => remove_count += 1,
            }
        }
        insert_count - remove_count
    }

    impl ConcreteLazyMapState {
        fn assert_validation_accepted(&self) {
            // Init the VP env from tx env in which we applied the map
            // transitions
            let tx_env = tx_host_env::take();
            vp_host_env::init_from_tx(self.address.clone(), tx_env, |_| {});

            // Simulate a validity predicate run using the lazy map's validation
            // helpers
            let changed_keys =
                vp_host_env::with(|env| env.all_touched_storage_keys());

            let mut validation_builder = None;

            // Push followed by pop is a no-op, in which case we'd still see the
            // changed keys for these actions, but they wouldn't affect the
            // validation result and they never get persisted, but we'd still
            // them as changed key here. To guard against this case,
            // we check that `map_len_from_transitions` is not empty.
            let map_len_diff =
                map_len_diff_from_transitions(self.current_transitions.iter());

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
                    .lazy_map
                    .accumulate(
                        vp_host_env::ctx(),
                        &mut validation_builder,
                        key,
                    )
                    .unwrap();

                assert!(
                    is_sub_key,
                    "We're only modifying the lazy_map's keys here. Key: \
                     \"{key}\", map length diff {map_len_diff}"
                );
            }
            if !changed_keys.is_empty() && map_len_diff != 0 {
                assert!(
                    validation_builder.is_some(),
                    "If some keys were changed, the builder must get filled in"
                );
                let actions =
                    NestedTestMap::validate(validation_builder.unwrap())
                        .unwrap();
                let mut actions_to_check = actions.clone();

                // Check that every transition has a corresponding action from
                // validation. We drop the found actions to check that all
                // actions are matched too.
                let current_transitions =
                    normalize_transitions(&self.current_transitions);
                for transition in &current_transitions {
                    use collection_validation::lazy_map::Action;
                    use collection_validation::lazy_map::NestedAction::At;

                    match transition {
                        Transition::CommitTx | Transition::CommitTxAndBlock => {
                        }
                        Transition::Insert(expected_key, expected_val) => {
                            for (ix, action) in
                                actions_to_check.iter().enumerate()
                            {
                                if let At(
                                    key_outer,
                                    At(
                                        key_middle,
                                        Action::Insert(key_inner, val),
                                    ),
                                ) = action
                                {
                                    let key =
                                        (*key_outer, *key_middle, *key_inner);
                                    if expected_key == &key
                                        && expected_val == val
                                    {
                                        actions_to_check.remove(ix);
                                        break;
                                    }
                                }
                            }
                        }
                        Transition::Remove(expected_key) => {
                            for (ix, action) in
                                actions_to_check.iter().enumerate()
                            {
                                if let At(
                                    key_outer,
                                    At(
                                        key_middle,
                                        Action::Remove(key_inner, _val),
                                    ),
                                ) = action
                                {
                                    let key =
                                        (*key_outer, *key_middle, *key_inner);
                                    if expected_key == &key {
                                        actions_to_check.remove(ix);
                                        break;
                                    }
                                }
                            }
                        }
                        Transition::Update(expected_key, value) => {
                            for (ix, action) in
                                actions_to_check.iter().enumerate()
                            {
                                if let At(
                                    key_outer,
                                    At(
                                        key_middle,
                                        Action::Update {
                                            key: key_inner,
                                            pre: _,
                                            post,
                                        },
                                    ),
                                ) = action
                                {
                                    let key =
                                        (*key_outer, *key_middle, *key_inner);
                                    if expected_key == &key && post == value {
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
    fn arb_map_key() -> impl Strategy<Value = (KeyOuter, KeyMiddle, KeyInner)> {
        (any::<u64>(), any::<i32>(), any::<i8>())
    }

    /// Generate an arbitrary `TestVal`
    fn arb_map_val() -> impl Strategy<Value = TestVal> {
        (any::<u64>(), any::<bool>()).prop_map(|(x, y)| TestVal { x, y })
    }

    /// Apply `Transition` on an eager `Map`.
    fn apply_transition_on_eager_map(
        map: &mut NestedEagerMap,
        transition: &Transition,
    ) {
        match transition {
            Transition::CommitTx | Transition::CommitTxAndBlock => {}
            Transition::Insert((key_outer, key_middle, key_inner), value)
            | Transition::Update((key_outer, key_middle, key_inner), value) => {
                let middle =
                    map.entry(*key_outer).or_insert_with(Default::default);
                let inner =
                    middle.entry(*key_middle).or_insert_with(Default::default);
                inner.insert(*key_inner, value.clone());
            }
            Transition::Remove((key_outer, key_middle, key_inner)) => {
                let middle =
                    map.entry(*key_outer).or_insert_with(Default::default);
                let inner =
                    middle.entry(*key_middle).or_insert_with(Default::default);
                let _popped = inner.remove(key_inner);
            }
        }
    }

    /// Normalize transitions:
    /// - remove(key) + insert(key, val) -> update(key, val)
    /// - insert(key, val) + update(key, new_val) -> insert(key, new_val)
    /// - update(key, val) + update(key, new_val) -> update(key, new_val)
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
                Transition::Insert(key, val) => {
                    for (ix, collapsed_transition) in
                        collapsed.iter().enumerate()
                    {
                        if let Transition::Remove(remove_key) =
                            collapsed_transition
                        {
                            if key == remove_key {
                                // remove(key) + insert(key, val) -> update(key,
                                // val)

                                // Replace the Remove with an Update instead of
                                // inserting the Insert
                                *collapsed.get_mut(ix).unwrap() =
                                    Transition::Update(*key, val.clone());
                                continue 'outer;
                            }
                        }
                    }
                    collapsed.push(transition.clone());
                }
                Transition::Update(key, value) => {
                    for (ix, collapsed_transition) in
                        collapsed.iter().enumerate()
                    {
                        if let Transition::Insert(insert_key, _) =
                            collapsed_transition
                        {
                            if key == insert_key {
                                // insert(key, val) + update(key, new_val) ->
                                // insert(key, new_val)

                                // Replace the insert with the new update's
                                // value instead of inserting it
                                *collapsed.get_mut(ix).unwrap() =
                                    Transition::Insert(*key, value.clone());
                                continue 'outer;
                            }
                        } else if let Transition::Update(update_key, _) =
                            collapsed_transition
                        {
                            if key == update_key {
                                // update(key, val) + update(key, new_val) ->
                                // update(key, new_val)

                                // Replace the insert with the new update's
                                // value instead of inserting it
                                *collapsed.get_mut(ix).unwrap() =
                                    Transition::Update(*key, value.clone());
                                continue 'outer;
                            }
                        }
                    }
                    collapsed.push(transition.clone());
                }
            }
        }
        collapsed
    }
}
