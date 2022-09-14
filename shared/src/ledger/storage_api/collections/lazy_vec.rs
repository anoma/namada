//! Lazy dynamically-sized vector.

use std::collections::BTreeSet;
use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use derivative::Derivative;
use thiserror::Error;

use super::super::Result;
use super::LazyCollection;
use crate::ledger::storage_api::validation::{self, Data};
use crate::ledger::storage_api::{self, ResultExt, StorageRead, StorageWrite};
use crate::ledger::vp_env::VpEnv;
use crate::types::storage::{self, DbKeySeg};

/// Subkey pointing to the length of the LazyVec
pub const LEN_SUBKEY: &str = "len";
/// Subkey corresponding to the data elements of the LazyVec
pub const DATA_SUBKEY: &str = "data";

/// Using `u64` for vector's indices
pub type Index = u64;

/// Lazy dynamically-sized vector.
///
/// This can be used as an alternative to `std::collections::Vec`. In the lazy
/// vector, the elements do not reside in memory but are instead read and
/// written to storage sub-keys of the storage `key` used to construct the
/// vector.
#[derive(Clone, Debug)]
pub struct LazyVec<T> {
    key: storage::Key,
    phantom: PhantomData<T>,
}

/// Possible sub-keys of a [`LazyVec`]
#[derive(Debug)]
pub enum SubKey {
    /// Length sub-key
    Len,
    /// Data sub-key, further sub-keyed by its index
    Data(Index),
}

/// Possible sub-keys of a [`LazyVec`], together with their [`validation::Data`]
/// that contains prior and posterior state.
#[derive(Debug)]
pub enum SubKeyWithData<T> {
    /// Length sub-key
    Len(Data<Index>),
    /// Data sub-key, further sub-keyed by its index
    Data(Index, Data<T>),
}

/// Possible actions that can modify a [`LazyVec`]. This roughly corresponds to
/// the methods that have `StorageWrite` access.
#[derive(Debug)]
pub enum Action<T> {
    /// Push a value `T` into a [`LazyVec<T>`]
    Push(T),
    /// Pop a value `T` from a [`LazyVec<T>`]
    Pop(T),
    /// Update a value `T` at index from pre to post state in a [`LazyVec<T>`]
    Update {
        /// index at which the value is updated
        index: Index,
        /// value before the update
        pre: T,
        /// value after the update
        post: T,
    },
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Storage error in reading key {0}")]
    StorageError(storage::Key),
    #[error("Incorrect difference in LazyVec's length")]
    InvalidLenDiff,
    #[error("An empty LazyVec must be deleted from storage")]
    EmptyVecShouldBeDeleted,
    #[error("Push at a wrong index. Got {got}, expected {expected}.")]
    UnexpectedPushIndex { got: Index, expected: Index },
    #[error("Pop at a wrong index. Got {got}, expected {expected}.")]
    UnexpectedPopIndex { got: Index, expected: Index },
    #[error(
        "Update (combination of pop and push) at a wrong index. Got {got}, \
         expected {expected}."
    )]
    UnexpectedUpdateIndex { got: Index, expected: Index },
    #[error("An index has overflown its representation: {0}")]
    IndexOverflow(<usize as TryInto<Index>>::Error),
    #[error("Unexpected underflow in `{0} - {0}`")]
    UnexpectedUnderflow(Index, Index),
    #[error("Invalid storage key {0}")]
    InvalidSubKey(storage::Key),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum UpdateError {
    #[error(
        "Invalid index into a LazyVec. Got {index}, but the length is {len}"
    )]
    InvalidIndex { index: Index, len: u64 },
}

/// [`LazyVec`] validation result
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

/// [`LazyVec`] validation builder from storage changes. The changes can be
/// accumulated with `LazyVec::validate()` and then turned into a list
/// of valid actions on the vector with `ValidationBuilder::build()`.
#[derive(Debug, Derivative)]
// https://mcarton.github.io/rust-derivative/latest/Default.html#custom-bound
#[derivative(Default(bound = ""))]
pub struct ValidationBuilder<T> {
    /// The accumulator of found changes under the vector
    pub changes: Vec<SubKeyWithData<T>>,
}

impl<T> LazyCollection for LazyVec<T> {
    /// Create or use an existing vector with the given storage `key`.
    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }
}

// Generic `LazyVec` methods that require no bounds on values `T`
impl<T> LazyVec<T> {
    /// Reads the number of elements in the vector.
    #[allow(clippy::len_without_is_empty)]
    pub fn len<S>(&self, storage: &S) -> Result<u64>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let len = storage.read(&self.get_len_key())?;
        Ok(len.unwrap_or_default())
    }

    /// Returns `true` if the vector contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        Ok(self.len(storage)? == 0)
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of vector's elements storage
    fn get_data_key(&self, index: Index) -> storage::Key {
        self.get_data_prefix().push(&index).unwrap()
    }

    /// Get the sub-key of vector's length storage
    fn get_len_key(&self) -> storage::Key {
        self.key.push(&LEN_SUBKEY.to_owned()).unwrap()
    }
}

// `LazyVec` methods with borsh encoded values `T`
impl<T> LazyVec<T>
where
    T: BorshSerialize + BorshDeserialize + 'static,
{
    /// Appends an element to the back of a collection.
    pub fn push<S>(&self, storage: &mut S, val: T) -> Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let len = self.len(storage)?;
        let data_key = self.get_data_key(len);
        storage.write(&data_key, val)?;
        storage.write(&self.get_len_key(), len + 1)
    }

    /// Removes the last element from a vector and returns it, or `Ok(None)` if
    /// it is empty.
    ///
    /// Note that an empty vector is completely removed from storage.
    pub fn pop<S>(&self, storage: &mut S) -> Result<Option<T>>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let len = self.len(storage)?;
        if len == 0 {
            Ok(None)
        } else {
            let index = len - 1;
            let data_key = self.get_data_key(index);
            if len == 1 {
                storage.delete(&self.get_len_key())?;
            } else {
                storage.write(&self.get_len_key(), index)?;
            }
            let popped_val = storage.read(&data_key)?;
            storage.delete(&data_key)?;
            Ok(popped_val)
        }
    }

    /// Update an element at the given index.
    ///
    /// The index must be smaller than the length of the vector, otherwise this
    /// will fail with `UpdateError::InvalidIndex`.
    pub fn update<S>(&self, storage: &mut S, index: Index, val: T) -> Result<()>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let len = self.len(storage)?;
        if index >= len {
            return Err(UpdateError::InvalidIndex { index, len })
                .into_storage_result();
        }
        let data_key = self.get_data_key(index);
        storage.write(&data_key, val)
    }

    /// Read an element at the index or `Ok(None)` if out of bounds.
    pub fn get<S>(&self, storage: &S, index: Index) -> Result<Option<T>>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        storage.read(&self.get_data_key(index))
    }

    /// An iterator visiting all elements. The iterator element type is
    /// `Result<T>`, because iterator's call to `next` may fail with e.g. out of
    /// gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead<'iter>,
    ) -> Result<impl Iterator<Item = Result<T>> + 'iter> {
        let iter = storage_api::iter_prefix(storage, &self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (_key, val) = key_val_res?;
            Ok(val)
        }))
    }

    /// Check if the given storage key is a valid LazyVec sub-key and if so
    /// return which one
    pub fn is_valid_sub_key(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<SubKey>> {
        let suffix = match key.split_prefix(&self.key) {
            None => {
                // not matching prefix, irrelevant
                return Ok(None);
            }
            Some(None) => {
                // no suffix, invalid
                return Err(ValidationError::InvalidSubKey(key.clone()))
                    .into_storage_result();
            }
            Some(Some(suffix)) => suffix,
        };

        // Match the suffix against expected sub-keys
        match &suffix.segments[..] {
            [DbKeySeg::StringSeg(sub)] if sub == LEN_SUBKEY => {
                Ok(Some(SubKey::Len))
            }
            [DbKeySeg::StringSeg(sub_a), DbKeySeg::StringSeg(sub_b)]
                if sub_a == DATA_SUBKEY =>
            {
                if let Ok(index) = storage::KeySeg::parse(sub_b.clone()) {
                    Ok(Some(SubKey::Data(index)))
                } else {
                    Err(ValidationError::InvalidSubKey(key.clone()))
                        .into_storage_result()
                }
            }
            _ => Err(ValidationError::InvalidSubKey(key.clone()))
                .into_storage_result(),
        }
    }

    /// Accumulate storage changes inside a [`ValidationBuilder`]. This is
    /// typically done by the validity predicate while looping through the
    /// changed keys. If the resulting `builder` is not `None`, one must
    /// call `fn build()` on it to get the validation result.
    /// This function will return `Ok(true)` if the storage key is a valid
    /// sub-key of this collection, `Ok(false)` if the storage key doesn't match
    /// the prefix of this collection, or fail with
    /// [`ValidationError::InvalidSubKey`] if the prefix matches this
    /// collection, but the key itself is not recognized.
    pub fn accumulate<ENV>(
        &self,
        env: &ENV,
        builder: &mut Option<ValidationBuilder<T>>,
        key_changed: &storage::Key,
    ) -> storage_api::Result<bool>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        if let Some(sub) = self.is_valid_sub_key(key_changed)? {
            let change = match sub {
                SubKey::Len => {
                    let data = validation::read_data(env, key_changed)?;
                    data.map(SubKeyWithData::Len)
                }
                SubKey::Data(index) => {
                    let data = validation::read_data(env, key_changed)?;
                    data.map(|data| SubKeyWithData::Data(index, data))
                }
            };
            if let Some(change) = change {
                let builder =
                    builder.get_or_insert(ValidationBuilder::default());
                builder.changes.push(change);
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl<T> ValidationBuilder<T> {
    /// Validate storage changes and if valid, build from them a list of
    /// actions.
    ///
    /// The validation rules for a [`LazyVec`] are:
    ///   - A difference in the vector's length must correspond to the
    ///     difference in how many elements where pushed versus how many
    ///     elements were popped.
    ///   - An empty vector must be deleted from storage
    ///   - In addition, we check that indices of any changes are within an
    ///     expected range (i.e. the vectors indices should always be
    ///     monotonically increasing from zero)
    pub fn build(self) -> ValidationResult<Vec<Action<T>>> {
        let mut actions = vec![];

        // We need to accumulate some values for what's changed
        let mut post_gt_pre = false;
        let mut len_diff: u64 = 0;
        let mut len_pre: u64 = 0;
        let mut added = BTreeSet::<Index>::default();
        let mut updated = BTreeSet::<Index>::default();
        let mut deleted = BTreeSet::<Index>::default();

        for change in self.changes {
            match change {
                SubKeyWithData::Len(data) => match data {
                    Data::Add { post } => {
                        if post == 0 {
                            return Err(
                                ValidationError::EmptyVecShouldBeDeleted,
                            );
                        }
                        post_gt_pre = true;
                        len_diff = post;
                    }
                    Data::Update { pre, post } => {
                        if post == 0 {
                            return Err(
                                ValidationError::EmptyVecShouldBeDeleted,
                            );
                        }
                        if post > pre {
                            post_gt_pre = true;
                            len_diff = post - pre;
                        } else {
                            len_diff = pre - post;
                        }
                        len_pre = pre;
                    }
                    Data::Delete { pre } => {
                        len_diff = pre;
                        len_pre = pre;
                    }
                },
                SubKeyWithData::Data(index, data) => match data {
                    Data::Add { post } => {
                        actions.push(Action::Push(post));
                        added.insert(index);
                    }
                    Data::Update { pre, post } => {
                        actions.push(Action::Update { index, pre, post });
                        updated.insert(index);
                    }
                    Data::Delete { pre } => {
                        actions.push(Action::Pop(pre));
                        deleted.insert(index);
                    }
                },
            }
        }
        let added_len: u64 = deleted
            .len()
            .try_into()
            .map_err(ValidationError::IndexOverflow)?;
        let deleted_len: u64 = deleted
            .len()
            .try_into()
            .map_err(ValidationError::IndexOverflow)?;

        if len_diff != 0
            && !(if post_gt_pre {
                deleted_len + len_diff == added_len
            } else {
                added_len + len_diff == deleted_len
            })
        {
            return Err(ValidationError::InvalidLenDiff);
        }

        let mut last_added = Option::None;
        // Iterate additions in increasing order of indices
        for index in added {
            if let Some(last_added) = last_added {
                // Following additions should be at monotonically increasing
                // indices
                let expected = last_added + 1;
                if expected != index {
                    return Err(ValidationError::UnexpectedPushIndex {
                        got: index,
                        expected,
                    });
                }
            } else if index != len_pre {
                // The first addition must be at the pre length value.
                // If something is deleted and a new value is added
                // in its place, it will go through `Data::Update`
                // instead.
                return Err(ValidationError::UnexpectedPushIndex {
                    got: index,
                    expected: len_pre,
                });
            }
            last_added = Some(index);
        }

        let mut last_deleted = Option::None;
        // Also iterate deletions in increasing order of indices
        for index in deleted {
            if let Some(last_added) = last_deleted {
                // Following deletions should be at monotonically increasing
                // indices
                let expected = last_added + 1;
                if expected != index {
                    return Err(ValidationError::UnexpectedPopIndex {
                        got: index,
                        expected,
                    });
                }
            }
            last_deleted = Some(index);
        }
        if let Some(index) = last_deleted {
            if len_pre > 0 {
                let expected = len_pre - 1;
                if index != expected {
                    // The last deletion must be at the pre length value minus 1
                    return Err(ValidationError::UnexpectedPopIndex {
                        got: index,
                        expected: len_pre,
                    });
                }
            }
        }

        // And finally iterate updates in increasing order of indices
        let mut last_updated = Option::None;
        for index in updated {
            if let Some(last_updated) = last_updated {
                // Following additions should be at monotonically increasing
                // indices
                let expected = last_updated + 1;
                if expected != index {
                    return Err(ValidationError::UnexpectedUpdateIndex {
                        got: index,
                        expected,
                    });
                }
            }
            last_updated = Some(index);
        }
        if let Some(index) = last_updated {
            let expected = len_pre.checked_sub(deleted_len).ok_or(
                ValidationError::UnexpectedUnderflow(len_pre, deleted_len),
            )?;
            if index != expected {
                // The last update must be at the pre length value minus
                // deleted_len.
                // If something is added and then deleted in a
                // single tx, it will never be visible here.
                return Err(ValidationError::UnexpectedUpdateIndex {
                    got: index,
                    expected: len_pre,
                });
            }
        }

        Ok(actions)
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;
    use proptest::prop_state_machine;
    use proptest::state_machine::{AbstractStateMachine, StateMachineTest};
    use proptest::test_runner::Config;
    use test_log::test;

    use super::*;
    use crate::ledger::storage::testing::TestStorage;

    #[test]
    fn test_lazy_vec_basics() -> storage_api::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_vec = LazyVec::<u32>::open(key);

        // The vec should be empty at first
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Push a new value and check that it's added
        lazy_vec.push(&mut storage, 15_u32)?;
        assert!(!lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 1);
        assert_eq!(lazy_vec.iter(&storage)?.next().unwrap()?, 15_u32);
        assert_eq!(lazy_vec.get(&storage, 0)?.unwrap(), 15_u32);
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        // Pop the last value and check that the vec is empty again
        let popped = lazy_vec.pop(&mut storage)?.unwrap();
        assert_eq!(popped, 15_u32);
        assert!(lazy_vec.is_empty(&storage)?);
        assert!(lazy_vec.len(&storage)? == 0);
        assert!(lazy_vec.iter(&storage)?.next().is_none());
        assert!(lazy_vec.pop(&mut storage)?.is_none());
        assert!(lazy_vec.get(&storage, 0)?.is_none());
        assert!(lazy_vec.get(&storage, 1)?.is_none());

        Ok(())
    }

    prop_state_machine! {
        #![proptest_config(Config {
            // Instead of the default 256, we only run 5 because otherwise it
            // takes too long and it's preferable to crank up the number of
            // transitions instead, to allow each case to run for more epochs as
            // some issues only manifest once the model progresses further.
            // Additionally, more cases will be explored every time this test is
            // executed in the CI.
            cases: 5,
            .. Config::default()
        })]
        #[test]
        /// A `StateMachineTest` implemented on `LazyVec` that manipulates
        /// it with `Transition`s and checks its state against an in-memory
        /// `std::collections::Vec`.
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

    #[derive(Debug)]
    struct ConcreteLazyVecState {
        // The eager vec in `AbstractLazyVecState` is not visible in `impl
        // StateMachineTest for ConcreteLazyVecState`, it's only used to drive
        // transition generation, so we duplicate it here and apply the
        // transitions on it the same way (with
        // `fn apply_transition_on_eager_vec`)
        eager_vec: Vec<TestVecItem>,
        lazy_vec: LazyVec<TestVecItem>,
        storage: TestStorage,
    }

    #[derive(Clone, Debug)]
    struct AbstractLazyVecState(Vec<TestVecItem>);

    /// Possible transitions that can modify a [`LazyVec`]. This roughly
    /// corresponds to the methods that have `StorageWrite` access and is very
    /// similar to [`Action`]
    #[derive(Clone, Debug)]
    pub enum Transition<T> {
        /// Push a value `T` into a [`LazyVec<T>`]
        Push(T),
        /// Pop a value from a [`LazyVec<T>`]
        Pop,
        /// Update a value `T` at index from pre to post state in a
        /// [`LazyVec<T>`]
        Update {
            /// index at which the value is updated
            index: Index,
            /// value to update the element to
            value: T,
        },
    }

    impl AbstractStateMachine for AbstractLazyVecState {
        type State = Self;
        type Transition = Transition<TestVecItem>;

        fn init_state() -> BoxedStrategy<Self::State> {
            Just(Self(vec![])).boxed()
        }

        fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
            if state.0.is_empty() {
                prop_oneof![arb_test_vec_item().prop_map(Transition::Push)]
                    .boxed()
            } else {
                let indices: Vec<Index> =
                    (0_usize..state.0.len()).map(|ix| ix as Index).collect();
                let arb_index = proptest::sample::select(indices);
                prop_oneof![
                    Just(Transition::Pop),
                    arb_test_vec_item().prop_map(Transition::Push),
                    (arb_index, arb_test_vec_item()).prop_map(
                        |(index, value)| Transition::Update { index, value }
                    )
                ]
                .boxed()
            }
        }

        fn apply_abstract(
            mut state: Self::State,
            transition: &Self::Transition,
        ) -> Self::State {
            apply_transition_on_eager_vec(&mut state.0, transition);
            state
        }

        fn preconditions(
            state: &Self::State,
            transition: &Self::Transition,
        ) -> bool {
            if state.0.is_empty() {
                !matches!(
                    transition,
                    Transition::Pop | Transition::Update { .. }
                )
            } else if let Transition::Update { index, .. } = transition {
                *index < (state.0.len() - 1) as Index
            } else {
                true
            }
        }
    }

    impl StateMachineTest for ConcreteLazyVecState {
        type Abstract = AbstractLazyVecState;
        type ConcreteState = Self;

        fn init_test(
            _initial_state: <Self::Abstract as AbstractStateMachine>::State,
        ) -> Self::ConcreteState {
            Self {
                eager_vec: vec![],
                lazy_vec: LazyVec::open(
                    storage::Key::parse("key_path/arbitrary").unwrap(),
                ),
                storage: TestStorage::default(),
            }
        }

        fn apply_concrete(
            mut state: Self::ConcreteState,
            transition: <Self::Abstract as AbstractStateMachine>::Transition,
        ) -> Self::ConcreteState {
            // Transition application on lazy vec and post-conditions:
            match dbg!(&transition) {
                Transition::Push(value) => {
                    let old_len = state.lazy_vec.len(&state.storage).unwrap();

                    state
                        .lazy_vec
                        .push(&mut state.storage, value.clone())
                        .unwrap();

                    // Post-conditions:
                    let new_len = state.lazy_vec.len(&state.storage).unwrap();
                    let stored_value = state
                        .lazy_vec
                        .get(&state.storage, new_len - 1)
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        &stored_value, value,
                        "the new item must be added to the back"
                    );
                    assert_eq!(old_len + 1, new_len, "length must increment");
                }
                Transition::Pop => {
                    let old_len = state.lazy_vec.len(&state.storage).unwrap();

                    let popped = state
                        .lazy_vec
                        .pop(&mut state.storage)
                        .unwrap()
                        .unwrap();

                    // Post-conditions:
                    let new_len = state.lazy_vec.len(&state.storage).unwrap();
                    assert_eq!(old_len, new_len + 1, "length must decrement");
                    assert_eq!(
                        &popped,
                        state.eager_vec.last().unwrap(),
                        "popped element matches the last element in eager vec \
                         before it's updated"
                    );
                }
                Transition::Update { index, value } => {
                    state
                        .lazy_vec
                        .update(&mut state.storage, *index, value.clone())
                        .unwrap();
                }
            }

            // Apply transition in the eager vec for comparison
            apply_transition_on_eager_vec(&mut state.eager_vec, &transition);

            // Global post-conditions:

            // All items in eager vec must be present in lazy vec
            for (ix, expected_item) in state.eager_vec.iter().enumerate() {
                let got = state
                    .lazy_vec
                    .get(&state.storage, ix as Index)
                    .unwrap()
                    .expect("The expected item must be present in lazy vec");
                assert_eq!(expected_item, &got, "at index {ix}");
            }

            // All items in lazy vec must be present in eager vec
            for (ix, expected_item) in
                state.lazy_vec.iter(&state.storage).unwrap().enumerate()
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
}
