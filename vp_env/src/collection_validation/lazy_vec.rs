//! LazyVec validation helpers

use std::collections::BTreeSet;
use std::fmt::Debug;

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::types::storage;
use namada_storage::collections::lazy_vec::{
    Index, LazyVec, SubKey, ValidationError,
};
use namada_storage::ResultExt;

use super::{read_data, Data, LazyCollectionExt};
use crate::VpEnv;

/// Possible sub-keys of a [`LazyVec`], together with their [`Data`]
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
#[derive(Clone, Debug)]
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

impl<T> LazyCollectionExt for LazyVec<T>
where
    T: BorshSerialize + BorshDeserialize + 'static + Debug,
{
    type Action = Action<T>;
    type SubKeyWithData = SubKeyWithData<T>;

    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> namada_storage::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        let change = match sub_key {
            SubKey::Len => {
                let data = read_data(env, storage_key)?;
                data.map(SubKeyWithData::Len)
            }
            SubKey::Data(index) => {
                let data = read_data(env, storage_key)?;
                data.map(|data| SubKeyWithData::Data(index, data))
            }
        };
        Ok(change)
    }

    /// The validation rules for a [`LazyVec`] are:
    ///   - A difference in the vector's length must correspond to the
    ///     difference in how many elements were pushed versus how many elements
    ///     were popped.
    ///   - An empty vector must be deleted from storage
    ///   - In addition, we check that indices of any changes are within an
    ///     expected range (i.e. the vectors indices should always be
    ///     monotonically increasing from zero)
    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> namada_storage::Result<Vec<Self::Action>> {
        let mut actions = vec![];

        // We need to accumulate some values for what's changed
        let mut post_gt_pre = false;
        let mut len_diff: u64 = 0;
        let mut len_pre: u64 = 0;
        let mut added = BTreeSet::<Index>::default();
        let mut updated = BTreeSet::<Index>::default();
        let mut deleted = BTreeSet::<Index>::default();

        for key in keys {
            match key {
                SubKeyWithData::Len(data) => match data {
                    Data::Add { post } => {
                        if post == 0 {
                            return Err(
                                ValidationError::EmptyVecShouldBeDeleted,
                            )
                            .into_storage_result();
                        }
                        post_gt_pre = true;
                        len_diff = post;
                    }
                    Data::Update { pre, post } => {
                        if post == 0 {
                            return Err(
                                ValidationError::EmptyVecShouldBeDeleted,
                            )
                            .into_storage_result();
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
        let added_len: u64 = added
            .len()
            .try_into()
            .map_err(ValidationError::IndexOverflow)
            .into_storage_result()?;
        let deleted_len: u64 = deleted
            .len()
            .try_into()
            .map_err(ValidationError::IndexOverflow)
            .into_storage_result()?;

        if len_diff != 0
            && !(if post_gt_pre {
                deleted_len + len_diff == added_len
            } else {
                added_len + len_diff == deleted_len
            })
        {
            return Err(ValidationError::InvalidLenDiff).into_storage_result();
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
                    })
                    .into_storage_result();
                }
            } else if index != len_pre {
                // The first addition must be at the pre length value.
                // If something is deleted and a new value is added
                // in its place, it will go through `Data::Update`
                // instead.
                return Err(ValidationError::UnexpectedPushIndex {
                    got: index,
                    expected: len_pre,
                })
                .into_storage_result();
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
                    })
                    .into_storage_result();
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
                    })
                    .into_storage_result();
                }
            }
        }

        // And finally iterate updates
        for index in updated {
            // Update index has to be within the length bounds
            let max = len_pre + len_diff;
            if index >= max {
                return Err(ValidationError::UnexpectedUpdateIndex {
                    got: index,
                    max,
                })
                .into_storage_result();
            }
        }

        Ok(actions)
    }
}
