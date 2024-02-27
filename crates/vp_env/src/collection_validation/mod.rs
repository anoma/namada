//! Storage change validation helpers

pub mod lazy_map;
pub mod lazy_set;
pub mod lazy_vec;

use std::fmt::Debug;

use derivative::Derivative;
use namada_core::borsh::BorshDeserialize;
use namada_core::storage;
use namada_storage::collections::LazyCollection;

use crate::VpEnv;

/// Validation builder from storage changes. The changes can
/// be accumulated with `LazyCollection::accumulate()` and then turned into a
/// list of valid actions on the collection with `LazyCollection::validate()`.
#[derive(Debug, Derivative)]
// https://mcarton.github.io/rust-derivative/latest/Default.html#custom-bound
#[derivative(Default(bound = ""))]
pub struct ValidationBuilder<Change> {
    /// The accumulator of found changes under the vector
    pub changes: Vec<Change>,
}

/// Data update with prior and posterior state.
#[derive(Clone, Debug)]
pub enum Data<T> {
    /// Newly added value
    Add {
        /// Posterior state
        post: T,
    },
    /// Updated value prior and posterior state
    Update {
        /// Prior state
        pre: T,
        /// Posterior state
        post: T,
    },
    /// Deleted value
    Delete {
        /// Prior state
        pre: T,
    },
}

/// Read the prior and posterior state for the given key.
pub fn read_data<ENV, T>(
    env: &ENV,
    key: &storage::Key,
) -> Result<Option<Data<T>>, namada_storage::Error>
where
    T: BorshDeserialize,
    ENV: for<'a> VpEnv<'a>,
{
    let pre = env.read_pre(key)?;
    let post = env.read_post(key)?;
    Ok(match (pre, post) {
        (None, None) => {
            // If the key was inserted and then deleted in the same tx, we don't
            // need to validate it as it's not visible to any VPs
            None
        }
        (None, Some(post)) => Some(Data::Add { post }),
        (Some(pre), None) => Some(Data::Delete { pre }),
        (Some(pre), Some(post)) => Some(Data::Update { pre, post }),
    })
}

pub trait LazyCollectionExt: LazyCollection {
    /// Actions on the collection determined from changed storage keys by
    /// `Self::validate`
    type Action;

    /// Possible sub-keys together with the data read from storage
    type SubKeyWithData: Debug;

    /// Try to read and decode the data for each change storage key in prior and
    /// posterior state. If there is no value in neither prior or posterior
    /// state (which is a possible state when transaction e.g. writes and then
    /// deletes one storage key, but it is treated as a no-op as it doesn't
    /// affect result of validation), returns `Ok(None)`.
    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> namada_storage::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>;

    /// Validate changed sub-keys associated with their data and return back
    /// a vector of `Self::Action`s, if the changes are valid
    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> namada_storage::Result<Vec<Self::Action>>;

    /// Accumulate storage changes inside a `ValidationBuilder`. This is
    /// typically done by the validity predicate while looping through the
    /// changed keys. If the resulting `builder` is not `None`, one must
    /// call `fn build()` on it to get the validation result.
    /// This function will return `Ok(true)` if the storage key is a valid
    /// sub-key of this collection, `Ok(false)` if the storage key doesn't match
    /// the prefix of this collection, or error if the prefix matches this
    /// collection, but the key itself is not recognized.
    fn accumulate<ENV>(
        &self,
        env: &ENV,
        builder: &mut Option<ValidationBuilder<Self::SubKeyWithData>>,
        key_changed: &storage::Key,
    ) -> namada_storage::Result<bool>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        if let Some(sub) = self.is_valid_sub_key(key_changed)? {
            let change = Self::read_sub_key_data(env, key_changed, sub)?;
            if let Some(change) = change {
                let builder =
                    builder.get_or_insert(ValidationBuilder::default());
                builder.changes.push(change);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Execute validation on the validation builder, to be called when
    /// `accumulate` instantiates the builder to `Some(_)`, after all the
    /// changes storage keys have been processed.
    fn validate(
        builder: ValidationBuilder<Self::SubKeyWithData>,
    ) -> namada_storage::Result<Vec<Self::Action>> {
        Self::validate_changed_sub_keys(builder.changes)
    }
}
