//! LazySet validation helpers

use std::fmt::Debug;

use namada_core::storage;
use namada_storage::collections::lazy_set::{LazySet, SubKey};

use super::LazyCollectionExt;
use crate::VpEnv;

/// Possible actions that can modify a [`LazySet`]. This roughly corresponds to
/// the methods that have `StorageWrite` access.
#[derive(Clone, Debug)]
pub enum Action<K> {
    /// Insert a key `K` in a [`LazySet<K>`].
    Insert(K),
    /// Remove a key `K` from a [`LazySet<K>`].
    Remove(K),
}

impl<K> LazyCollectionExt for LazySet<K>
where
    K: storage::KeySeg + Debug,
{
    type Action = Action<K>;
    type SubKeyWithData = Action<K>;

    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> namada_storage::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        let SubKey::Data(key) = sub_key;
        determine_action(env, storage_key, key)
    }

    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> namada_storage::Result<Vec<Self::Action>> {
        Ok(keys)
    }
}

/// Determine what action was taken from the pre/post state
pub fn determine_action<ENV, K>(
    env: &ENV,
    storage_key: &storage::Key,
    parsed_key: K,
) -> namada_storage::Result<Option<Action<K>>>
where
    ENV: for<'a> VpEnv<'a>,
{
    let pre = env.read_pre(storage_key)?;
    let post = env.read_post(storage_key)?;
    Ok(match (pre, post) {
        (None, None) => {
            // If the key was inserted and then deleted in the same tx, we don't
            // need to validate it as it's not visible to any VPs
            None
        }
        (None, Some(())) => Some(Action::Insert(parsed_key)),
        (Some(()), None) => Some(Action::Remove(parsed_key)),
        (Some(()), Some(())) => {
            // Because the value for set is a unit, we can skip this too
            None
        }
    })
}
