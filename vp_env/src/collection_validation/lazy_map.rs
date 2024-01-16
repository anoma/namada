//! LazyMap validation helpers

use core::fmt::Debug;
use core::hash::Hash;
use std::collections::HashMap;

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::types::storage;
use namada_storage::collections::lazy_map::{LazyMap, NestedSubKey, SubKey};
use namada_storage::collections::{Nested, Simple};

use super::{read_data, Data, LazyCollectionExt};
use crate::VpEnv;

/// Possible sub-keys of a [`LazyMap`], together with their [`Data`]
/// that contains prior and posterior state.
#[derive(Clone, Debug)]
pub enum SubKeyWithData<K, V> {
    /// Data sub-key, further sub-keyed by its literal map key
    Data(K, Data<V>),
}

/// Possible actions that can modify a simple (not nested) [`LazyMap`]. This
/// roughly corresponds to the methods that have `StorageWrite` access.
#[derive(Clone, Debug)]
pub enum Action<K, V> {
    /// Insert or update a value `V` at key `K` in a [`LazyMap<K, V>`].
    Insert(K, V),
    /// Remove a value `V` at key `K` from a [`LazyMap<K, V>`].
    Remove(K, V),
    /// Update a value `V` at key `K` in a [`LazyMap<K, V>`].
    Update {
        /// key at which the value is updated
        key: K,
        /// value before the update
        pre: V,
        /// value after the update
        post: V,
    },
}

/// Possible actions that can modify a nested [`LazyMap`].
#[derive(Clone, Debug)]
pub enum NestedAction<K, A> {
    /// Nested collection action `A` at key `K`
    At(K, A),
}

impl<K, V> LazyCollectionExt for LazyMap<K, V, Nested>
where
    K: storage::KeySeg + Clone + Hash + Eq + Debug,
    V: LazyCollectionExt + Debug,
{
    type Action = NestedAction<K, <V as LazyCollectionExt>::Action>;
    type SubKeyWithData =
        NestedSubKey<K, <V as LazyCollectionExt>::SubKeyWithData>;

    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> namada_storage::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        let NestedSubKey::Data {
            key,
            // In here, we just have a nested sub-key without data
            nested_sub_key,
        } = sub_key;
        // Try to read data from the nested collection
        let nested_data = <V as LazyCollectionExt>::read_sub_key_data(
            env,
            storage_key,
            nested_sub_key,
        )?;
        // If found, transform it back into a `NestedSubKey`, but with
        // `nested_sub_key` replaced with the one we read
        Ok(nested_data.map(|nested_sub_key| NestedSubKey::Data {
            key,
            nested_sub_key,
        }))
    }

    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> namada_storage::Result<Vec<Self::Action>> {
        // We have to group the nested sub-keys by the key from this map
        let mut grouped_by_key: HashMap<
            K,
            Vec<<V as LazyCollectionExt>::SubKeyWithData>,
        > = HashMap::new();
        for NestedSubKey::Data {
            key,
            nested_sub_key,
        } in keys
        {
            grouped_by_key
                .entry(key)
                .or_insert_with(Vec::new)
                .push(nested_sub_key);
        }

        // Recurse for each sub-keys group
        let mut actions = vec![];
        for (key, sub_keys) in grouped_by_key {
            let nested_actions =
                <V as LazyCollectionExt>::validate_changed_sub_keys(sub_keys)?;
            actions.extend(
                nested_actions
                    .into_iter()
                    .map(|action| NestedAction::At(key.clone(), action)),
            );
        }
        Ok(actions)
    }
}

impl<K, V> LazyCollectionExt for LazyMap<K, V, Simple>
where
    K: storage::KeySeg + Debug,
    V: BorshDeserialize + BorshSerialize + 'static + Debug,
{
    type Action = Action<K, V>;
    type SubKeyWithData = SubKeyWithData<K, V>;

    fn read_sub_key_data<ENV>(
        env: &ENV,
        storage_key: &storage::Key,
        sub_key: Self::SubKey,
    ) -> namada_storage::Result<Option<Self::SubKeyWithData>>
    where
        ENV: for<'a> VpEnv<'a>,
    {
        let SubKey::Data(key) = sub_key;
        let data = read_data(env, storage_key)?;
        Ok(data.map(|data| SubKeyWithData::Data(key, data)))
    }

    fn validate_changed_sub_keys(
        keys: Vec<Self::SubKeyWithData>,
    ) -> namada_storage::Result<Vec<Self::Action>> {
        Ok(keys
            .into_iter()
            .map(|change| {
                let SubKeyWithData::Data(key, data) = change;
                match data {
                    Data::Add { post } => Action::Insert(key, post),
                    Data::Update { pre, post } => {
                        Action::Update { key, pre, post }
                    }
                    Data::Delete { pre } => Action::Remove(key, pre),
                }
            })
            .collect())
    }
}
