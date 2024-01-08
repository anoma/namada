//! DB mock for testing

use std::cell::RefCell;
use std::collections::{btree_map, BTreeMap};
use std::ops::Bound::{Excluded, Included};
use std::path::Path;
use std::str::FromStr;

use itertools::Either;
use namada_core::borsh::{BorshDeserialize, BorshSerializeExt};
use namada_core::ledger::replay_protection;
use namada_core::types;
use namada_core::types::hash::Hash;
use namada_core::types::storage::{
    BlockHeight, BlockResults, Epoch, EthEventsQueue, Header, Key, KeySeg,
    KEY_SEGMENT_SEPARATOR,
};
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token::ConversionState;
use namada_core::types::{ethereum_events, ethereum_structs};
use namada_merkle_tree::{
    base_tree_key_prefix, subtree_key_prefix, MerkleTreeStoresRead, StoreType,
};

use crate::db::{
    BlockStateRead, BlockStateWrite, DBIter, DBWriteBatch, Error, Result, DB,
};
use crate::tx_queue::TxQueue;
use crate::types::{KVBytes, PrefixIterator};

/// An in-memory DB for testing.
#[derive(Debug, Default)]
pub struct MockDB(
    // The state is wrapped in `RefCell` to allow modifying it directly from
    // batch write method (which requires immutable self ref).
    RefCell<BTreeMap<String, Vec<u8>>>,
);

// The `MockDB` is not `Sync`, but we're sharing it across threads for reading
// only (for parallelized VP runs). In a different context, this may not be
// safe.
unsafe impl Sync for MockDB {}

/// An in-memory write batch is not needed as it just updates values in memory.
/// It's here to satisfy the storage interface.
#[derive(Debug, Default)]
pub struct MockDBWriteBatch;

impl DB for MockDB {
    /// There is no cache for MockDB
    type Cache = ();
    type WriteBatch = MockDBWriteBatch;

    fn open(_db_path: impl AsRef<Path>, _cache: Option<&Self::Cache>) -> Self {
        Self::default()
    }

    fn flush(&self, _wait: bool) -> Result<()> {
        Ok(())
    }

    fn read_last_block(&self) -> Result<Option<BlockStateRead>> {
        // Block height
        let height: BlockHeight = match self.0.borrow().get("height") {
            Some(bytes) => types::decode(bytes).map_err(Error::CodingError)?,
            None => return Ok(None),
        };
        // Block results
        let results_path = format!("results/{}", height.raw());
        let results: BlockResults =
            match self.0.borrow().get(results_path.as_str()) {
                Some(bytes) => {
                    types::decode(bytes).map_err(Error::CodingError)?
                }
                None => return Ok(None),
            };

        // Epoch start height and time
        let next_epoch_min_start_height: BlockHeight =
            match self.0.borrow().get("next_epoch_min_start_height") {
                Some(bytes) => {
                    types::decode(bytes).map_err(Error::CodingError)?
                }
                None => return Ok(None),
            };
        let next_epoch_min_start_time: DateTimeUtc =
            match self.0.borrow().get("next_epoch_min_start_time") {
                Some(bytes) => {
                    types::decode(bytes).map_err(Error::CodingError)?
                }
                None => return Ok(None),
            };
        let update_epoch_blocks_delay: Option<u32> =
            match self.0.borrow().get("update_epoch_blocks_delay") {
                Some(bytes) => {
                    types::decode(bytes).map_err(Error::CodingError)?
                }
                None => return Ok(None),
            };
        let conversion_state: ConversionState =
            match self.0.borrow().get("conversion_state") {
                Some(bytes) => {
                    types::decode(bytes).map_err(Error::CodingError)?
                }
                None => return Ok(None),
            };
        let tx_queue: TxQueue = match self.0.borrow().get("tx_queue") {
            Some(bytes) => types::decode(bytes).map_err(Error::CodingError)?,
            None => return Ok(None),
        };

        let ethereum_height: Option<ethereum_structs::BlockHeight> =
            match self.0.borrow().get("ethereum_height") {
                Some(bytes) => {
                    types::decode(bytes).map_err(Error::CodingError)?
                }
                None => return Ok(None),
            };

        let eth_events_queue: EthEventsQueue =
            match self.0.borrow().get("ethereum_height") {
                Some(bytes) => {
                    types::decode(bytes).map_err(Error::CodingError)?
                }
                None => return Ok(None),
            };

        // Load data at the height
        let prefix = format!("{}/", height.raw());
        let upper_prefix = format!("{}/", height.next_height().raw());
        let mut merkle_tree_stores = MerkleTreeStoresRead::default();
        let mut hash = None;
        let mut time = None;
        let mut epoch: Option<Epoch> = None;
        let mut pred_epochs = None;
        let mut address_gen = None;
        for (path, bytes) in self
            .0
            .borrow()
            .range((Included(prefix), Excluded(upper_prefix)))
        {
            let segments: Vec<&str> =
                path.split(KEY_SEGMENT_SEPARATOR).collect();
            match segments.get(1) {
                Some(prefix) => match *prefix {
                    "tree" => match segments.get(2) {
                        Some(s) => {
                            let st = StoreType::from_str(s)?;
                            match segments.get(3) {
                                Some(&"root") => merkle_tree_stores.set_root(
                                    &st,
                                    types::decode(bytes)
                                        .map_err(Error::CodingError)?,
                                ),
                                Some(&"store") => merkle_tree_stores
                                    .set_store(st.decode_store(bytes)?),
                                _ => unknown_key_error(path)?,
                            }
                        }
                        None => unknown_key_error(path)?,
                    },
                    "header" => {
                        // the block header doesn't have to be restored
                    }
                    "hash" => {
                        hash = Some(
                            types::decode(bytes).map_err(Error::CodingError)?,
                        )
                    }
                    "time" => {
                        time = Some(
                            types::decode(bytes).map_err(Error::CodingError)?,
                        )
                    }
                    "epoch" => {
                        epoch = Some(
                            types::decode(bytes).map_err(Error::CodingError)?,
                        )
                    }
                    "pred_epochs" => {
                        pred_epochs = Some(
                            types::decode(bytes).map_err(Error::CodingError)?,
                        )
                    }
                    "address_gen" => {
                        address_gen = Some(
                            types::decode(bytes).map_err(Error::CodingError)?,
                        );
                    }
                    _ => unknown_key_error(path)?,
                },
                None => unknown_key_error(path)?,
            }
        }
        // Restore subtrees of Merkle tree
        if let Some(epoch) = epoch {
            for st in StoreType::iter_subtrees() {
                let prefix_key = subtree_key_prefix(st, epoch);
                let root_key =
                    prefix_key.clone().with_segment("root".to_owned());
                if let Some(bytes) = self.0.borrow().get(&root_key.to_string())
                {
                    merkle_tree_stores.set_root(
                        st,
                        types::decode(bytes).map_err(Error::CodingError)?,
                    );
                }
                let store_key = prefix_key.with_segment("store".to_owned());
                if let Some(bytes) = self.0.borrow().get(&store_key.to_string())
                {
                    merkle_tree_stores.set_store(st.decode_store(bytes)?);
                }
            }
        }
        match (hash, time, epoch, pred_epochs, address_gen) {
            (
                Some(hash),
                Some(time),
                Some(epoch),
                Some(pred_epochs),
                Some(address_gen),
            ) => Ok(Some(BlockStateRead {
                merkle_tree_stores,
                hash,
                height,
                time,
                epoch,
                pred_epochs,
                next_epoch_min_start_height,
                next_epoch_min_start_time,
                update_epoch_blocks_delay,
                address_gen,
                results,
                conversion_state,
                tx_queue,
                ethereum_height,
                eth_events_queue,
            })),
            _ => Err(Error::Temporary {
                error: "Essential data couldn't be read from the DB"
                    .to_string(),
            }),
        }
    }

    fn add_block_to_batch(
        &self,
        state: BlockStateWrite,
        _batch: &mut Self::WriteBatch,
        is_full_commit: bool,
    ) -> Result<()> {
        let BlockStateWrite {
            merkle_tree_stores,
            header,
            hash,
            time,
            height,
            epoch,
            pred_epochs,
            next_epoch_min_start_height,
            next_epoch_min_start_time,
            update_epoch_blocks_delay,
            address_gen,
            results,
            conversion_state,
            ethereum_height,
            eth_events_queue,
            tx_queue,
        }: BlockStateWrite = state;

        // Epoch start height and time
        self.0.borrow_mut().insert(
            "next_epoch_min_start_height".into(),
            types::encode(&next_epoch_min_start_height),
        );
        self.0.borrow_mut().insert(
            "next_epoch_min_start_time".into(),
            types::encode(&next_epoch_min_start_time),
        );
        self.0.borrow_mut().insert(
            "update_epoch_blocks_delay".into(),
            types::encode(&update_epoch_blocks_delay),
        );
        self.0
            .borrow_mut()
            .insert("ethereum_height".into(), types::encode(&ethereum_height));
        self.0.borrow_mut().insert(
            "eth_events_queue".into(),
            types::encode(&eth_events_queue),
        );
        self.0
            .borrow_mut()
            .insert("tx_queue".into(), types::encode(&tx_queue));
        self.0
            .borrow_mut()
            .insert("conversion_state".into(), types::encode(conversion_state));

        let prefix_key = Key::from(height.to_db_key());
        // Merkle tree
        {
            for st in StoreType::iter() {
                if *st == StoreType::Base || is_full_commit {
                    let key_prefix = if *st == StoreType::Base {
                        base_tree_key_prefix(height)
                    } else {
                        subtree_key_prefix(st, epoch)
                    };
                    let root_key =
                        key_prefix.clone().with_segment("root".to_owned());
                    self.0.borrow_mut().insert(
                        root_key.to_string(),
                        types::encode(merkle_tree_stores.root(st)),
                    );
                    let store_key = key_prefix.with_segment("store".to_owned());
                    self.0.borrow_mut().insert(
                        store_key.to_string(),
                        merkle_tree_stores.store(st).encode(),
                    );
                }
            }
        }
        // Block header
        {
            if let Some(h) = header {
                let key = prefix_key
                    .push(&"header".to_owned())
                    .map_err(Error::KeyError)?;
                self.0
                    .borrow_mut()
                    .insert(key.to_string(), h.serialize_to_vec());
            }
        }
        // Block hash
        {
            let key = prefix_key
                .push(&"hash".to_owned())
                .map_err(Error::KeyError)?;
            self.0
                .borrow_mut()
                .insert(key.to_string(), types::encode(&hash));
        }
        // Block time
        {
            let key = prefix_key
                .push(&"time".to_owned())
                .map_err(Error::KeyError)?;
            self.0
                .borrow_mut()
                .insert(key.to_string(), types::encode(&time));
        }
        // Block epoch
        {
            let key = prefix_key
                .push(&"epoch".to_owned())
                .map_err(Error::KeyError)?;
            self.0
                .borrow_mut()
                .insert(key.to_string(), types::encode(&epoch));
        }
        // Predecessor block epochs
        {
            let key = prefix_key
                .push(&"pred_epochs".to_owned())
                .map_err(Error::KeyError)?;
            self.0
                .borrow_mut()
                .insert(key.to_string(), types::encode(&pred_epochs));
        }
        // Address gen
        {
            let key = prefix_key
                .push(&"address_gen".to_owned())
                .map_err(Error::KeyError)?;
            let value = &address_gen;
            self.0
                .borrow_mut()
                .insert(key.to_string(), types::encode(value));
        }
        self.0
            .borrow_mut()
            .insert("height".to_owned(), types::encode(&height));
        // Block results
        {
            let results_path = format!("results/{}", height.raw());
            self.0
                .borrow_mut()
                .insert(results_path, types::encode(&results));
        }
        Ok(())
    }

    fn read_block_header(&self, height: BlockHeight) -> Result<Option<Header>> {
        let prefix_key = Key::from(height.to_db_key());
        let key = prefix_key
            .push(&"header".to_owned())
            .map_err(Error::KeyError)?;
        let value = self.0.borrow().get(&key.to_string()).cloned();
        match value {
            Some(v) => Ok(Some(
                BorshDeserialize::try_from_slice(&v[..])
                    .map_err(Error::BorshCodingError)?,
            )),
            None => Ok(None),
        }
    }

    fn read_merkle_tree_stores(
        &self,
        epoch: Epoch,
        base_height: BlockHeight,
        store_type: Option<StoreType>,
    ) -> Result<Option<MerkleTreeStoresRead>> {
        let mut merkle_tree_stores = MerkleTreeStoresRead::default();
        let store_types = store_type
            .as_ref()
            .map(|st| Either::Left(std::iter::once(st)))
            .unwrap_or_else(|| Either::Right(StoreType::iter()));
        for st in store_types {
            let key_prefix = if *st == StoreType::Base {
                base_tree_key_prefix(base_height)
            } else {
                subtree_key_prefix(st, epoch)
            };
            let root_key = key_prefix.clone().with_segment("root".to_owned());
            let bytes = self.0.borrow().get(&root_key.to_string()).cloned();
            match bytes {
                Some(b) => {
                    let root = types::decode(b).map_err(Error::CodingError)?;
                    merkle_tree_stores.set_root(st, root);
                }
                None => return Ok(None),
            }

            let store_key = key_prefix.with_segment("store".to_owned());
            let bytes = self.0.borrow().get(&store_key.to_string()).cloned();
            match bytes {
                Some(b) => {
                    merkle_tree_stores.set_store(st.decode_store(b)?);
                }
                None => return Ok(None),
            }
        }
        Ok(Some(merkle_tree_stores))
    }

    fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool> {
        let prefix_key =
            Key::parse("replay_protection").map_err(Error::KeyError)?;
        for subkey in [
            replay_protection::last_key(hash),
            replay_protection::all_key(hash),
        ] {
            let key = prefix_key.join(&subkey);
            if self.0.borrow().contains_key(&key.to_string()) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn read_subspace_val(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        let key = Key::parse("subspace").map_err(Error::KeyError)?.join(key);
        Ok(self.0.borrow().get(&key.to_string()).cloned())
    }

    fn read_subspace_val_with_height(
        &self,
        key: &Key,
        _height: BlockHeight,
        _last_height: BlockHeight,
    ) -> Result<Option<Vec<u8>>> {
        tracing::warn!(
            "read_subspace_val_with_height is not implemented, will read \
             subspace value from latest height"
        );
        self.read_subspace_val(key)
    }

    fn write_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64> {
        // batch_write are directly committed
        self.batch_write_subspace_val(&mut MockDBWriteBatch, height, key, value)
    }

    fn delete_subspace_val(
        &mut self,
        height: BlockHeight,
        key: &Key,
    ) -> Result<i64> {
        // batch_delete are directly committed
        self.batch_delete_subspace_val(&mut MockDBWriteBatch, height, key)
    }

    fn batch() -> Self::WriteBatch {
        MockDBWriteBatch
    }

    fn exec_batch(&mut self, _batch: Self::WriteBatch) -> Result<()> {
        // Nothing to do - in MockDB, batch writes are committed directly from
        // `batch_write_subspace_val` and `batch_delete_subspace_val`.
        Ok(())
    }

    fn batch_write_subspace_val(
        &self,
        _batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64> {
        let value = value.as_ref();
        let subspace_key =
            Key::parse("subspace").map_err(Error::KeyError)?.join(key);
        let current_len = value.len() as i64;
        let diff_prefix = Key::from(height.to_db_key());
        let mut db = self.0.borrow_mut();
        Ok(
            match db.insert(subspace_key.to_string(), value.to_owned()) {
                Some(prev_value) => {
                    let old_key = diff_prefix
                        .push(&"old".to_string().to_db_key())
                        .unwrap()
                        .join(key);
                    db.insert(old_key.to_string(), prev_value.clone());
                    let new_key = diff_prefix
                        .push(&"new".to_string().to_db_key())
                        .unwrap()
                        .join(key);
                    db.insert(new_key.to_string(), value.to_owned());
                    current_len - prev_value.len() as i64
                }
                None => {
                    let new_key = diff_prefix
                        .push(&"new".to_string().to_db_key())
                        .unwrap()
                        .join(key);
                    db.insert(new_key.to_string(), value.to_owned());
                    current_len
                }
            },
        )
    }

    fn batch_delete_subspace_val(
        &self,
        _batch: &mut Self::WriteBatch,
        height: BlockHeight,
        key: &Key,
    ) -> Result<i64> {
        let subspace_key =
            Key::parse("subspace").map_err(Error::KeyError)?.join(key);
        let diff_prefix = Key::from(height.to_db_key());
        let mut db = self.0.borrow_mut();
        Ok(match db.remove(&subspace_key.to_string()) {
            Some(value) => {
                let old_key = diff_prefix
                    .push(&"old".to_string().to_db_key())
                    .unwrap()
                    .join(key);
                db.insert(old_key.to_string(), value.clone());
                value.len() as i64
            }
            None => 0,
        })
    }

    fn prune_merkle_tree_store(
        &mut self,
        _batch: &mut Self::WriteBatch,
        store_type: &StoreType,
        epoch: Epoch,
    ) -> Result<()> {
        let prefix_key = subtree_key_prefix(store_type, epoch);
        let root_key = prefix_key
            .push(&"root".to_owned())
            .map_err(Error::KeyError)?;
        self.0.borrow_mut().remove(&root_key.to_string());
        let store_key = prefix_key
            .push(&"store".to_owned())
            .map_err(Error::KeyError)?;
        self.0.borrow_mut().remove(&store_key.to_string());
        Ok(())
    }

    fn read_bridge_pool_signed_nonce(
        &self,
        _height: BlockHeight,
        _last_height: BlockHeight,
    ) -> Result<Option<ethereum_events::Uint>> {
        Ok(None)
    }

    fn write_replay_protection_entry(
        &mut self,
        _batch: &mut Self::WriteBatch,
        key: &Key,
    ) -> Result<()> {
        let key = Key::parse("replay_protection")
            .map_err(Error::KeyError)?
            .join(key);

        match self.0.borrow_mut().insert(key.to_string(), vec![]) {
            Some(_) => Err(Error::DBError(format!(
                "Replay protection key {key} already in storage"
            ))),
            None => Ok(()),
        }
    }

    fn delete_replay_protection_entry(
        &mut self,
        _batch: &mut Self::WriteBatch,
        key: &Key,
    ) -> Result<()> {
        let key = Key::parse("replay_protection")
            .map_err(Error::KeyError)?
            .join(key);

        self.0.borrow_mut().remove(&key.to_string());

        Ok(())
    }
}

impl<'iter> DBIter<'iter> for MockDB {
    type PrefixIter = MockPrefixIterator;

    fn iter_prefix(&'iter self, prefix: Option<&Key>) -> MockPrefixIterator {
        let stripped_prefix = "subspace/".to_owned();
        let prefix = format!(
            "{}{}",
            stripped_prefix,
            match prefix {
                Some(prefix) => {
                    if prefix == &Key::default() {
                        prefix.to_string()
                    } else {
                        format!("{prefix}/")
                    }
                }
                None => "".to_string(),
            }
        );
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_results(&'iter self) -> MockPrefixIterator {
        let stripped_prefix = "results/".to_owned();
        let prefix = "results".to_owned();
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_old_diffs(
        &self,
        height: BlockHeight,
        prefix: Option<&Key>,
    ) -> MockPrefixIterator {
        // Returns an empty iterator since Mock DB can read only the latest
        // value for now
        let stripped_prefix = format!("{}/old/", height.0.raw());
        let prefix = prefix
            .map(|k| {
                if k == &Key::default() {
                    stripped_prefix.clone()
                } else {
                    format!("{stripped_prefix}{k}/")
                }
            })
            .unwrap_or("".to_string());
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_new_diffs(
        &self,
        height: BlockHeight,
        prefix: Option<&Key>,
    ) -> MockPrefixIterator {
        // Returns an empty iterator since Mock DB can read only the latest
        // value for now
        let stripped_prefix = format!("{}/new/", height.0.raw());
        let prefix = prefix
            .map(|k| {
                if k == &Key::default() {
                    stripped_prefix.clone()
                } else {
                    format!("{stripped_prefix}{k}/")
                }
            })
            .unwrap_or("".to_string());
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }

    fn iter_replay_protection(&'iter self) -> Self::PrefixIter {
        let stripped_prefix =
            format!("replay_protection/{}/", replay_protection::last_prefix());
        let prefix = stripped_prefix.clone();
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, stripped_prefix)
    }
}

/// A prefix iterator base for the [`MockPrefixIterator`].
#[derive(Debug)]
pub struct MockIterator {
    prefix: String,
    /// The concrete iterator
    pub iter: btree_map::IntoIter<String, Vec<u8>>,
}

/// A prefix iterator for the [`MockDB`].
pub type MockPrefixIterator = PrefixIterator<MockIterator>;

impl Iterator for MockIterator {
    type Item = Result<KVBytes>;

    fn next(&mut self) -> Option<Self::Item> {
        for (key, val) in &mut self.iter {
            if key.starts_with(&self.prefix) {
                return Some(Ok((
                    Box::from(key.as_bytes()),
                    Box::from(val.as_slice()),
                )));
            }
        }
        None
    }
}

impl Iterator for PrefixIterator<MockIterator> {
    type Item = (String, Vec<u8>, u64);

    /// Returns the next pair and the gas cost
    fn next(&mut self) -> Option<(String, Vec<u8>, u64)> {
        match self.iter.next() {
            Some(result) => {
                let (key, val) =
                    result.expect("Prefix iterator shouldn't fail");
                let key = String::from_utf8(key.to_vec())
                    .expect("Cannot convert from bytes to key string");
                match key.strip_prefix(&self.stripped_prefix) {
                    Some(k) => {
                        let gas = k.len() + val.len();
                        Some((k.to_owned(), val.to_vec(), gas as _))
                    }
                    None => self.next(),
                }
            }
            None => None,
        }
    }
}

impl DBWriteBatch for MockDBWriteBatch {}

fn unknown_key_error(key: &str) -> Result<()> {
    Err(Error::UnknownKey {
        key: key.to_owned(),
    })
}
