//! DB mock for testing

use std::cell::RefCell;
use std::collections::{btree_map, BTreeMap};
use std::ops::Bound::{Excluded, Included};
use std::path::Path;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};

use super::merkle_tree::{MerkleTreeStoresRead, StoreType};
use super::{
    BlockStateRead, BlockStateWrite, DBIter, DBWriteBatch, Error, Result, DB,
};
use crate::ledger::storage::types::{self, KVBytes, PrefixIterator};
use crate::types::ethereum_structs;
use crate::types::hash::Hash;
#[cfg(feature = "ferveo-tpke")]
use crate::types::internal::TxQueue;
use crate::types::storage::{
    BlockHeight, BlockResults, Epoch, Epochs, EthEventsQueue, Header, Key,
    KeySeg, KEY_SEGMENT_SEPARATOR,
};
use crate::types::time::DateTimeUtc;

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
        #[cfg(feature = "ferveo-tpke")]
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
        let mut epoch = None;
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
                #[cfg(feature = "ferveo-tpke")]
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
        _is_full_commit: bool,
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
            ethereum_height,
            eth_events_queue,
            #[cfg(feature = "ferveo-tpke")]
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
        #[cfg(feature = "ferveo-tpke")]
        {
            self.0
                .borrow_mut()
                .insert("tx_queue".into(), types::encode(&tx_queue));
        }

        let prefix_key = Key::from(height.to_db_key());
        // Merkle tree
        {
            let prefix_key = prefix_key
                .push(&"tree".to_owned())
                .map_err(Error::KeyError)?;
            for st in StoreType::iter() {
                let prefix_key = prefix_key
                    .push(&st.to_string())
                    .map_err(Error::KeyError)?;
                let root_key = prefix_key
                    .push(&"root".to_owned())
                    .map_err(Error::KeyError)?;
                self.0.borrow_mut().insert(
                    root_key.to_string(),
                    types::encode(merkle_tree_stores.root(st)),
                );
                let store_key = prefix_key
                    .push(&"store".to_owned())
                    .map_err(Error::KeyError)?;
                self.0.borrow_mut().insert(
                    store_key.to_string(),
                    merkle_tree_stores.store(st).encode(),
                );
            }
        }
        // Block header
        {
            if let Some(h) = header {
                let key = prefix_key
                    .push(&"header".to_owned())
                    .map_err(Error::KeyError)?;
                self.0.borrow_mut().insert(
                    key.to_string(),
                    h.try_to_vec().expect("serialization failed"),
                );
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
        height: BlockHeight,
    ) -> Result<Option<(BlockHeight, MerkleTreeStoresRead)>> {
        let mut merkle_tree_stores = MerkleTreeStoresRead::default();
        let height_key = Key::from(height.to_db_key());
        let tree_key = height_key
            .push(&"tree".to_owned())
            .map_err(Error::KeyError)?;
        for st in StoreType::iter() {
            let prefix_key =
                tree_key.push(&st.to_string()).map_err(Error::KeyError)?;
            let root_key = prefix_key
                .push(&"root".to_owned())
                .map_err(Error::KeyError)?;
            let bytes = self.0.borrow().get(&root_key.to_string()).cloned();
            match bytes {
                Some(b) => {
                    let root = types::decode(b).map_err(Error::CodingError)?;
                    merkle_tree_stores.set_root(st, root);
                }
                None => return Ok(None),
            }

            let store_key = prefix_key
                .push(&"store".to_owned())
                .map_err(Error::KeyError)?;
            let bytes = self.0.borrow().get(&store_key.to_string()).cloned();
            match bytes {
                Some(b) => {
                    merkle_tree_stores.set_store(st.decode_store(b)?);
                }
                None => return Ok(None),
            }
        }
        Ok(Some((height, merkle_tree_stores)))
    }

    fn has_replay_protection_entry(&self, hash: &Hash) -> Result<bool> {
        let prefix_key =
            Key::parse("replay_protection").map_err(Error::KeyError)?;
        for prefix in ["last", "all"] {
            let key = prefix_key
                .push(&prefix.to_string())
                .map_err(Error::KeyError)?
                .push(&hash.to_string())
                .map_err(Error::KeyError)?;

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
        _height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64> {
        let value = value.as_ref();
        let key = Key::parse("subspace").map_err(Error::KeyError)?.join(key);
        let current_len = value.len() as i64;
        Ok(
            match self
                .0
                .borrow_mut()
                .insert(key.to_string(), value.to_owned())
            {
                Some(prev_value) => current_len - prev_value.len() as i64,
                None => current_len,
            },
        )
    }

    fn delete_subspace_val(
        &mut self,
        _height: BlockHeight,
        key: &Key,
    ) -> Result<i64> {
        let key = Key::parse("subspace").map_err(Error::KeyError)?.join(key);
        Ok(match self.0.borrow_mut().remove(&key.to_string()) {
            Some(value) => value.len() as i64,
            None => 0,
        })
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
        _height: BlockHeight,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<i64> {
        let value = value.as_ref();
        let key = Key::parse("subspace").map_err(Error::KeyError)?.join(key);
        let current_len = value.len() as i64;
        Ok(
            match self
                .0
                .borrow_mut()
                .insert(key.to_string(), value.to_owned())
            {
                Some(prev_value) => current_len - prev_value.len() as i64,
                None => current_len,
            },
        )
    }

    fn batch_delete_subspace_val(
        &self,
        _batch: &mut Self::WriteBatch,
        _height: BlockHeight,
        key: &Key,
    ) -> Result<i64> {
        let key = Key::parse("subspace").map_err(Error::KeyError)?.join(key);
        Ok(match self.0.borrow_mut().remove(&key.to_string()) {
            Some(value) => value.len() as i64,
            None => 0,
        })
    }

    fn prune_merkle_tree_stores(
        &mut self,
        _batch: &mut Self::WriteBatch,
        epoch: Epoch,
        pred_epochs: &Epochs,
    ) -> Result<()> {
        match pred_epochs.get_start_height_of_epoch(epoch) {
            Some(height) => {
                let prefix_key = Key::from(height.to_db_key())
                    .push(&"tree".to_owned())
                    .map_err(Error::KeyError)?;
                for st in StoreType::iter() {
                    if *st != StoreType::Base {
                        let prefix_key = prefix_key
                            .push(&st.to_string())
                            .map_err(Error::KeyError)?;
                        let root_key = prefix_key
                            .push(&"root".to_owned())
                            .map_err(Error::KeyError)?;
                        self.0.borrow_mut().remove(&root_key.to_string());
                        let store_key = prefix_key
                            .push(&"store".to_owned())
                            .map_err(Error::KeyError)?;
                        self.0.borrow_mut().remove(&store_key.to_string());
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
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
        let db_prefix = "subspace/".to_owned();
        let prefix = format!(
            "{}{}",
            db_prefix,
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
        MockPrefixIterator::new(MockIterator { prefix, iter }, db_prefix)
    }

    fn iter_results(&'iter self) -> MockPrefixIterator {
        let db_prefix = "results/".to_owned();
        let prefix = "results".to_owned();
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(MockIterator { prefix, iter }, db_prefix)
    }

    fn iter_old_diffs(&self, _height: BlockHeight) -> MockPrefixIterator {
        // Mock DB can read only the latest value for now
        unimplemented!()
    }

    fn iter_new_diffs(&self, _height: BlockHeight) -> MockPrefixIterator {
        // Mock DB can read only the latest value for now
        unimplemented!()
    }

    fn iter_replay_protection(&'iter self) -> Self::PrefixIter {
        let db_prefix = "replay_protection/".to_owned();
        let iter = self.0.borrow().clone().into_iter();
        MockPrefixIterator::new(
            MockIterator {
                prefix: "last".to_string(),
                iter,
            },
            db_prefix,
        )
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
                match key.strip_prefix(&self.db_prefix) {
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
