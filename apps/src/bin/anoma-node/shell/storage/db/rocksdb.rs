//! The persistent storage in RocksDB.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;

use anoma_shared::types::{Address, BlockHash, BlockHeight, Key, KeySeg};
use rocksdb::{
    BlockBasedOptions, Direction, FlushOptions, IteratorMode, Options,
    ReadOptions, SliceTransform, WriteBatch, WriteOptions,
};
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use super::{BlockState, DBIter, Error, Result, DB};
use crate::shell::storage::types::{MerkleTree, PrefixIterator, Value};

// TODO the DB schema will probably need some kind of versioning

#[derive(Debug)]
pub struct RocksDB(rocksdb::DB);

/// Open RocksDB for the DB
pub fn open(path: impl AsRef<Path>) -> Result<RocksDB> {
    let mut cf_opts = Options::default();
    // ! recommended initial setup https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#other-general-options
    cf_opts.set_level_compaction_dynamic_level_bytes(true);
    // compactions + flushes
    cf_opts.set_max_background_jobs(6);
    cf_opts.set_bytes_per_sync(1048576);
    // TODO the recommended default `options.compaction_pri =
    // kMinOverlappingRatio` doesn't seem to be available in Rust
    let mut table_opts = BlockBasedOptions::default();
    table_opts.set_block_size(16 * 1024);
    table_opts.set_cache_index_and_filter_blocks(true);
    table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
    // latest format versions https://github.com/facebook/rocksdb/blob/d1c510baecc1aef758f91f786c4fbee3bc847a63/include/rocksdb/table.h#L394
    table_opts.set_format_version(5);
    cf_opts.set_block_based_table_factory(&table_opts);

    cf_opts.create_missing_column_families(true);
    cf_opts.create_if_missing(true);

    cf_opts.set_comparator(&"key_comparator", key_comparator);
    let extractor = SliceTransform::create_fixed_prefix(20);
    cf_opts.set_prefix_extractor(extractor);
    // TODO use column families
    rocksdb::DB::open_cf_descriptors(&cf_opts, path, vec![])
        .map(RocksDB)
        .map_err(|e| Error::DBError {
            error: e.into_string(),
        })
}

fn key_comparator(a: &[u8], b: &[u8]) -> Ordering {
    let a_str = &String::from_utf8(a.to_vec()).unwrap();
    let b_str = &String::from_utf8(b.to_vec()).unwrap();

    let a_vec: Vec<&str> = a_str.split('/').collect();
    let b_vec: Vec<&str> = b_str.split('/').collect();

    let result_a_h = a_vec[0].parse::<u64>();
    let result_b_h = b_vec[0].parse::<u64>();
    match (result_a_h, result_b_h) {
        (Ok(a_h), Ok(b_h)) => {
            if a_h == b_h {
                a_vec[1..].cmp(&b_vec[1..])
            } else {
                a_h.cmp(&b_h)
            }
        }
        _ => {
            // the key doesn't include the height
            a_str.cmp(b_str)
        }
    }
}

impl DB for RocksDB {
    #[allow(dead_code)]
    fn flush(&self) -> Result<()> {
        let mut flush_opts = FlushOptions::default();
        flush_opts.set_wait(true);
        self.0.flush_opt(&flush_opts).map_err(|e| Error::DBError {
            error: e.into_string(),
        })
    }

    fn write_block(
        &mut self,
        tree: &MerkleTree,
        hash: &BlockHash,
        height: BlockHeight,
        subspaces: &HashMap<Key, Vec<u8>>,
    ) -> Result<()> {
        let mut batch = WriteBatch::default();

        let prefix_key = Key::from(height.to_db_key());
        // Merkle tree
        {
            let prefix_key = prefix_key
                .push(&"tree".to_owned())
                .map_err(Error::KeyError)?;
            // Merkle root hash
            {
                let key = prefix_key
                    .push(&"root".to_owned())
                    .map_err(Error::KeyError)?;
                let value = tree.0.root();
                batch.put(key.to_string(), value.as_slice());
            }
            // Tree's store
            {
                let key = prefix_key
                    .push(&"store".to_owned())
                    .map_err(Error::KeyError)?;
                let value = tree.0.store();
                batch.put(key.to_string(), value.encode());
            }
        }
        // Block hash
        {
            let key = prefix_key
                .push(&"hash".to_owned())
                .map_err(Error::KeyError)?;
            let value = hash;
            batch.put(key.to_string(), value.encode());
        }
        // SubSpace
        {
            let subspace_prefix = prefix_key
                .push(&"subspace".to_owned())
                .map_err(Error::KeyError)?;
            subspaces.iter().for_each(|(key, value)| {
                let key = subspace_prefix.join(key);
                batch.put(key.to_string(), value);
            });
        }
        let mut write_opts = WriteOptions::default();
        // TODO: disable WAL when we can shutdown with flush
        write_opts.set_sync(true);
        // write_opts.disable_wal(true);
        self.0
            .write_opt(batch, &write_opts)
            .map_err(|e| Error::DBError {
                error: e.into_string(),
            })?;
        // Block height - write after everything else is written
        // NOTE for async writes, we need to take care that all previous heights
        // are known when updating this
        self.0
            .put_opt("height", height.encode(), &write_opts)
            .map_err(|e| Error::DBError {
                error: e.into_string(),
            })
    }

    fn write_chain_id(&mut self, chain_id: &String) -> Result<()> {
        let mut write_opts = WriteOptions::default();
        // TODO: disable WAL when we can shutdown with flush
        write_opts.set_sync(true);
        // write_opts.disable_wal(true);
        self.0
            .put_opt("chain_id", chain_id.encode(), &write_opts)
            .map_err(|e| Error::DBError {
                error: e.into_string(),
            })
    }

    fn read(&self, height: BlockHeight, key: &Key) -> Result<Option<Vec<u8>>> {
        let key = Key::from(height.to_db_key())
            .push(&"subspace".to_owned())
            .map_err(Error::KeyError)?
            .join(key);
        match self.0.get(key.to_string()).map_err(|e| Error::DBError {
            error: e.into_string(),
        })? {
            Some(bytes) => Ok(Some(bytes)),
            None => Ok(None),
        }
    }

    fn read_last_block(&mut self) -> Result<Option<BlockState>> {
        let chain_id;
        let height;
        // Chain ID
        match self.0.get("chain_id").map_err(|e| Error::DBError {
            error: e.into_string(),
        })? {
            Some(bytes) => {
                chain_id = String::decode(bytes);
            }
            None => return Ok(None),
        }
        // Block height
        match self.0.get("height").map_err(|e| Error::DBError {
            error: e.into_string(),
        })? {
            Some(bytes) => {
                // TODO if there's an issue decoding this height, should we try
                // load its predecessor instead?
                height = BlockHeight::decode(bytes);
            }
            None => return Ok(None),
        }
        // Load data at the height
        let prefix = format!("{}/", height.to_string());
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(false);
        let next_height_prefix =
            format!("{}/", height.next_height().to_string());
        read_opts.set_iterate_upper_bound(next_height_prefix);
        let mut root = None;
        let mut store = None;
        let mut hash = None;
        let mut subspaces: HashMap<Key, Vec<u8>> = HashMap::new();
        for (key, bytes) in self.0.iterator_opt(
            IteratorMode::From(prefix.as_bytes(), Direction::Forward),
            read_opts,
        ) {
            let path = &String::from_utf8((*key).to_vec()).map_err(|e| {
                Error::Temporary {
                    error: format!(
                        "Cannot convert path from utf8 bytes to string: {}",
                        e
                    ),
                }
            })?;
            let mut segments: Vec<&str> = path.split('/').collect();
            match segments.get(1) {
                Some(prefix) => match *prefix {
                    "tree" => match segments.get(2) {
                        Some(smt) => match *smt {
                            "root" => root = Some(H256::decode(bytes.to_vec())),
                            "store" => {
                                store = Some(DefaultStore::<H256>::decode(
                                    bytes.to_vec(),
                                ))
                            }
                            _ => unknown_key_error(path)?,
                        },
                        None => unknown_key_error(path)?,
                    },
                    "hash" => hash = Some(BlockHash::decode(bytes.to_vec())),
                    "subspace" => {
                        let key = match segments.get(3) {
                            Some(seg) if *seg == "?" => {
                                // the path of a validity predicate should be
                                // height/subspace/address/?
                                let mut addr_str = (*segments
                                    .get(2)
                                    .expect("the address not found"))
                                .to_owned();
                                let _ = addr_str.remove(0);
                                let addr = Address::decode(&addr_str)
                                    .expect("cannot decode the address");
                                Key::validity_predicate(&addr)
                                    .expect("failed to make the VP key")
                            }
                            _ => Key::parse(segments.split_off(2).join("/"))
                                .map_err(|e| Error::Temporary {
                                    error: format!(
                                        "Cannot parse key segments {}: {}",
                                        path, e
                                    ),
                                })?,
                        };
                        subspaces.insert(key, bytes.to_vec());
                    }
                    _ => unknown_key_error(path)?,
                },
                None => unknown_key_error(path)?,
            }
        }
        match (root, store, hash) {
            (Some(root), Some(store), Some(hash)) => {
                let tree = MerkleTree(SparseMerkleTree::new(root, store));
                Ok(Some(BlockState {
                    chain_id,
                    tree,
                    hash,
                    height,
                    subspaces,
                }))
            }
            _ => Err(Error::Temporary {
                error: "Essential data couldn't be read from the DB"
                    .to_string(),
            }),
        }
    }
}

impl<'iter> DBIter<'iter> for RocksDB {
    type PrefixIter = PersistentPrefixIterator<'iter>;

    fn iter_prefix(
        &'iter self,
        height: BlockHeight,
        prefix: &Key,
    ) -> PersistentPrefixIterator<'iter> {
        let db_prefix = format!("{}/subspace/", height.to_string());
        let prefix = format!("{}{}", db_prefix, prefix.to_string());

        let mut read_opts = ReadOptions::default();
        // don't use the prefix bloom filter
        read_opts.set_total_order_seek(true);
        let mut upper_prefix = prefix.clone().into_bytes();
        if let Some(last) = upper_prefix.pop() {
            upper_prefix.push(last + 1);
        }
        read_opts.set_iterate_upper_bound(upper_prefix);

        let iter = self.0.iterator_opt(
            IteratorMode::From(prefix.as_bytes(), Direction::Forward),
            read_opts,
        );
        PersistentPrefixIterator::new(iter, db_prefix)
    }
}

pub type PersistentPrefixIterator<'a> = PrefixIterator<rocksdb::DBIterator<'a>>;

impl<'a> Iterator for PersistentPrefixIterator<'a> {
    type Item = (String, Vec<u8>, u64);

    /// Returns the next pair and the gas cost
    fn next(&mut self) -> Option<(String, Vec<u8>, u64)> {
        match self.iter.next() {
            Some((key, val)) => {
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

fn unknown_key_error(key: &str) -> Result<()> {
    Err(Error::UnknownKey {
        key: key.to_owned(),
    })
}
