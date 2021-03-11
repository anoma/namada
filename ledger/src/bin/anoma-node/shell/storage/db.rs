//! The persistent storage, currently in RocksDB.
//!
//! The current storage tree is:
//! - `chain_id`
//! - `height`: the last committed block height
//! - `h`: for each block at height `h`:
//!   - `tree`: merkle tree
//!     - `root`: root hash
//!     - `store`: the tree's store
//!   - `hash`: block hash
//!   - `balance/address`: balance for each account `address`

use super::{
    types::{BlockHeight, KeySeg},
    Address, Balance, BlockHash, MerkleTree,
};
use crate::shell::storage::types::Value;
use rocksdb::{
    BlockBasedOptions, FlushOptions, Options, WriteBatch, WriteOptions,
};
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256};
use std::{collections::HashMap, path::Path};

// TODO the DB schema will probably need some kind of versioning

#[derive(Debug)]
pub struct DB(rocksdb::DB);

#[derive(Debug, Clone)]
pub enum Error {
    // TODO strong types
    Stringly(String),
    RocksDBError(rocksdb::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn open<P: AsRef<Path>>(path: P) -> Result<DB> {
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

    // TODO use column families
    rocksdb::DB::open_cf_descriptors(&cf_opts, path, vec![])
        .map(DB)
        .map_err(Error::RocksDBError)
}

impl DB {
    pub fn flush(&self) -> Result<()> {
        let mut flush_opts = FlushOptions::default();
        flush_opts.set_wait(true);
        self.0
            .flush_opt(&flush_opts)
            .map_err(|e| Error::RocksDBError(e))
    }

    pub fn write_block(
        &mut self,
        tree: &MerkleTree,
        hash: &BlockHash,
        height: &BlockHeight,
        balances: &HashMap<Address, Balance>,
    ) -> Result<()> {
        let mut batch = WriteBatch::default();

        let prefix = height.to_key_seg();
        // Merkle tree
        {
            let prefix = format!("{}/tree", prefix);
            // Merkle root hash
            {
                let key = format!("{}/root", prefix);
                let value = tree.0.root();
                batch.put(key, value.as_slice());
            }
            // Tree's store
            {
                let key = format!("{}/store", prefix);
                let value = tree.0.store();
                batch.put(key, value.encode());
            }
        }
        // Block hash
        {
            let key = format!("{}/hash", prefix);
            let value = hash;
            batch.put(key, value.encode());
        }
        // Balances
        {
            balances.iter().for_each(|(addr, balance)| {
                let key = format!("{}/balance/{}", prefix, addr.to_key_seg());
                batch.put(key, balance.encode());
            });
        }
        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(true);
        self.0
            .write_opt(batch, &write_opts)
            .map_err(|e| Error::RocksDBError(e))?;
        // Block height - write after everything else is written
        // NOTE for async writes, we need to take care that all previous heights
        // are known when updating this
        self.0
            .put_opt("height", height.encode(), &write_opts)
            .map_err(|e| Error::RocksDBError(e))
    }

    pub fn write_chain_id(&mut self, chain_id: &String) -> Result<()> {
        let mut write_opts = WriteOptions::default();
        write_opts.disable_wal(true);
        self.0
            .put_opt("chain_id", chain_id.encode(), &write_opts)
            .map_err(|e| Error::RocksDBError(e))
    }

    pub fn read_last_block(
        &mut self,
    ) -> Result<
        Option<(
            String,
            MerkleTree,
            BlockHash,
            BlockHeight,
            HashMap<Address, Balance>,
        )>,
    > {
        let chain_id;
        let tree;
        let hash;
        let height;
        let mut balances: HashMap<Address, Balance> = HashMap::new();

        let prefix;
        // Chain ID
        match self.0.get("chain_id").map_err(Error::RocksDBError)? {
            Some(bytes) => {
                chain_id = String::decode(bytes);
            }
            None => return Ok(None),
        }
        // Block height
        match self.0.get("height").map_err(Error::RocksDBError)? {
            Some(bytes) => {
                // TODO if there's an issue decoding this height, should we try
                // load its predecessor instead?
                height = BlockHeight::decode(bytes);
                prefix = height.to_key_seg();
            }
            None => return Ok(None),
        }
        // Merkle tree
        {
            let tree_prefix = format!("{}/tree", prefix);
            let root;
            // Merkle root hash
            {
                let key = format!("{}/root", tree_prefix);
                match self.0.get(&key).map_err(Error::RocksDBError)? {
                    Some(raw_root) => {
                        root = H256::decode(raw_root);
                    }
                    None => {
                        return Err(Error::Stringly(format!(
                            "Cannot read value for key {}",
                            key
                        )));
                    }
                }
            }
            // Tree's store
            {
                let key = format!("{}/store", tree_prefix);
                let bytes =
                    self.0.get(key).map_err(Error::RocksDBError)?.unwrap();
                let store = DefaultStore::<H256>::decode(bytes);
                tree = MerkleTree(SparseMerkleTree::new(root, store))
            }
        }
        // Block hash
        {
            let key = format!("{}/hash", prefix);
            let bytes = self.0.get(key).map_err(Error::RocksDBError)?.unwrap();
            hash = BlockHash::decode(bytes);
        }
        // Balances
        {
            let prefix = format!("{}/balance/", prefix);
            for (key, bytes) in self.0.prefix_iterator(&prefix) {
                // decode the key and strip the prefix
                let path =
                    &String::from_utf8((*key).to_vec()).map_err(|e| {
                        Error::Stringly(format!(
                            "error decoding an address: {}",
                            e
                        ))
                    })?;
                match path.strip_prefix(&prefix) {
                    Some(segment) => {
                        let addr = Address::from_key_seg(&segment.to_owned())
                            .map_err(|e| {
                            Error::Stringly(format!(
                                "error decoding an address: {}",
                                e
                            ))
                        })?;
                        let balance = Balance::decode(bytes.to_vec());
                        balances.insert(addr, balance);
                    }
                    None => {
                        // TODO the prefix_iterator is
                        // going into non-matching
                        // prefixes. We either need to
                        // use a fully numerical paths
                        // or a custom comparator
                        log::debug!(
                            "Cannot find prefix \"{}\" in \"{}\"",
                            prefix,
                            path
                        );
                    }
                }
            }
        }
        Ok(Some((chain_id, tree, hash, height, balances)))
    }
}
