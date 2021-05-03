//! DB mock for testing

use std::collections::btree_map::Range;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound::{Excluded, Included};

use anoma_shared::types::{BlockHash, BlockHeight, Key, KeySeg};
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use super::super::types::{KVBytes, MerkleTree, Value};
use super::{BlockState, Error, Result, DB};
use crate::shell::storage::types::PrefixIterator;
use crate::shell::storage::DBIter;

#[derive(Debug)]
pub struct MockDB(BTreeMap<String, Vec<u8>>);

impl Default for MockDB {
    fn default() -> MockDB {
        MockDB(BTreeMap::new())
    }
}

impl DB for MockDB {
    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn write_block(
        &mut self,
        tree: &MerkleTree,
        hash: &BlockHash,
        height: BlockHeight,
        subspaces: &HashMap<Key, Vec<u8>>,
    ) -> Result<()> {
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
                self.0.insert(key.to_string(), value.encode());
            }
            // Tree's store
            {
                let key = prefix_key
                    .push(&"store".to_owned())
                    .map_err(Error::KeyError)?;
                let value = tree.0.store();
                self.0.insert(key.to_string(), value.encode());
            }
        }
        // Block hash
        {
            let key = prefix_key
                .push(&"hash".to_owned())
                .map_err(Error::KeyError)?;
            let value = hash;
            self.0.insert(key.to_string(), value.encode());
        }
        // SubSpace
        {
            let subspace_prefix = prefix_key
                .push(&"subspace".to_owned())
                .map_err(Error::KeyError)?;
            subspaces.iter().for_each(|(key, value)| {
                let key = subspace_prefix.join(key);
                self.0.insert(key.to_string(), value.clone());
            });
        }
        self.0.insert("height".to_owned(), height.encode());
        Ok(())
    }

    fn write_chain_id(&mut self, chain_id: &String) -> Result<()> {
        self.0.insert("chain_id".to_owned(), chain_id.encode());
        Ok(())
    }

    fn read(&self, height: BlockHeight, key: &Key) -> Result<Option<Vec<u8>>> {
        let key = Key::from(height.to_db_key())
            .push(&"subspace".to_owned())
            .map_err(Error::KeyError)?
            .join(key);
        match self.0.get(&key.to_string()) {
            Some(v) => Ok(Some(v.clone())),
            None => Ok(None),
        }
    }

    fn read_last_block(&mut self) -> Result<Option<BlockState>> {
        let chain_id;
        let height;
        // Chain ID
        match self.0.get("chain_id") {
            Some(bytes) => {
                chain_id = String::decode(bytes.clone());
            }
            None => return Ok(None),
        }
        // Block height
        match self.0.get("height") {
            Some(bytes) => {
                height = BlockHeight::decode(bytes.clone());
            }
            None => return Ok(None),
        }
        // Load data at the height
        let prefix = format!("{}/", height.to_string());
        let upper_prefix = format!("{}/", height.next_height().to_string());
        let mut root = None;
        let mut store = None;
        let mut hash = None;
        let mut subspaces: HashMap<Key, Vec<u8>> = HashMap::new();
        for (path, bytes) in
            self.0.range((Included(prefix), Excluded(upper_prefix)))
        {
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
                        let key = Key::parse(segments.split_off(2).join("/"))
                            .map_err(|e| Error::Temporary {
                            error: format!(
                                "Cannot parse key segments {}: {}",
                                path, e
                            ),
                        })?;
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

impl<'iter> DBIter<'iter> for MockDB {
    type PrefixIter = MockPrefixIterator<'iter>;

    fn iter_prefix(
        &'iter self,
        height: BlockHeight,
        prefix: &Key,
    ) -> MockPrefixIterator<'iter> {
        let db_prefix = format!("{}/subspace/", height.to_string());
        let prefix = format!("{}{}", db_prefix, prefix.to_string());

        let mut upper_prefix = prefix.clone().into_bytes();
        if let Some(last) = upper_prefix.pop() {
            upper_prefix.push(last + 1);
        }
        let upper =
            String::from_utf8(upper_prefix).expect("failed convert to string");
        let iter = self.0.range((Included(prefix), Excluded(upper)));
        MockPrefixIterator::new(MockIterator { iter }, db_prefix)
    }
}

pub struct MockIterator<'a> {
    pub iter: Range<'a, String, Vec<u8>>,
}

pub type MockPrefixIterator<'a> = PrefixIterator<MockIterator<'a>>;

impl<'a> Iterator for MockIterator<'a> {
    type Item = KVBytes;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(key, val)| {
            (Box::from(key.as_bytes()), Box::from(val.as_slice()))
        })
    }
}

impl<'a> Iterator for PrefixIterator<MockIterator<'a>> {
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
