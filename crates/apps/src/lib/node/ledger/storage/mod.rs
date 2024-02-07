//! The storage module handles both the current state in-memory and the stored
//! state in DB.

mod rocksdb;

use std::fmt;

use arse_merkle_tree::blake2b::Blake2bHasher;
use arse_merkle_tree::traits::Hasher;
use arse_merkle_tree::H256;
use blake2b_rs::{Blake2b, Blake2bBuilder};
use namada::state::{State, StorageHasher};

#[derive(Default)]
pub struct PersistentStorageHasher(Blake2bHasher);

pub type PersistentDB = rocksdb::RocksDB;

pub type PersistentStorage = State<PersistentDB, PersistentStorageHasher>;

impl Hasher for PersistentStorageHasher {
    fn write_bytes(&mut self, h: &[u8]) {
        self.0.write_bytes(h)
    }

    fn finish(self) -> H256 {
        self.0.finish()
    }
}

impl StorageHasher for PersistentStorageHasher {
    fn hash(value: impl AsRef<[u8]>) -> H256 {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(value.as_ref());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

impl fmt::Debug for PersistentStorageHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PersistentStorageHasher")
    }
}

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"namada storage").build()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use borsh::BorshDeserialize;
    use itertools::Itertools;
    use namada::eth_bridge::storage::proof::BridgePoolRootProof;
    use namada::ledger::eth_bridge::storage::bridge_pool;
    use namada::ledger::gas::STORAGE_ACCESS_GAS_PER_BYTE;
    use namada::ledger::ibc::storage::ibc_key;
    use namada::ledger::parameters::{EpochDuration, Parameters};
    use namada::state::write_log::WriteLog;
    use namada::state::{
        self, StorageRead, StorageWrite, StoreType, WlStorage, DB,
    };
    use namada::token::conversion::update_allowed_conversions;
    use namada::types::chain::ChainId;
    use namada::types::ethereum_events::Uint;
    use namada::types::hash::Hash;
    use namada::types::keccak::KeccakHash;
    use namada::types::storage::{BlockHash, BlockHeight, Key};
    use namada::types::time::DurationSecs;
    use namada::types::{address, storage};
    use namada::{parameters, types};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    use tempfile::TempDir;

    use super::*;
    use crate::node::ledger::shell::is_merklized_storage_key;

    #[test]
    fn test_crud_value() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );
        let key = Key::parse("key").expect("cannot parse the key string");
        let value: u64 = 1;
        let value_bytes = types::encode(&value);
        let value_bytes_len = value_bytes.len();

        // before insertion
        let (result, gas) = storage.has_key(&key).expect("has_key failed");
        assert!(!result);
        assert_eq!(gas, key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE);
        let (result, gas) = storage.read(&key).expect("read failed");
        assert_eq!(result, None);
        assert_eq!(gas, key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE);

        // insert
        storage.write(&key, value_bytes).expect("write failed");

        // read
        let (result, gas) = storage.has_key(&key).expect("has_key failed");
        assert!(result);
        assert_eq!(gas, key.len() as u64 * STORAGE_ACCESS_GAS_PER_BYTE);
        let (result, gas) = storage.read(&key).expect("read failed");
        let read_value: u64 =
            types::decode(result.expect("value doesn't exist"))
                .expect("decoding failed");
        assert_eq!(read_value, value);
        assert_eq!(
            gas,
            (key.len() as u64 + value_bytes_len as u64)
                * STORAGE_ACCESS_GAS_PER_BYTE
        );

        // delete
        storage.delete(&key).expect("delete failed");

        // read again
        let (result, _) = storage.has_key(&key).expect("has_key failed");
        assert!(!result);
        let (result, _) = storage.read(&key).expect("read failed");
        assert_eq!(result, None);
    }

    #[test]
    fn test_commit_block() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );
        storage
            .begin_block(BlockHash::default(), BlockHeight(100))
            .expect("begin_block failed");
        let key = Key::parse("key").expect("cannot parse the key string");
        let value: u64 = 1;
        let value_bytes = types::encode(&value);
        let mut wl_storage = WlStorage::new(WriteLog::default(), storage);
        // initialize parameter storage
        let params = Parameters {
            max_tx_bytes: 1024 * 1024,
            epoch_duration: EpochDuration {
                min_num_of_blocks: 1,
                min_duration: DurationSecs(3600),
            },
            max_expected_time_per_block: DurationSecs(3600),
            max_proposal_bytes: Default::default(),
            max_block_gas: 100,
            vp_allowlist: vec![],
            tx_allowlist: vec![],
            implicit_vp_code_hash: Default::default(),
            epochs_per_year: 365,
            max_signatures_per_transaction: 10,
            fee_unshielding_gas_limit: 0,
            fee_unshielding_descriptions_limit: 0,
            minimum_gas_price: Default::default(),
        };
        parameters::init_storage(&params, &mut wl_storage)
            .expect("Test failed");
        // insert and commit
        wl_storage
            .storage
            .write(&key, value_bytes.clone())
            .expect("write failed");
        wl_storage.storage.block.epoch = wl_storage.storage.block.epoch.next();
        wl_storage
            .storage
            .block
            .pred_epochs
            .new_epoch(BlockHeight(100));
        // make wl_storage to update conversion for a new epoch

        update_allowed_conversions(&mut wl_storage)
            .expect("update conversions failed");
        wl_storage.commit_block().expect("commit failed");

        // save the last state and the storage
        let root = wl_storage.storage.merkle_root().0;
        let hash = wl_storage.storage.get_block_hash().0;
        let address_gen = wl_storage.storage.address_gen.clone();
        drop(wl_storage);

        // load the last state
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );
        storage
            .load_last_state()
            .expect("loading the last state failed");
        let (loaded_root, height) =
            storage.get_state().expect("no block exists");
        assert_eq!(loaded_root.0, root);
        assert_eq!(height, 100);
        assert_eq!(storage.get_block_hash().0, hash);
        assert_eq!(storage.address_gen, address_gen);
        let (val, _) = storage.read(&key).expect("read failed");
        assert_eq!(val.expect("no value"), value_bytes);
    }

    #[test]
    fn test_iter() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );
        storage
            .begin_block(BlockHash::default(), BlockHeight(100))
            .expect("begin_block failed");

        let mut expected = Vec::new();
        let prefix = Key::parse("prefix").expect("cannot parse the key string");
        for i in (0..9).rev() {
            let key = prefix
                .push(&format!("{}", i))
                .expect("cannot push the key segment");
            let value_bytes = types::encode(&(i as u64));
            // insert
            storage
                .write(&key, value_bytes.clone())
                .expect("write failed");
            expected.push((key.to_string(), value_bytes));
        }
        let batch = PersistentStorage::batch();
        storage.commit_block(batch).expect("commit failed");

        let (iter, gas) = storage.iter_prefix(&prefix);
        assert_eq!(gas, (prefix.len() as u64) * STORAGE_ACCESS_GAS_PER_BYTE);
        for (k, v, gas) in iter {
            match expected.pop() {
                Some((expected_key, expected_val)) => {
                    assert_eq!(k, expected_key);
                    assert_eq!(v, expected_val);
                    let expected_gas = expected_key.len() + expected_val.len();
                    assert_eq!(gas, expected_gas as u64);
                }
                None => panic!("read a pair though no expected pair"),
            }
        }
    }

    #[test]
    fn test_validity_predicate() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );
        storage
            .begin_block(BlockHash::default(), BlockHeight(100))
            .expect("begin_block failed");

        let addr = storage.address_gen.generate_address("test".as_bytes());
        let key = Key::validity_predicate(&addr);

        // not exist
        let (vp, gas) =
            storage.validity_predicate(&addr).expect("VP load failed");
        assert_eq!(vp, None);
        assert_eq!(gas, (key.len() as u64) * STORAGE_ACCESS_GAS_PER_BYTE);

        // insert
        let vp1 = Hash::sha256("vp1".as_bytes());
        storage.write(&key, vp1).expect("write failed");

        // check
        let (vp_code_hash, gas) =
            storage.validity_predicate(&addr).expect("VP load failed");
        assert_eq!(vp_code_hash.expect("no VP"), vp1);
        assert_eq!(
            gas,
            ((key.len() + vp1.len()) as u64) * STORAGE_ACCESS_GAS_PER_BYTE
        );
    }

    proptest! {
        #![proptest_config(Config {
            cases: 5,
            .. Config::default()
        })]
        #[test]
        fn test_read_with_height(blocks_write_value in vec(any::<bool>(), 20)) {
            test_read_with_height_aux(blocks_write_value).unwrap()
        }

        #[test]
        fn test_get_merkle_tree(blocks_write_type in vec(0..5_u64, 50)) {
            test_get_merkle_tree_aux(blocks_write_type).unwrap()
        }
    }

    /// Test reads at arbitrary block heights.
    ///
    /// We generate `blocks_write_value` with random bools as the input to this
    /// function, then:
    ///
    /// 1. For each `blocks_write_value`, write the current block height if true
    ///    or delete otherwise.
    /// 2. We try to read from these heights to check that we get back expected
    ///    value if was written at that block height or `None` if it was
    ///    deleted.
    /// 3. We try to read past the last height and we expect the last written
    ///    value, if any.
    fn test_read_with_height_aux(
        blocks_write_value: Vec<bool>,
    ) -> namada::state::Result<()> {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );

        // 1. For each `blocks_write_value`, write the current block height if
        // true or delete otherwise.
        // We `.enumerate()` height (starting from `0`)
        let blocks_write_value = blocks_write_value
            .into_iter()
            .enumerate()
            .map(|(height, write_value)| {
                println!(
                    "At height {height} will {}",
                    if write_value { "write" } else { "delete" }
                );
                // start from height 1 - 0 is sentinel
                (BlockHeight::from(height as u64 + 1), write_value)
            });

        let key = Key::parse("key").expect("cannot parse the key string");
        for (height, write_value) in blocks_write_value.clone() {
            let hash = BlockHash::default();
            storage.begin_block(hash, height)?;
            assert_eq!(
                height, storage.block.height,
                "sanity check - height is as expected"
            );

            if write_value {
                let value_bytes = types::encode(&storage.block.height);
                storage.write(&key, value_bytes)?;
            } else {
                storage.delete(&key)?;
            }
            let batch = PersistentStorage::batch();
            storage.commit_block(batch)?;
        }

        // 2. We try to read from these heights to check that we get back
        // expected value if was written at that block height or
        // `None` if it was deleted.
        for (height, write_value) in blocks_write_value.clone() {
            let (value_bytes, _gas) = storage.read_with_height(&key, height)?;
            if write_value {
                let value_bytes = value_bytes.unwrap_or_else(|| {
                    panic!("Couldn't read from height {height}")
                });
                let value: BlockHeight = types::decode(value_bytes).unwrap();
                assert_eq!(value, height);
            } else if value_bytes.is_some() {
                let value: BlockHeight =
                    types::decode(value_bytes.unwrap()).unwrap();
                panic!("Expected no value at height {height}, got {}", value,);
            }
        }

        // 3. We try to read past the last height and we expect the last written
        // value, if any.

        // If height is >= storage.last_height, it should read the latest state.
        let is_last_write = blocks_write_value.last().unwrap().1;

        // The upper bound is arbitrary.
        for height in storage.get_last_block_height().0
            ..storage.get_last_block_height().0 + 10
        {
            let height = BlockHeight::from(height);
            let (value_bytes, _gas) = storage.read_with_height(&key, height)?;
            if is_last_write {
                let value_bytes =
                    value_bytes.expect("Should have been written");
                let value: BlockHeight = types::decode(value_bytes).unwrap();
                assert_eq!(value, storage.get_last_block_height());
            } else if value_bytes.is_some() {
                let value: BlockHeight =
                    types::decode(value_bytes.unwrap()).unwrap();
                panic!("Expected no value at height {height}, got {}", value,);
            }
        }

        Ok(())
    }

    /// Test the restore of the merkle tree
    fn test_get_merkle_tree_aux(
        blocks_write_type: Vec<u64>,
    ) -> namada::state::Result<()> {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );

        let num_keys = 5;
        let blocks_write_type = blocks_write_type.into_iter().enumerate().map(
            |(index, write_type)| {
                // try to update some keys at each height
                let height = BlockHeight::from(index as u64 / num_keys + 1);
                let key =
                    ibc_key(format!("key{}", index as u64 % num_keys)).unwrap();
                (height, key, write_type)
            },
        );

        let mut roots = HashMap::new();

        // write values at Height 0 like init_storage
        for i in 0..num_keys {
            let key = ibc_key(format!("key{}", i)).unwrap();
            let value_bytes = types::encode(&storage.block.height);
            storage.write(&key, value_bytes)?;
        }
        let key = bridge_pool::get_signed_root_key();
        let root_proof =
            BridgePoolRootProof::new((KeccakHash::default(), Uint::default()));
        let bytes = types::encode(&root_proof);
        storage.write(&key, bytes)?;

        // Update and commit
        let hash = BlockHash::default();
        let height = BlockHeight(1);
        storage.begin_block(hash, height)?;
        // Epoch 0
        storage.block.pred_epochs.new_epoch(height);
        let mut batch = PersistentStorage::batch();
        for (height, key, write_type) in blocks_write_type.clone() {
            if height != storage.block.height {
                // to check the root later
                roots.insert(storage.block.height, storage.merkle_root());
                if storage.block.height.0 % 5 == 0 {
                    // new epoch every 5 heights
                    storage.block.epoch = storage.block.epoch.next();
                    storage.block.pred_epochs.new_epoch(storage.block.height);
                }
                storage.commit_block(batch)?;
                let hash = BlockHash::default();
                storage
                    .begin_block(hash, storage.block.height.next_height())?;
                batch = PersistentStorage::batch();
            }
            match write_type {
                0 => {
                    // no update
                }
                1 => {
                    storage.delete(&key)?;
                }
                2 => {
                    let value_bytes = types::encode(&storage.block.height);
                    storage.write(&key, value_bytes)?;
                }
                3 => {
                    storage.batch_delete_subspace_val(&mut batch, &key)?;
                }
                _ => {
                    let value_bytes = types::encode(&storage.block.height);
                    storage.batch_write_subspace_val(
                        &mut batch,
                        &key,
                        value_bytes,
                    )?;
                }
            }
        }
        roots.insert(storage.block.height, storage.merkle_root());
        storage.commit_block(batch)?;

        let mut current_state = HashMap::new();
        for i in 0..num_keys {
            let key = ibc_key(format!("key{}", i)).unwrap();
            current_state.insert(key, true);
        }
        // Check a Merkle tree
        for (height, key, write_type) in blocks_write_type {
            let tree = storage.get_merkle_tree(height, Some(StoreType::Ibc))?;
            assert_eq!(tree.root().0, roots.get(&height).unwrap().0);
            match write_type {
                0 => {
                    if *current_state.get(&key).unwrap() {
                        assert!(tree.has_key(&key)?);
                    } else {
                        assert!(!tree.has_key(&key)?);
                    }
                }
                1 | 3 => {
                    assert!(!tree.has_key(&key)?);
                    current_state.insert(key, false);
                }
                _ => {
                    assert!(tree.has_key(&key)?);
                    current_state.insert(key, true);
                }
            }
        }

        Ok(())
    }

    /// Test the restore of the merkle tree
    #[test]
    fn test_prune_merkle_tree_stores() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let mut storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            Some(5),
            is_merklized_storage_key,
        );
        let new_epoch_start = BlockHeight(1);
        let signed_root_key = bridge_pool::get_signed_root_key();
        // the first nonce isn't written for a test skipping pruning
        let nonce = Uint::default();

        storage
            .begin_block(BlockHash::default(), new_epoch_start)
            .expect("begin_block failed");

        let key = ibc_key("key").unwrap();
        let value: u64 = 1;
        storage
            .write(&key, types::encode(&value))
            .expect("write failed");

        storage.block.pred_epochs.new_epoch(new_epoch_start);
        let batch = PersistentStorage::batch();
        storage.commit_block(batch).expect("commit failed");

        let new_epoch_start = BlockHeight(6);
        storage
            .begin_block(BlockHash::default(), new_epoch_start)
            .expect("begin_block failed");

        let key = ibc_key("key2").unwrap();
        let value: u64 = 2;
        storage
            .write(&key, types::encode(&value))
            .expect("write failed");

        // the second nonce isn't written for a test skipping pruning
        let nonce = nonce + 1;

        storage.block.epoch = storage.block.epoch.next();
        storage.block.pred_epochs.new_epoch(new_epoch_start);
        let batch = PersistentStorage::batch();
        storage.commit_block(batch).expect("commit failed");

        let result = storage.get_merkle_tree(1.into(), Some(StoreType::Ibc));
        assert!(result.is_ok(), "The tree at Height 1 should be restored");

        let new_epoch_start = BlockHeight(11);
        storage
            .begin_block(BlockHash::default(), new_epoch_start)
            .expect("begin_block failed");

        let nonce = nonce + 1;
        let root_proof =
            BridgePoolRootProof::new((KeccakHash::default(), nonce));
        let bytes = types::encode(&root_proof);
        storage.write(&signed_root_key, bytes).unwrap();

        storage.block.epoch = storage.block.epoch.next();
        storage.block.pred_epochs.new_epoch(new_epoch_start);
        let batch = PersistentStorage::batch();
        storage.commit_block(batch).expect("commit failed");

        let result = storage.get_merkle_tree(1.into(), Some(StoreType::Ibc));
        assert!(result.is_err(), "The tree at Height 1 should be pruned");
        let result = storage.get_merkle_tree(5.into(), Some(StoreType::Ibc));
        assert!(
            result.is_err(),
            "The tree at Height 5 shouldn't be able to be restored"
        );
        let result = storage.get_merkle_tree(6.into(), Some(StoreType::Ibc));
        assert!(result.is_ok(), "The ibc tree should be restored");
        let result =
            storage.get_merkle_tree(6.into(), Some(StoreType::BridgePool));
        assert!(result.is_ok(), "The bridge pool tree should be restored");

        storage
            .begin_block(BlockHash::default(), BlockHeight(12))
            .expect("begin_block failed");

        let nonce = nonce + 1;
        let root_proof =
            BridgePoolRootProof::new((KeccakHash::default(), nonce));
        let bytes = types::encode(&root_proof);
        storage.write(&signed_root_key, bytes).unwrap();
        storage.block.epoch = storage.block.epoch.next();
        storage.block.pred_epochs.new_epoch(BlockHeight(12));
        let batch = PersistentStorage::batch();
        storage.commit_block(batch).expect("commit failed");

        // ibc tree should be able to be restored
        let result = storage.get_merkle_tree(6.into(), Some(StoreType::Ibc));
        assert!(result.is_ok(), "The ibc tree should be restored");
        // bridge pool tree should be pruned because of the nonce
        let result =
            storage.get_merkle_tree(6.into(), Some(StoreType::BridgePool));
        assert!(result.is_err(), "The bridge pool tree should be pruned");
    }

    /// Test the prefix iterator with RocksDB.
    #[test]
    fn test_persistent_storage_prefix_iter() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            is_merklized_storage_key,
        );
        let mut storage = WlStorage {
            storage,
            write_log: Default::default(),
        };

        let prefix = storage::Key::parse("prefix").unwrap();
        let mismatched_prefix = storage::Key::parse("different").unwrap();
        // We'll write sub-key in some random order to check prefix iter's order
        let sub_keys = [2_i32, -1, 260, -2, 5, 0];

        for i in sub_keys.iter() {
            let key = prefix.push(i).unwrap();
            storage.write(&key, i).unwrap();

            let key = mismatched_prefix.push(i).unwrap();
            storage.write(&key, i / 2).unwrap();
        }

        // Then try to iterate over their prefix
        let iter = state::iter_prefix(&storage, &prefix)
            .unwrap()
            .map(Result::unwrap);

        // The order has to be sorted by sub-key value
        let expected = sub_keys
            .iter()
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter, expected.clone());

        // Commit genesis state
        storage.commit_block().unwrap();

        // Again, try to iterate over their prefix
        let iter = state::iter_prefix(&storage, &prefix)
            .unwrap()
            .map(Result::unwrap);
        itertools::assert_equal(iter, expected);

        let more_sub_keys = [1_i32, i32::MIN, -10, 123, i32::MAX, 10];
        debug_assert!(
            !more_sub_keys.iter().any(|x| sub_keys.contains(x)),
            "assuming no repetition"
        );
        for i in more_sub_keys.iter() {
            let key = prefix.push(i).unwrap();
            storage.write(&key, i).unwrap();

            let key = mismatched_prefix.push(i).unwrap();
            storage.write(&key, i / 2).unwrap();
        }

        let iter = state::iter_prefix(&storage, &prefix)
            .unwrap()
            .map(Result::unwrap);

        // The order has to be sorted by sub-key value
        let merged = itertools::merge(sub_keys.iter(), more_sub_keys.iter());
        let expected = merged
            .clone()
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter, expected);

        // Delete some keys
        let delete_keys = [2, 0, -10, 123];
        for i in delete_keys.iter() {
            let key = prefix.push(i).unwrap();
            storage.delete(&key).unwrap()
        }

        // Check that iter_prefix doesn't return deleted keys anymore
        let iter = state::iter_prefix(&storage, &prefix)
            .unwrap()
            .map(Result::unwrap);
        let expected = merged
            .filter(|x| !delete_keys.contains(x))
            .sorted()
            .map(|i| (prefix.push(i).unwrap(), *i));
        itertools::assert_equal(iter, expected.clone());

        // Commit genesis state
        storage.commit_block().unwrap();

        // And check again
        let iter = state::iter_prefix(&storage, &prefix)
            .unwrap()
            .map(Result::unwrap);
        itertools::assert_equal(iter, expected);
    }

    fn test_key_1() -> Key {
        Key::parse("testing1").unwrap()
    }

    fn test_key_2() -> Key {
        Key::parse("testing2").unwrap()
    }

    fn merkle_tree_key_filter(key: &Key) -> bool {
        key == &test_key_1()
    }

    #[test]
    fn test_persistent_storage_writing_without_merklizing_or_diffs() {
        let db_path =
            TempDir::new().expect("Unable to create a temporary DB directory");
        let storage = PersistentStorage::open(
            db_path.path(),
            ChainId::default(),
            address::nam(),
            None,
            None,
            merkle_tree_key_filter,
        );
        let mut wls = WlStorage {
            storage,
            write_log: Default::default(),
        };
        // Start the first block
        let first_height = BlockHeight::first();
        wls.storage.block.height = first_height;

        let key1 = test_key_1();
        let val1 = 1u64;
        let key2 = test_key_2();
        let val2 = 2u64;

        // Standard write of key-val-1
        wls.write(&key1, val1).unwrap();

        // Read from WlStorage should return val1
        let res = wls.read::<u64>(&key1).unwrap().unwrap();
        assert_eq!(res, val1);

        // Read from Storage shouldn't return val1 because the block hasn't been
        // committed
        let (res, _) = wls.storage.read(&key1).unwrap();
        assert!(res.is_none());

        // Write key-val-2 without merklizing or diffs
        wls.write(&key2, val2).unwrap();

        // Read from WlStorage should return val2
        let res = wls.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res, val2);

        // Commit block and storage changes
        wls.commit_block().unwrap();
        wls.storage.block.height = wls.storage.block.height.next_height();
        let second_height = wls.storage.block.height;

        // Read key1 from Storage should return val1
        let (res1, _) = wls.storage.read(&key1).unwrap();
        let res1 = u64::try_from_slice(&res1.unwrap()).unwrap();
        assert_eq!(res1, val1);

        // Check merkle tree inclusion of key-val-1 explicitly
        let is_merklized1 = wls.storage.block.tree.has_key(&key1).unwrap();
        assert!(is_merklized1);

        // Key2 should be in storage. Confirm by reading from
        // WlStorage and also by reading Storage subspace directly
        let res2 = wls.read::<u64>(&key2).unwrap().unwrap();
        assert_eq!(res2, val2);
        let res2 = wls.storage.db.read_subspace_val(&key2).unwrap().unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Check explicitly that key-val-2 is not in merkle tree
        let is_merklized2 = wls.storage.block.tree.has_key(&key2).unwrap();
        assert!(!is_merklized2);

        // Check that the proper diffs exist for key-val-1
        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, first_height, true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, first_height, false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        // Check that there are diffs for key-val-2 in block 0, since all keys
        // need to have diffs for at least 1 block for rollback purposes
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, first_height, true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, first_height, false)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);

        // Delete the data then commit the block
        wls.delete(&key1).unwrap();
        wls.delete(&key2).unwrap();
        wls.commit_block().unwrap();
        wls.storage.block.height = wls.storage.block.height.next_height();

        // Check the key-vals are removed from the storage subspace
        let res1 = wls.read::<u64>(&key1).unwrap();
        let res2 = wls.read::<u64>(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());
        let res1 = wls.storage.db.read_subspace_val(&key1).unwrap();
        let res2 = wls.storage.db.read_subspace_val(&key2).unwrap();
        assert!(res1.is_none() && res2.is_none());

        // Check that the key-vals don't exist in the merkle tree anymore
        let is_merklized1 = wls.storage.block.tree.has_key(&key1).unwrap();
        let is_merklized2 = wls.storage.block.tree.has_key(&key2).unwrap();
        assert!(!is_merklized1 && !is_merklized2);

        // Check that key-val-1 diffs are properly updated for blocks 0 and 1
        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, first_height, true)
            .unwrap();
        assert!(res1.is_none());

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, first_height, false)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, second_height, true)
            .unwrap()
            .unwrap();
        let res1 = u64::try_from_slice(&res1).unwrap();
        assert_eq!(res1, val1);

        let res1 = wls
            .storage
            .db
            .read_diffs_val(&key1, second_height, false)
            .unwrap();
        assert!(res1.is_none());

        // Check that key-val-2 diffs don't exist for block 0 anymore
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, first_height, true)
            .unwrap();
        assert!(res2.is_none());
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, first_height, false)
            .unwrap();
        assert!(res2.is_none());

        // Check that the block 1 diffs for key-val-2 include an "old" value of
        // val2 and no "new" value
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, second_height, true)
            .unwrap()
            .unwrap();
        let res2 = u64::try_from_slice(&res2).unwrap();
        assert_eq!(res2, val2);
        let res2 = wls
            .storage
            .db
            .read_diffs_val(&key2, second_height, false)
            .unwrap();
        assert!(res2.is_none());
    }
}
