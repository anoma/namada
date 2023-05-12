//! Storage with write log.

use std::iter::Peekable;

use super::EPOCH_SWITCH_BLOCKS_DELAY;
use crate::ledger::parameters::EpochDuration;
use crate::ledger::storage::write_log::{self, WriteLog};
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api::{ResultExt, StorageRead, StorageWrite};
use crate::ledger::{gas, parameters, storage_api};
use crate::types::address::Address;
use crate::types::storage::{self, BlockHeight};
use crate::types::time::DateTimeUtc;

/// Storage with write log that allows to implement prefix iterator that works
/// with changes not yet committed to the DB.
#[derive(Debug)]
pub struct WlStorage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: WriteLog,
    /// Storage provides access to DB
    pub storage: Storage<D, H>,
}

/// Temporary storage that can be used for changes that will never be committed
/// to the DB. This is useful for the shell `PrepareProposal` and
/// `ProcessProposal` handlers that should not change state, but need to apply
/// storage changes for replay protection to validate the proposal.
#[derive(Debug)]
pub struct TempWlStorage<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: WriteLog,
    /// Storage provides access to DB
    pub storage: &'a Storage<D, H>,
}

impl<'a, D, H> TempWlStorage<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Create a temp storage that can mutated in memory, but never committed to
    /// DB.
    pub fn new(storage: &'a Storage<D, H>) -> Self {
        Self {
            write_log: WriteLog::default(),
            storage,
        }
    }
}

/// Common trait for [`WlStorage`] and [`TempWlStorage`], used to implement
/// storage_api traits.
trait WriteLogAndStorage {
    // DB type
    type D: DB + for<'iter> DBIter<'iter>;
    // DB hasher type
    type H: StorageHasher;

    /// Borrow `WriteLog`
    fn write_log(&self) -> &WriteLog;

    /// Borrow mutable `WriteLog`
    fn write_log_mut(&mut self) -> &mut WriteLog;

    /// Borrow `Storage`
    fn storage(&self) -> &Storage<Self::D, Self::H>;
}

impl<D, H> WriteLogAndStorage for WlStorage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        &self.write_log
    }

    fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.write_log
    }

    fn storage(&self) -> &Storage<D, H> {
        &self.storage
    }
}

impl<D, H> WriteLogAndStorage for TempWlStorage<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        &self.write_log
    }

    fn write_log_mut(&mut self) -> &mut WriteLog {
        &mut self.write_log
    }

    fn storage(&self) -> &Storage<D, H> {
        self.storage
    }
}

impl<D, H> WlStorage<D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    /// Combine storage with write-log
    pub fn new(write_log: WriteLog, storage: Storage<D, H>) -> Self {
        Self { write_log, storage }
    }

    /// Commit the current transaction's write log to the block when it's
    /// accepted by all the triggered validity predicates. Starts a new
    /// transaction write log.
    pub fn commit_tx(&mut self) {
        self.write_log.commit_tx()
    }

    /// Drop the current transaction's write log when it's declined by any of
    /// the triggered validity predicates. Starts a new transaction write log.
    pub fn drop_tx(&mut self) {
        self.write_log.drop_tx()
    }

    /// Commit the current block's write log to the storage and commit the block
    /// to DB. Starts a new block write log.
    pub fn commit_block(&mut self) -> storage_api::Result<()> {
        self.write_log
            .commit_block(&mut self.storage)
            .into_storage_result()?;
        self.storage.commit_block().into_storage_result()
    }

    /// Initialize a new epoch when the current epoch is finished. Returns
    /// `true` on a new epoch.
    pub fn update_epoch(
        &mut self,
        height: BlockHeight,
        time: DateTimeUtc,
    ) -> crate::ledger::storage::Result<bool> {
        let parameters =
            parameters::read(self).expect("Couldn't read protocol parameters");

        match self.storage.update_epoch_blocks_delay.as_mut() {
            None => {
                // Check if the new epoch minimum start height and start time
                // have been fulfilled. If so, queue the next
                // epoch to start two blocks into the future so
                // as to align validator set updates + etc with
                // tendermint. This is because tendermint has a two block delay
                // to validator changes.
                let current_epoch_duration_satisfied = height
                    >= self.storage.next_epoch_min_start_height
                    && time >= self.storage.next_epoch_min_start_time;
                if current_epoch_duration_satisfied {
                    self.storage.update_epoch_blocks_delay =
                        Some(EPOCH_SWITCH_BLOCKS_DELAY);
                }
            }
            Some(blocks_until_switch) => {
                *blocks_until_switch -= 1;
            }
        };
        let new_epoch =
            matches!(self.storage.update_epoch_blocks_delay, Some(0));

        if new_epoch {
            // Reset the delay tracker
            self.storage.update_epoch_blocks_delay = None;

            // Begin a new epoch
            self.storage.block.epoch = self.storage.block.epoch.next();
            let EpochDuration {
                min_num_of_blocks,
                min_duration,
            } = parameters.epoch_duration;
            self.storage.next_epoch_min_start_height =
                height + min_num_of_blocks;
            self.storage.next_epoch_min_start_time = time + min_duration;
            // TODO put this into PoS parameters and pass it to tendermint
            // `consensus_params` on `InitChain` and `EndBlock`
            let evidence_max_age_num_blocks: u64 = 100000;
            self.storage
                .block
                .pred_epochs
                .new_epoch(height, evidence_max_age_num_blocks);
            tracing::info!("Began a new epoch {}", self.storage.block.epoch);
        }
        self.storage.update_epoch_in_merkle_tree()?;
        Ok(new_epoch)
    }
}

/// Prefix iterator for [`WlStorage`].
#[derive(Debug)]
pub struct PrefixIter<'iter, D>
where
    D: DB + DBIter<'iter>,
{
    /// Peekable storage iterator
    pub storage_iter: Peekable<<D as DBIter<'iter>>::PrefixIter>,
    /// Peekable write log iterator
    pub write_log_iter: Peekable<write_log::PrefixIter>,
}

/// Iterate write-log storage items prior to a tx execution, matching the
/// given prefix. Returns the iterator and gas cost.
pub fn iter_prefix_pre<'iter, D, H>(
    // We cannot use e.g. `&'iter WlStorage`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `Storage`.
    write_log: &'iter WriteLog,
    storage: &'iter Storage<D, H>,
    prefix: &storage::Key,
) -> (PrefixIter<'iter, D>, u64)
where
    D: DB + for<'iter_> DBIter<'iter_>,
    H: StorageHasher,
{
    let storage_iter = storage.db.iter_prefix(prefix).peekable();
    let write_log_iter = write_log.iter_prefix_pre(prefix).peekable();
    (
        PrefixIter {
            storage_iter,
            write_log_iter,
        },
        gas::MIN_STORAGE_GAS,
    )
}

/// Iterate write-log storage items posterior to a tx execution, matching the
/// given prefix. Returns the iterator and gas cost.
pub fn iter_prefix_post<'iter, D, H>(
    // We cannot use e.g. `&'iter WlStorage`, because it doesn't live long
    // enough - the lifetime of the `PrefixIter` must depend on the lifetime of
    // references to the `WriteLog` and `Storage`.
    write_log: &'iter WriteLog,
    storage: &'iter Storage<D, H>,
    prefix: &storage::Key,
) -> (PrefixIter<'iter, D>, u64)
where
    D: DB + for<'iter_> DBIter<'iter_>,
    H: StorageHasher,
{
    let storage_iter = storage.db.iter_prefix(prefix).peekable();
    let write_log_iter = write_log.iter_prefix_post(prefix).peekable();
    (
        PrefixIter {
            storage_iter,
            write_log_iter,
        },
        gas::MIN_STORAGE_GAS,
    )
}

impl<'iter, D> Iterator for PrefixIter<'iter, D>
where
    D: DB + DBIter<'iter>,
{
    type Item = (String, Vec<u8>, u64);

    fn next(&mut self) -> Option<Self::Item> {
        enum Next {
            ReturnWl { advance_storage: bool },
            ReturnStorage,
        }
        loop {
            let what: Next;
            {
                let storage_peeked = self.storage_iter.peek();
                let wl_peeked = self.write_log_iter.peek();
                match (storage_peeked, wl_peeked) {
                    (None, None) => return None,
                    (None, Some(_)) => {
                        what = Next::ReturnWl {
                            advance_storage: false,
                        };
                    }
                    (Some(_), None) => {
                        what = Next::ReturnStorage;
                    }
                    (Some((storage_key, _, _)), Some((wl_key, _))) => {
                        if wl_key <= storage_key {
                            what = Next::ReturnWl {
                                advance_storage: wl_key == storage_key,
                            };
                        } else {
                            what = Next::ReturnStorage;
                        }
                    }
                }
            }
            match what {
                Next::ReturnWl { advance_storage } => {
                    if advance_storage {
                        let _ = self.storage_iter.next();
                    }

                    if let Some((key, modification)) =
                        self.write_log_iter.next()
                    {
                        match modification {
                            write_log::StorageModification::Write { value }
                            | write_log::StorageModification::Temp { value } => {
                                let gas = value.len() as u64;
                                return Some((key, value, gas));
                            }
                            write_log::StorageModification::InitAccount {
                                vp_code_hash,
                            } => {
                                let gas = vp_code_hash.len() as u64;
                                return Some((key, vp_code_hash.to_vec(), gas));
                            }
                            write_log::StorageModification::Delete => {
                                continue;
                            }
                        }
                    }
                }
                Next::ReturnStorage => {
                    if let Some(next) = self.storage_iter.next() {
                        return Some(next);
                    }
                }
            }
        }
    }
}

impl<T, D, H> StorageRead for T
where
    T: WriteLogAndStorage<D = D, H = H>,
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type PrefixIter<'iter> = PrefixIter<'iter, D> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<Vec<u8>>> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log().read(key);
        match log_val {
            Some(write_log::StorageModification::Write { ref value }) => {
                Ok(Some(value.clone()))
            }
            Some(write_log::StorageModification::Delete) => Ok(None),
            Some(write_log::StorageModification::InitAccount {
                ref vp_code_hash,
            }) => Ok(Some(vp_code_hash.to_vec())),
            Some(write_log::StorageModification::Temp { ref value }) => {
                Ok(Some(value.clone()))
            }
            None => {
                // when not found in write log, try to read from the storage
                self.storage()
                    .db
                    .read_subspace_val(key)
                    .into_storage_result()
            }
        }
    }

    fn has_key(&self, key: &storage::Key) -> storage_api::Result<bool> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log().read(key);
        match log_val {
            Some(&write_log::StorageModification::Write { .. })
            | Some(&write_log::StorageModification::InitAccount { .. })
            | Some(&write_log::StorageModification::Temp { .. }) => Ok(true),
            Some(&write_log::StorageModification::Delete) => {
                // the given key has been deleted
                Ok(false)
            }
            None => {
                // when not found in write log, try to check the storage
                self.storage().block.tree.has_key(key).into_storage_result()
            }
        }
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> storage_api::Result<Self::PrefixIter<'iter>> {
        let (iter, _gas) =
            iter_prefix_post(self.write_log(), self.storage(), prefix);
        Ok(iter)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> storage_api::Result<Option<(String, Vec<u8>)>> {
        Ok(iter.next().map(|(key, val, _gas)| (key, val)))
    }

    fn get_chain_id(&self) -> std::result::Result<String, storage_api::Error> {
        Ok(self.storage().chain_id.to_string())
    }

    fn get_block_height(
        &self,
    ) -> std::result::Result<storage::BlockHeight, storage_api::Error> {
        Ok(self.storage().block.height)
    }

    fn get_block_hash(
        &self,
    ) -> std::result::Result<storage::BlockHash, storage_api::Error> {
        Ok(self.storage().block.hash.clone())
    }

    fn get_block_epoch(
        &self,
    ) -> std::result::Result<storage::Epoch, storage_api::Error> {
        Ok(self.storage().block.epoch)
    }

    fn get_tx_index(
        &self,
    ) -> std::result::Result<storage::TxIndex, storage_api::Error> {
        Ok(self.storage().tx_index)
    }

    fn get_native_token(&self) -> storage_api::Result<Address> {
        Ok(self.storage().native_token.clone())
    }
}

impl<T, D, H> StorageWrite for T
where
    T: WriteLogAndStorage<D = D, H = H>,
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn write_bytes(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> storage_api::Result<()> {
        let _ = self
            .write_log_mut()
            .protocol_write(key, val.as_ref().to_vec())
            .into_storage_result();
        Ok(())
    }

    fn delete(&mut self, key: &storage::Key) -> storage_api::Result<()> {
        let _ = self
            .write_log_mut()
            .protocol_delete(key)
            .into_storage_result();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use borsh::{BorshDeserialize, BorshSerialize};
    use proptest::prelude::*;
    use proptest::test_runner::Config;
    // Use `RUST_LOG=info` (or another tracing level) and `--nocapture` to
    // see `tracing` logs from tests
    use test_log::test;

    use super::*;
    use crate::ledger::storage::testing::TestWlStorage;

    proptest! {
        // Generate arb valid input for `test_prefix_iters_aux`
        #![proptest_config(Config {
            cases: 10,
            .. Config::default()
        })]
        #[test]
        fn test_prefix_iters(
            key_vals in arb_key_vals(50),
        ) {
            test_prefix_iters_aux(key_vals)
        }
    }

    /// Check the `prefix_iter_pre` and `prefix_iter_post` return expected
    /// values, generated in the input to this function
    fn test_prefix_iters_aux(kvs: Vec<KeyVal<i8>>) {
        let mut s = TestWlStorage::default();

        // Partition the tx and storage kvs
        let (tx_kvs, rest): (Vec<_>, Vec<_>) = kvs
            .into_iter()
            .partition(|(_key, val)| matches!(val, Level::TxWriteLog(_)));
        // Partition the kvs to only apply block level first
        let (block_kvs, storage_kvs): (Vec<_>, Vec<_>) = rest
            .into_iter()
            .partition(|(_key, val)| matches!(val, Level::BlockWriteLog(_)));

        // Apply the kvs in order of the levels
        apply_to_wl_storage(&mut s, &storage_kvs);
        apply_to_wl_storage(&mut s, &block_kvs);
        apply_to_wl_storage(&mut s, &tx_kvs);

        // Collect the expected values in prior state - storage level then block
        let mut expected_pre = BTreeMap::new();
        for (key, val) in storage_kvs {
            if let Level::Storage(val) = val {
                expected_pre.insert(key, val);
            }
        }
        for (key, val) in &block_kvs {
            if let Level::BlockWriteLog(WlMod::Write(val)) = val {
                expected_pre.insert(key.clone(), *val);
            }
        }
        for (key, val) in &block_kvs {
            // Deletes have to be applied last
            if let Level::BlockWriteLog(WlMod::Delete) = val {
                expected_pre.remove(key);
            }
        }

        // Collect the values from prior state prefix iterator
        let (iter_pre, _gas) =
            iter_prefix_pre(&s.write_log, &s.storage, &storage::Key::default());
        let mut read_pre = BTreeMap::new();
        for (key, val, _gas) in iter_pre {
            let key = storage::Key::parse(key).unwrap();
            let val: i8 = BorshDeserialize::try_from_slice(&val).unwrap();
            read_pre.insert(key, val);
        }

        // A helper for dbg
        let keys_to_string = |kvs: &BTreeMap<storage::Key, i8>| {
            kvs.iter()
                .map(|(key, val)| (key.to_string(), *val))
                .collect::<Vec<_>>()
        };
        dbg!(keys_to_string(&expected_pre), keys_to_string(&read_pre));
        // Clone the prior expected kvs for posterior state check
        let mut expected_post = expected_pre.clone();
        itertools::assert_equal(expected_pre, read_pre);

        // Collect the expected values in posterior state - all the levels
        for (key, val) in &tx_kvs {
            if let Level::TxWriteLog(WlMod::Write(val)) = val {
                expected_post.insert(key.clone(), *val);
            }
        }
        for (key, val) in &tx_kvs {
            // Deletes have to be applied last
            if let Level::TxWriteLog(WlMod::Delete) = val {
                expected_post.remove(key);
            }
        }

        // Collect the values from posterior state prefix iterator
        let (iter_post, _gas) = iter_prefix_post(
            &s.write_log,
            &s.storage,
            &storage::Key::default(),
        );
        let mut read_post = BTreeMap::new();
        for (key, val, _gas) in iter_post {
            let key = storage::Key::parse(key).unwrap();
            let val: i8 = BorshDeserialize::try_from_slice(&val).unwrap();
            read_post.insert(key, val);
        }
        dbg!(keys_to_string(&expected_post), keys_to_string(&read_post));
        itertools::assert_equal(expected_post, read_post);
    }

    fn apply_to_wl_storage(s: &mut TestWlStorage, kvs: &[KeyVal<i8>]) {
        for (key, val) in kvs {
            match val {
                Level::TxWriteLog(WlMod::Delete)
                | Level::BlockWriteLog(WlMod::Delete) => {}
                Level::TxWriteLog(WlMod::Write(val)) => {
                    s.write_log.write(key, val.try_to_vec().unwrap()).unwrap();
                }
                Level::BlockWriteLog(WlMod::Write(val)) => {
                    s.write_log
                        // protocol only writes at block level
                        .protocol_write(key, val.try_to_vec().unwrap())
                        .unwrap();
                }
                Level::Storage(val) => {
                    s.storage.write(key, val.try_to_vec().unwrap()).unwrap();
                }
            }
        }
        for (key, val) in kvs {
            match val {
                Level::TxWriteLog(WlMod::Delete) => {
                    s.write_log.delete(key).unwrap();
                }
                Level::BlockWriteLog(WlMod::Delete) => {
                    s.write_log.protocol_delete(key).unwrap();
                }
                _ => {}
            }
        }
    }

    /// WlStorage key written in the write log or storage
    type KeyVal<VAL> = (storage::Key, Level<VAL>);

    /// WlStorage write level
    #[derive(Clone, Copy, Debug)]
    enum Level<VAL> {
        TxWriteLog(WlMod<VAL>),
        BlockWriteLog(WlMod<VAL>),
        Storage(VAL),
    }

    /// Write log modification
    #[derive(Clone, Copy, Debug)]
    enum WlMod<VAL> {
        Write(VAL),
        Delete,
    }

    fn arb_key_vals(len: usize) -> impl Strategy<Value = Vec<KeyVal<i8>>> {
        // Start with some arb. storage key-vals
        let storage_kvs = prop::collection::vec(
            (storage::testing::arb_key(), any::<i8>()),
            1..len,
        )
        .prop_map(|kvs| {
            kvs.into_iter()
                .map(|(key, val)| (key, Level::Storage(val)))
                .collect::<Vec<_>>()
        });

        // Select some indices to override in write log
        let overrides = prop::collection::vec(
            (any::<prop::sample::Index>(), any::<i8>(), any::<bool>()),
            1..len / 2,
        );

        // Select some indices to delete
        let deletes = prop::collection::vec(
            (any::<prop::sample::Index>(), any::<bool>()),
            1..len / 3,
        );

        // Combine them all together
        (storage_kvs, overrides, deletes).prop_map(
            |(mut kvs, overrides, deletes)| {
                for (ix, val, is_tx) in overrides {
                    let (key, _) = ix.get(&kvs);
                    let wl_mod = WlMod::Write(val);
                    let lvl = if is_tx {
                        Level::TxWriteLog(wl_mod)
                    } else {
                        Level::BlockWriteLog(wl_mod)
                    };
                    kvs.push((key.clone(), lvl));
                }
                for (ix, is_tx) in deletes {
                    let (key, _) = ix.get(&kvs);
                    // We have to skip validity predicate keys as they cannot be
                    // deleted
                    if key.is_validity_predicate().is_some() {
                        continue;
                    }
                    let wl_mod = WlMod::Delete;
                    let lvl = if is_tx {
                        Level::TxWriteLog(wl_mod)
                    } else {
                        Level::BlockWriteLog(wl_mod)
                    };
                    kvs.push((key.clone(), lvl));
                }
                kvs
            },
        )
    }
}
