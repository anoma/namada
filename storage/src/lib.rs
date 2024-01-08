//! The common storage read trait is implemented in the storage, client RPC, tx
//! and VPs (both native and WASM).

pub mod collections;
mod db;
mod error;
pub mod mockdb;
pub mod tx_queue;
pub mod types;

pub use db::{Error as DbError, Result as DbResult, *};
pub use error::{CustomError, Error, OptionExt, Result, ResultExt};
use namada_core::borsh::{BorshDeserialize, BorshSerialize, BorshSerializeExt};
use namada_core::types::address::Address;
pub use namada_core::types::hash::StorageHasher;
use namada_core::types::storage::{
    self, BlockHash, BlockHeight, Epoch, Epochs, Header, TxIndex,
};

/// Common storage read interface
///
/// If you're using this trait and having compiler complaining about needing an
/// explicit lifetime parameter, simply use trait bounds with the following
/// syntax:
///
/// ```rust,ignore
/// where
///     S: StorageRead
/// ```
///
/// If you want to know why this is needed, see the to-do task below. The
/// syntax for this relies on higher-rank lifetimes, see e.g.
/// <https://doc.rust-lang.org/nomicon/hrtb.html>.
pub trait StorageRead {
    /// Storage read prefix iterator
    type PrefixIter<'iter>
    where
        Self: 'iter;

    /// Storage read Borsh encoded value. It will try to read from the storage
    /// and decode it if found.
    fn read<T: BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>> {
        let bytes = self.read_bytes(key)?;
        match bytes {
            Some(bytes) => {
                let val = T::try_from_slice(&bytes).into_storage_result()?;
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    /// Storage read raw bytes. It will try to read from the storage.
    fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>>;

    /// Storage `has_key` in. It will try to read from the storage.
    fn has_key(&self, key: &storage::Key) -> Result<bool>;

    /// Storage prefix iterator ordered by the storage keys. It will try to get
    /// an iterator from the storage.
    ///
    /// For a more user-friendly iterator API, use [`fn@iter_prefix`] or
    /// [`fn@iter_prefix_bytes`] instead.
    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>>;

    /// Storage prefix iterator. It will try to read from the storage.
    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>>;

    /// Getting the chain ID.
    fn get_chain_id(&self) -> Result<String>;

    /// Getting the block height. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_height(&self) -> Result<BlockHeight>;

    /// Getting the block header.
    fn get_block_header(&self, height: BlockHeight) -> Result<Option<Header>>;

    /// Getting the block hash. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_hash(&self) -> Result<BlockHash>;

    /// Getting the block epoch. The epoch is that of the block to which the
    /// current transaction is being applied.
    fn get_block_epoch(&self) -> Result<Epoch>;

    /// Given the information about predecessor block epochs
    fn get_pred_epochs(&self) -> Result<Epochs>;

    /// Get the transaction index.
    fn get_tx_index(&self) -> Result<TxIndex>;

    /// Get the native token address
    fn get_native_token(&self) -> Result<Address>;

    /// Get the height of the first block of the current epoch.
    fn get_current_epoch_start_height(&self) -> Result<BlockHeight> {
        Ok(self
            .get_pred_epochs()?
            .first_block_heights()
            .last()
            .copied()
            .expect("The block height of the current epoch should be known"))
    }

    /// Get the height of the first block of the given epoch.
    fn get_epoch_start_height(
        &self,
        epoch: Epoch,
    ) -> Result<Option<BlockHeight>> {
        let epochs = self.get_pred_epochs()?;
        Ok(epochs.get_start_height_of_epoch(epoch))
    }

    /// Given the epoch at the given block height.
    fn get_epoch_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Epoch>> {
        let epochs = self.get_pred_epochs()?;
        Ok(epochs.get_epoch(height))
    }
}

/// Common storage write interface
pub trait StorageWrite {
    /// Write a value to be encoded with Borsh at the given key to storage.
    fn write<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<()> {
        let bytes = val.serialize_to_vec();
        self.write_bytes(key, bytes)
    }

    /// Write a value as bytes at the given key to storage.
    fn write_bytes(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> Result<()>;

    /// Delete a value at the given key from storage.
    fn delete(&mut self, key: &storage::Key) -> Result<()>;

    /// Delete all key-vals with a matching prefix.
    fn delete_prefix(&mut self, prefix: &storage::Key) -> Result<()>
    where
        Self: StorageRead + Sized,
    {
        let keys = iter_prefix_bytes(self, prefix)?
            .map(|res| {
                let (key, _val) = res?;
                Ok(key)
            })
            .collect::<Result<Vec<storage::Key>>>();
        for key in keys? {
            // Skip validity predicates as they cannot be deleted
            if key.is_validity_predicate().is_none() {
                self.delete(&key)?;
            }
        }
        Ok(())
    }
}

/// Iterate items matching the given prefix, ordered by the storage keys.
pub fn iter_prefix_bytes<'a>(
    storage: &'a impl StorageRead,
    prefix: &storage::Key,
) -> Result<impl Iterator<Item = Result<(storage::Key, Vec<u8>)>> + 'a> {
    let iter = storage.iter_prefix(prefix)?;
    let iter = itertools::unfold(iter, |iter| {
        match storage.iter_next(iter) {
            Ok(Some((key, val))) => {
                let key = match storage::Key::parse(key).into_storage_result() {
                    Ok(key) => key,
                    Err(err) => {
                        // Propagate key encoding errors into Iterator's Item
                        return Some(Err(err));
                    }
                };
                Some(Ok((key, val)))
            }
            Ok(None) => None,
            Err(err) => {
                // Propagate `iter_next` errors into Iterator's Item
                Some(Err(err))
            }
        }
    });
    Ok(iter)
}

/// Iterate Borsh encoded items matching the given prefix, ordered by the
/// storage keys.
pub fn iter_prefix<'a, T>(
    storage: &'a impl StorageRead,
    prefix: &storage::Key,
) -> Result<impl Iterator<Item = Result<(storage::Key, T)>> + 'a>
where
    T: BorshDeserialize,
{
    let iter = storage.iter_prefix(prefix)?;
    let iter = itertools::unfold(iter, |iter| {
        match storage.iter_next(iter) {
            Ok(Some((key, val))) => {
                let key = match storage::Key::parse(key).into_storage_result() {
                    Ok(key) => key,
                    Err(err) => {
                        // Propagate key encoding errors into Iterator's Item
                        return Some(Err(err));
                    }
                };
                let val = match T::try_from_slice(&val).into_storage_result() {
                    Ok(val) => val,
                    Err(err) => {
                        // Propagate val encoding errors into Iterator's Item
                        return Some(Err(err));
                    }
                };
                Some(Ok((key, val)))
            }
            Ok(None) => None,
            Err(err) => {
                // Propagate `iter_next` errors into Iterator's Item
                Some(Err(err))
            }
        }
    });
    Ok(iter)
}

/// Iterate Borsh encoded items matching the given prefix and passing the given
/// `filter` predicate, ordered by the storage keys.
///
/// The `filter` predicate is a function from a storage key to bool and only
/// the items that return `true` will be returned from the iterator.
///
/// Note that this is preferable over the regular `iter_prefix` combined with
/// the iterator's `filter` function as it avoids trying to decode values that
/// don't pass the filter. For `iter_prefix_bytes`, `filter` works fine.
pub fn iter_prefix_with_filter<'a, T, F>(
    storage: &'a impl StorageRead,
    prefix: &storage::Key,
    filter: F,
) -> Result<impl Iterator<Item = Result<(storage::Key, T)>> + 'a>
where
    T: BorshDeserialize,
    F: Fn(&storage::Key) -> bool + 'a,
{
    let iter = storage.iter_prefix(prefix)?;
    let iter = itertools::unfold(iter, move |iter| {
        // The loop is for applying filter - we `continue` when the current key
        // doesn't pass the predicate.
        loop {
            match storage.iter_next(iter) {
                Ok(Some((key, val))) => {
                    let key =
                        match storage::Key::parse(key).into_storage_result() {
                            Ok(key) => key,
                            Err(err) => {
                                // Propagate key encoding errors into Iterator's
                                // Item
                                return Some(Err(err));
                            }
                        };
                    // Check the predicate
                    if !filter(&key) {
                        continue;
                    }
                    let val =
                        match T::try_from_slice(&val).into_storage_result() {
                            Ok(val) => val,
                            Err(err) => {
                                // Propagate val encoding errors into Iterator's
                                // Item
                                return Some(Err(err));
                            }
                        };
                    return Some(Ok((key, val)));
                }
                Ok(None) => return None,
                Err(err) => {
                    // Propagate `iter_next` errors into Iterator's Item
                    return Some(Err(err));
                }
            }
        }
    });
    Ok(iter)
}

/// Helpers for testing components that depend on storage
#[cfg(any(test, feature = "testing"))]
pub mod testing {

    use namada_core::types::address;
    use namada_core::types::chain::ChainId;

    use super::mockdb::MockDB;
    use super::*;

    /// Storage with a mock DB for testing
    pub struct TestStorage {
        db: MockDB,
        chain_id: ChainId,
        height: BlockHeight,
        epoch: Epoch,
        pred_epochs: Epochs,
        native_token: Address,
    }

    #[allow(clippy::derivable_impls)]
    impl Default for TestStorage {
        fn default() -> Self {
            Self {
                db: Default::default(),
                chain_id: ChainId::default(),
                height: BlockHeight::first(),
                epoch: Epoch::default(),
                pred_epochs: Epochs::default(),
                native_token: address::nam(),
            }
        }
    }

    impl StorageRead for TestStorage {
        type PrefixIter<'iter> = PrefixIter<'iter> where Self: 'iter;

        fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>> {
            self.db.read_subspace_val(key).into_storage_result()
        }

        fn has_key(&self, key: &storage::Key) -> Result<bool> {
            Ok(self.read_bytes(key)?.is_some())
        }

        fn iter_prefix<'iter>(
            &'iter self,
            prefix: &storage::Key,
        ) -> Result<Self::PrefixIter<'iter>> {
            let storage_iter = self.db.iter_prefix(Some(prefix));
            Ok(PrefixIter {
                db_iter: storage_iter,
            })
        }

        fn iter_next<'iter>(
            &'iter self,
            iter: &mut Self::PrefixIter<'iter>,
        ) -> Result<Option<(String, Vec<u8>)>> {
            Ok(iter.next())
        }

        fn get_chain_id(&self) -> Result<String> {
            Ok(self.chain_id.to_string())
        }

        fn get_block_height(&self) -> Result<BlockHeight> {
            Ok(self.height)
        }

        fn get_block_header(
            &self,
            _height: BlockHeight,
        ) -> Result<Option<Header>> {
            Ok(None)
        }

        fn get_block_hash(&self) -> Result<BlockHash> {
            Ok(BlockHash::default())
        }

        fn get_block_epoch(&self) -> Result<Epoch> {
            Ok(self.epoch)
        }

        fn get_pred_epochs(&self) -> Result<Epochs> {
            Ok(self.pred_epochs.clone())
        }

        fn get_tx_index(&self) -> Result<TxIndex> {
            Ok(TxIndex::default())
        }

        fn get_native_token(&self) -> Result<Address> {
            Ok(self.native_token.clone())
        }
    }

    impl StorageWrite for TestStorage {
        fn write_bytes(
            &mut self,
            key: &storage::Key,
            val: impl AsRef<[u8]>,
        ) -> Result<()> {
            self.db
                .write_subspace_val(self.height, key, val)
                .into_storage_result()?;
            Ok(())
        }

        fn delete(&mut self, key: &storage::Key) -> Result<()> {
            self.db
                .delete_subspace_val(self.height, key)
                .into_storage_result()?;
            Ok(())
        }
    }

    /// Prefix iterator for [`TestStorage`].
    #[derive(Debug)]
    pub struct PrefixIter<'iter> {
        /// DB iterator
        pub db_iter: <MockDB as DBIter<'iter>>::PrefixIter,
    }

    impl<'iter> Iterator for PrefixIter<'iter> {
        type Item = (String, Vec<u8>);

        fn next(&mut self) -> Option<Self::Item> {
            self.db_iter.next().map(|(key, val, _gas)| (key, val))
        }
    }
}
