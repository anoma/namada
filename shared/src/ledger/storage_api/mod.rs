//! The common storage read trait is implemented in the storage, client RPC, tx
//! and VPs (both native and WASM).

mod error;

use borsh::{BorshDeserialize, BorshSerialize};
pub use error::{CustomError, Error, Result, ResultExt};

use crate::types::storage::{self, BlockHash, BlockHeight, Epoch};

/// Common storage read interface
///
/// If you're using this trait and having compiler complaining about needing an
/// explicit lifetime parameter, simply use trait bounds with the following
/// syntax:
///
/// ```rust,ignore
/// where
///     S: for<'iter> StorageRead<'iter>
/// ```
///
/// If you want to know why this is needed, see the to-do task below. The
/// syntax for this relies on higher-rank lifetimes, see e.g.
/// <https://doc.rust-lang.org/nomicon/hrtb.html>.
///
/// TODO: once GATs are stabilized, we should be able to remove the `'iter`
/// lifetime param that is currently the only way to make the prefix iterator
/// typecheck in the `<D as DBIter<'iter>>::PrefixIter` associated type used in
/// `impl StorageRead for Storage` (shared/src/ledger/storage/mod.rs).
/// See <https://github.com/rust-lang/rfcs/blob/master/text/1598-generic_associated_types.md>
pub trait StorageRead<'iter> {
    /// Storage read prefix iterator
    type PrefixIter;

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

    /// Storage prefix iterator for. It will try to read from the storage.
    fn iter_next(
        &self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>>;

    /// Storage prefix iterator. It will try to get an iterator from the
    /// storage.
    ///
    /// For a more user-friendly iterator API, use [`fn@iter_prefix`] or
    /// [`fn@iter_prefix_bytes`] instead.
    fn iter_prefix(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter>;

    /// Getting the chain ID.
    fn get_chain_id(&self) -> Result<String>;

    /// Getting the block height. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_height(&self) -> Result<BlockHeight>;

    /// Getting the block hash. The height is that of the block to which the
    /// current transaction is being applied.
    fn get_block_hash(&self) -> Result<BlockHash>;

    /// Getting the block epoch. The epoch is that of the block to which the
    /// current transaction is being applied.
    fn get_block_epoch(&self) -> Result<Epoch>;
}

/// Common storage write interface
pub trait StorageWrite {
    /// Write a value to be encoded with Borsh at the given key to storage.
    fn write<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<()> {
        let bytes = val.try_to_vec().into_storage_result()?;
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
}

/// Iterate items matching the given prefix.
pub fn iter_prefix_bytes<'a>(
    storage: &'a impl StorageRead<'a>,
    prefix: &crate::types::storage::Key,
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

/// Iterate Borsh encoded items matching the given prefix.
pub fn iter_prefix<'a, T>(
    storage: &'a impl StorageRead<'a>,
    prefix: &crate::types::storage::Key,
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
