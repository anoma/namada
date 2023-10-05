//! Native validity predicate interface associated with internal accounts such
//! as the PoS and IBC modules.

pub mod ethereum_bridge;
pub mod ibc;
pub mod multitoken;
pub mod parameters;

use std::cell::RefCell;
use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use eyre::WrapErr;
pub use namada_core::ledger::vp_env::VpEnv;

use super::storage_api::{self, ResultExt, StorageRead};
use super::vp_host_fns;
use crate::ledger::gas::VpGasMeter;
use crate::ledger::storage;
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{Storage, StorageHasher};
use crate::proto::Tx;
use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::storage::{
    BlockHash, BlockHeight, Epoch, Header, Key, TxIndex,
};
use crate::vm::prefix_iter::PrefixIterators;
use crate::vm::WasmCacheAccess;

/// Possible error in a native VP host function call
/// The `storage_api::Error` may wrap the `vp_host_fns::RuntimeError` and can
/// be extended with other custom errors when using `trait VpEnv`.
pub type Error = storage_api::Error;

/// A native VP module should implement its validation logic using this trait.
pub trait NativeVp {
    /// Error type for the methods' results.
    type Error: std::error::Error;

    /// Run the validity predicate
    fn validate_tx(
        &self,
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> std::result::Result<bool, Self::Error>;
}

/// A validity predicate's host context.
///
/// This is similar to [`crate::vm::host_env::VpCtx`], but without the VM
/// wrapper types and `eval_runner` field. The references must not be changed
/// when [`Ctx`] is mutable.
#[derive(Debug)]
pub struct Ctx<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// The address of the account that owns the VP
    pub address: &'a Address,
    /// Storage prefix iterators.
    pub iterators: RefCell<PrefixIterators<'a, DB>>,
    /// VP gas meter.
    pub gas_meter: RefCell<VpGasMeter>,
    /// Read-only access to the storage.
    pub storage: &'a Storage<DB, H>,
    /// Read-only access to the write log.
    pub write_log: &'a WriteLog,
    /// The transaction code is used for signature verification
    pub tx: &'a Tx,
    /// The transaction index is used to obtain the shielded transaction's
    /// parent
    pub tx_index: &'a TxIndex,
    /// The storage keys that have been changed. Used for calls to `eval`.
    pub keys_changed: &'a BTreeSet<Key>,
    /// The verifiers whose validity predicates should be triggered. Used for
    /// calls to `eval`.
    pub verifiers: &'a BTreeSet<Address>,
    /// VP WASM compilation cache
    #[cfg(feature = "wasm-runtime")]
    pub vp_wasm_cache: crate::vm::wasm::VpCache<CA>,
    /// To avoid unused parameter without "wasm-runtime" feature
    #[cfg(not(feature = "wasm-runtime"))]
    pub cache_access: std::marker::PhantomData<CA>,
}

/// Read access to the prior storage (state before tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPreStorageRead<'view, 'a: 'view, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    ctx: &'view Ctx<'a, DB, H, CA>,
}

/// Read access to the posterior storage (state after tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPostStorageRead<'view, 'a: 'view, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    ctx: &'view Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> Ctx<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Initialize a new context for native VP call
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: &'a Address,
        storage: &'a Storage<DB, H>,
        write_log: &'a WriteLog,
        tx: &'a Tx,
        tx_index: &'a TxIndex,
        gas_meter: VpGasMeter,
        keys_changed: &'a BTreeSet<Key>,
        verifiers: &'a BTreeSet<Address>,
        #[cfg(feature = "wasm-runtime")]
        vp_wasm_cache: crate::vm::wasm::VpCache<CA>,
    ) -> Self {
        Self {
            address,
            iterators: RefCell::new(PrefixIterators::default()),
            gas_meter: RefCell::new(gas_meter),
            storage,
            write_log,
            tx,
            tx_index,
            keys_changed,
            verifiers,
            #[cfg(feature = "wasm-runtime")]
            vp_wasm_cache,
            #[cfg(not(feature = "wasm-runtime"))]
            cache_access: std::marker::PhantomData,
        }
    }

    /// Read access to the prior storage (state before tx execution)
    /// via [`trait@StorageRead`].
    pub fn pre<'view>(&'view self) -> CtxPreStorageRead<'view, 'a, DB, H, CA> {
        CtxPreStorageRead { ctx: self }
    }

    /// Read access to the posterior storage (state after tx execution)
    /// via [`trait@StorageRead`].
    pub fn post<'view>(
        &'view self,
    ) -> CtxPostStorageRead<'view, 'a, DB, H, CA> {
        CtxPostStorageRead { ctx: self }
    }
}

impl<'view, 'a: 'view, DB, H, CA> StorageRead
    for CtxPreStorageRead<'view, 'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type PrefixIter<'iter> = storage::PrefixIter<'iter, DB> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &crate::types::storage::Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        vp_host_fns::read_pre(
            &mut self.ctx.gas_meter.borrow_mut(),
            self.ctx.storage,
            self.ctx.write_log,
            key,
        )
        .into_storage_result()
    }

    fn has_key(
        &self,
        key: &crate::types::storage::Key,
    ) -> Result<bool, storage_api::Error> {
        vp_host_fns::has_key_pre(
            &mut self.ctx.gas_meter.borrow_mut(),
            self.ctx.storage,
            self.ctx.write_log,
            key,
        )
        .into_storage_result()
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &crate::types::storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, storage_api::Error> {
        vp_host_fns::iter_prefix_pre(
            &mut self.ctx.gas_meter.borrow_mut(),
            self.ctx.write_log,
            self.ctx.storage,
            prefix,
        )
        .into_storage_result()
    }

    // ---- Methods below are implemented in `self.ctx`, because they are
    //      the same in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        vp_host_fns::iter_next::<DB>(&mut self.ctx.gas_meter.borrow_mut(), iter)
            .into_storage_result()
    }

    fn get_chain_id(&self) -> Result<String, storage_api::Error> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, storage_api::Error> {
        self.ctx.get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, storage_api::Error> {
        self.ctx.get_block_header(height)
    }

    fn get_block_hash(&self) -> Result<BlockHash, storage_api::Error> {
        self.ctx.get_block_hash()
    }

    fn get_block_epoch(&self) -> Result<Epoch, storage_api::Error> {
        self.ctx.get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex, storage_api::Error> {
        self.ctx.get_tx_index().into_storage_result()
    }

    fn get_native_token(&self) -> Result<Address, storage_api::Error> {
        self.ctx.get_native_token()
    }
}

impl<'view, 'a: 'view, DB, H, CA> StorageRead
    for CtxPostStorageRead<'view, 'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type PrefixIter<'iter> = storage::PrefixIter<'iter, DB> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &crate::types::storage::Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        vp_host_fns::read_post(
            &mut self.ctx.gas_meter.borrow_mut(),
            self.ctx.storage,
            self.ctx.write_log,
            key,
        )
        .into_storage_result()
    }

    fn has_key(
        &self,
        key: &crate::types::storage::Key,
    ) -> Result<bool, storage_api::Error> {
        vp_host_fns::has_key_post(
            &mut self.ctx.gas_meter.borrow_mut(),
            self.ctx.storage,
            self.ctx.write_log,
            key,
        )
        .into_storage_result()
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &crate::types::storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, storage_api::Error> {
        vp_host_fns::iter_prefix_post(
            &mut self.ctx.gas_meter.borrow_mut(),
            self.ctx.write_log,
            self.ctx.storage,
            prefix,
        )
        .into_storage_result()
    }

    // ---- Methods below are implemented in `self.ctx`, because they are
    //      the same in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        vp_host_fns::iter_next::<DB>(&mut self.ctx.gas_meter.borrow_mut(), iter)
            .into_storage_result()
    }

    fn get_chain_id(&self) -> Result<String, storage_api::Error> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, storage_api::Error> {
        self.ctx.get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, storage_api::Error> {
        self.ctx.get_block_header(height)
    }

    fn get_block_hash(&self) -> Result<BlockHash, storage_api::Error> {
        self.ctx.get_block_hash()
    }

    fn get_block_epoch(&self) -> Result<Epoch, storage_api::Error> {
        self.ctx.get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex, storage_api::Error> {
        self.ctx.get_tx_index().into_storage_result()
    }

    fn get_native_token(&self) -> Result<Address, storage_api::Error> {
        Ok(self.ctx.storage.native_token.clone())
    }
}

impl<'view, 'a: 'view, DB, H, CA> VpEnv<'view> for Ctx<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Post = CtxPostStorageRead<'view, 'a, DB, H, CA>;
    type Pre = CtxPreStorageRead<'view, 'a, DB, H, CA>;
    type PrefixIter<'iter> = storage::PrefixIter<'iter, DB> where Self: 'iter;

    fn pre(&'view self) -> Self::Pre {
        CtxPreStorageRead { ctx: self }
    }

    fn post(&'view self) -> Self::Post {
        CtxPostStorageRead { ctx: self }
    }

    fn read_temp<T: borsh::BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        vp_host_fns::read_temp(
            &mut self.gas_meter.borrow_mut(),
            self.write_log,
            key,
        )
        .map(|data| data.and_then(|t| T::try_from_slice(&t[..]).ok()))
        .into_storage_result()
    }

    fn read_bytes_temp(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        vp_host_fns::read_temp(
            &mut self.gas_meter.borrow_mut(),
            self.write_log,
            key,
        )
        .into_storage_result()
    }

    fn get_chain_id(&self) -> Result<String, storage_api::Error> {
        vp_host_fns::get_chain_id(
            &mut self.gas_meter.borrow_mut(),
            self.storage,
        )
        .into_storage_result()
    }

    fn get_block_height(&self) -> Result<BlockHeight, storage_api::Error> {
        vp_host_fns::get_block_height(
            &mut self.gas_meter.borrow_mut(),
            self.storage,
        )
        .into_storage_result()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, storage_api::Error> {
        vp_host_fns::get_block_header(
            &mut self.gas_meter.borrow_mut(),
            self.storage,
            height,
        )
        .into_storage_result()
    }

    fn get_block_hash(&self) -> Result<BlockHash, storage_api::Error> {
        vp_host_fns::get_block_hash(
            &mut self.gas_meter.borrow_mut(),
            self.storage,
        )
        .into_storage_result()
    }

    fn get_block_epoch(&self) -> Result<Epoch, storage_api::Error> {
        vp_host_fns::get_block_epoch(
            &mut self.gas_meter.borrow_mut(),
            self.storage,
        )
        .into_storage_result()
    }

    fn get_tx_index(&self) -> Result<TxIndex, storage_api::Error> {
        vp_host_fns::get_tx_index(
            &mut self.gas_meter.borrow_mut(),
            self.tx_index,
        )
        .into_storage_result()
    }

    fn get_native_token(&self) -> Result<Address, storage_api::Error> {
        vp_host_fns::get_native_token(
            &mut self.gas_meter.borrow_mut(),
            self.storage,
        )
        .into_storage_result()
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, storage_api::Error> {
        vp_host_fns::iter_prefix_pre(
            &mut self.gas_meter.borrow_mut(),
            self.write_log,
            self.storage,
            prefix,
        )
        .into_storage_result()
    }

    fn eval(
        &self,
        vp_code_hash: Hash,
        input_data: Tx,
    ) -> Result<bool, storage_api::Error> {
        #[cfg(feature = "wasm-runtime")]
        {
            use std::marker::PhantomData;

            use crate::vm::host_env::VpCtx;
            use crate::vm::wasm::run::VpEvalWasm;

            let eval_runner = VpEvalWasm {
                db: PhantomData,
                hasher: PhantomData,
                cache_access: PhantomData,
            };
            let mut iterators: PrefixIterators<'_, DB> =
                PrefixIterators::default();
            let mut result_buffer: Option<Vec<u8>> = None;
            let mut vp_wasm_cache = self.vp_wasm_cache.clone();

            let ctx = VpCtx::new(
                self.address,
                self.storage,
                self.write_log,
                &mut self.gas_meter.borrow_mut(),
                self.tx,
                self.tx_index,
                &mut iterators,
                self.verifiers,
                &mut result_buffer,
                self.keys_changed,
                &eval_runner,
                &mut vp_wasm_cache,
            );
            match eval_runner.eval_native_result(ctx, vp_code_hash, input_data)
            {
                Ok(result) => Ok(result),
                Err(err) => {
                    tracing::warn!(
                        "VP eval from a native VP failed with: {}",
                        err
                    );
                    Ok(false)
                }
            }
        }

        #[cfg(not(feature = "wasm-runtime"))]
        {
            // This line is here to prevent unused var clippy warning
            let _ = (vp_code_hash, input_data);
            unimplemented!(
                "The \"wasm-runtime\" feature must be enabled to use the \
                 `eval` function."
            )
        }
    }

    fn verify_masp(&self, _tx: Vec<u8>) -> Result<bool, storage_api::Error> {
        unimplemented!("no masp native vp")
    }

    fn charge_gas(&self, _used_gas: u64) -> Result<(), storage_api::Error> {
        unimplemented!("Native vps don't consume whitelisted gas")
    }

    fn get_tx_code_hash(&self) -> Result<Option<Hash>, storage_api::Error> {
        vp_host_fns::get_tx_code_hash(&mut self.gas_meter.borrow_mut(), self.tx)
            .into_storage_result()
    }

    fn read_pre<T: borsh::BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.pre().read(key).map_err(Into::into)
    }

    fn read_bytes_pre(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.pre().read_bytes(key).map_err(Into::into)
    }

    fn read_post<T: borsh::BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.post().read(key).map_err(Into::into)
    }

    fn read_bytes_post(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.post().read_bytes(key).map_err(Into::into)
    }

    fn has_key_pre(&self, key: &Key) -> Result<bool, storage_api::Error> {
        self.pre().has_key(key).map_err(Into::into)
    }

    fn has_key_post(&self, key: &Key) -> Result<bool, storage_api::Error> {
        self.post().has_key(key).map_err(Into::into)
    }
}

/// A convenience trait for reading and automatically deserializing a value from
/// storage
pub trait StorageReader {
    /// If `maybe_bytes` is not empty, return an `Option<T>` containing the
    /// deserialization of the bytes inside `maybe_bytes`.
    fn deserialize_if_present<T: BorshDeserialize>(
        maybe_bytes: Option<Vec<u8>>,
    ) -> eyre::Result<Option<T>> {
        maybe_bytes
            .map(|ref bytes| {
                T::try_from_slice(bytes)
                    .wrap_err_with(|| "couldn't deserialize".to_string())
            })
            .transpose()
    }

    /// Storage read prior state (before tx execution). It will try to read from
    /// the storage.
    fn read_pre_value<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> eyre::Result<Option<T>>;

    /// Storage read posterior state (after tx execution). It will try to read
    /// from the write log first and if no entry found then from the
    /// storage.
    fn read_post_value<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> eyre::Result<Option<T>>;
}

impl<'a, DB, H, CA> StorageReader for &Ctx<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Helper function. After reading posterior state,
    /// borsh deserialize to specified type
    fn read_post_value<T>(&self, key: &Key) -> eyre::Result<Option<T>>
    where
        T: BorshDeserialize,
    {
        let maybe_bytes = Ctx::read_bytes_post(self, key)
            .wrap_err_with(|| format!("couldn't read_bytes_post {}", key))?;
        Self::deserialize_if_present(maybe_bytes)
    }

    /// Helper function. After reading prior state,
    /// borsh deserialize to specified type
    fn read_pre_value<T>(&self, key: &Key) -> eyre::Result<Option<T>>
    where
        T: BorshDeserialize,
    {
        let maybe_bytes = Ctx::read_bytes_pre(self, key)
            .wrap_err_with(|| format!("couldn't read_bytes_pre {}", key))?;
        Self::deserialize_if_present(maybe_bytes)
    }
}

#[cfg(any(test, feature = "testing"))]
pub(super) mod testing {
    use std::collections::HashMap;

    use borsh::BorshDeserialize;

    use super::*;

    #[derive(Debug, Default)]
    pub(in super::super) struct FakeStorageReader {
        pre: HashMap<Key, Vec<u8>>,
        post: HashMap<Key, Vec<u8>>,
    }

    impl StorageReader for FakeStorageReader {
        fn read_pre_value<T: BorshDeserialize>(
            &self,
            key: &Key,
        ) -> eyre::Result<Option<T>> {
            let bytes = match self.pre.get(key) {
                Some(bytes) => bytes.to_owned(),
                None => return Ok(None),
            };
            Self::deserialize_if_present(Some(bytes))
        }

        fn read_post_value<T: BorshDeserialize>(
            &self,
            key: &Key,
        ) -> eyre::Result<Option<T>> {
            let bytes = match self.post.get(key) {
                Some(bytes) => bytes.to_owned(),
                None => return Ok(None),
            };
            Self::deserialize_if_present(Some(bytes))
        }
    }
}
