//! Native validity predicate interface associated with internal accounts such
//! as the PoS and IBC modules.

pub mod parameters;
pub mod governance;

use std::cell::RefCell;
use std::collections::BTreeSet;

use super::storage_api::{self, ResultExt, StorageRead};
pub use super::vp_env::VpEnv;
use crate::ledger::gas::VpGasMeter;
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{Storage, StorageHasher};
use crate::ledger::{storage, vp_env};
use crate::proto::Tx;
use crate::types::address::{Address, InternalAddress};
use crate::types::hash::Hash;
use crate::types::storage::{BlockHash, BlockHeight, Epoch, Key, TxIndex};
use crate::vm::prefix_iter::PrefixIterators;
use crate::vm::WasmCacheAccess;

/// Possible error in a native VP host function call
/// The `storage_api::Error` may wrap the `vp_env::RuntimeError` and can
/// be extended with other custom errors when using `trait VpEnv`.
pub type Error = storage_api::Error;

/// A native VP module should implement its validation logic using this trait.
pub trait NativeVp {
    /// The address of this VP
    const ADDR: InternalAddress;

    /// Error type for the methods' results.
    type Error: std::error::Error;

    /// Run the validity predicate
    fn validate_tx(
        &self,
        tx_data: &[u8],
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

    /// Add a gas cost incured in a validity predicate
    pub fn add_gas(&self, used_gas: u64) -> Result<(), vp_env::RuntimeError> {
        vp_env::add_gas(&mut *self.gas_meter.borrow_mut(), used_gas)
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

impl<'view, 'a, DB, H, CA> StorageRead<'view>
    for CtxPreStorageRead<'view, 'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type PrefixIter = <DB as storage::DBIter<'a>>::PrefixIter;

    fn read_bytes(
        &self,
        key: &crate::types::storage::Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        vp_env::read_pre(
            &mut *self.ctx.gas_meter.borrow_mut(),
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
        vp_env::has_key_pre(
            &mut *self.ctx.gas_meter.borrow_mut(),
            self.ctx.storage,
            key,
        )
        .into_storage_result()
    }

    fn rev_iter_prefix(
        &self,
        prefix: &crate::types::storage::Key,
    ) -> storage_api::Result<Self::PrefixIter> {
        self.ctx.rev_iter_prefix(prefix).into_storage_result()
    }

    fn iter_next(
        &self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        vp_env::iter_pre_next::<DB>(&mut *self.ctx.gas_meter.borrow_mut(), iter)
            .into_storage_result()
    }

    // ---- Methods below are implemented in `self.ctx`, because they are
    //      the same in `pre/post` ----

    fn iter_prefix(
        &self,
        prefix: &crate::types::storage::Key,
    ) -> Result<Self::PrefixIter, storage_api::Error> {
        self.ctx.iter_prefix(prefix)
    }

    fn get_chain_id(&self) -> Result<String, storage_api::Error> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, storage_api::Error> {
        self.ctx.get_block_height()
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

impl<'view, 'a, DB, H, CA> StorageRead<'view>
    for CtxPostStorageRead<'view, 'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type PrefixIter = <DB as storage::DBIter<'a>>::PrefixIter;

    fn read_bytes(
        &self,
        key: &crate::types::storage::Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        vp_env::read_post(
            &mut *self.ctx.gas_meter.borrow_mut(),
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
        vp_env::has_key_post(
            &mut *self.ctx.gas_meter.borrow_mut(),
            self.ctx.storage,
            self.ctx.write_log,
            key,
        )
        .into_storage_result()
    }

    fn rev_iter_prefix(
        &self,
        prefix: &crate::types::storage::Key,
    ) -> storage_api::Result<Self::PrefixIter> {
        self.ctx.rev_iter_prefix(prefix).into_storage_result()
    }

    fn iter_next(
        &self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        vp_env::iter_post_next::<DB>(
            &mut *self.ctx.gas_meter.borrow_mut(),
            self.ctx.write_log,
            iter,
        )
        .into_storage_result()
    }

    // ---- Methods below are implemented in `self.ctx`, because they are
    //      the same in `pre/post` ----

    fn iter_prefix(
        &self,
        prefix: &crate::types::storage::Key,
    ) -> Result<Self::PrefixIter, storage_api::Error> {
        self.ctx.iter_prefix(prefix)
    }

    fn get_chain_id(&self) -> Result<String, storage_api::Error> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, storage_api::Error> {
        self.ctx.get_block_height()
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
    type PrefixIter = <DB as storage::DBIter<'a>>::PrefixIter;

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
        vp_env::read_temp(
            &mut *self.gas_meter.borrow_mut(),
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
        vp_env::read_temp(
            &mut *self.gas_meter.borrow_mut(),
            self.write_log,
            key,
        )
        .into_storage_result()
    }

    fn get_chain_id(&'view self) -> Result<String, storage_api::Error> {
        vp_env::get_chain_id(&mut *self.gas_meter.borrow_mut(), self.storage)
            .into_storage_result()
    }

    fn get_block_height(
        &'view self,
    ) -> Result<BlockHeight, storage_api::Error> {
        vp_env::get_block_height(
            &mut *self.gas_meter.borrow_mut(),
            self.storage,
        )
        .into_storage_result()
    }

    fn get_block_hash(&'view self) -> Result<BlockHash, storage_api::Error> {
        vp_env::get_block_hash(&mut *self.gas_meter.borrow_mut(), self.storage)
            .into_storage_result()
    }

    fn get_block_epoch(&'view self) -> Result<Epoch, storage_api::Error> {
        vp_env::get_block_epoch(&mut *self.gas_meter.borrow_mut(), self.storage)
            .into_storage_result()
    }

    fn get_tx_index(&'view self) -> Result<TxIndex, storage_api::Error> {
        vp_env::get_tx_index(&mut *self.gas_meter.borrow_mut(), self.tx_index)
            .into_storage_result()
    }

    fn get_native_token(&'view self) -> Result<Address, storage_api::Error> {
        vp_env::get_native_token(
            &mut *self.gas_meter.borrow_mut(),
            self.storage,
        )
        .into_storage_result()
    }

    fn iter_prefix(
        &'view self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter, storage_api::Error> {
        vp_env::iter_prefix(
            &mut *self.gas_meter.borrow_mut(),
            self.storage,
            prefix,
        )
        .into_storage_result()
    }

    fn rev_iter_prefix(
        &self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter, storage_api::Error> {
        vp_env::rev_iter_prefix(
            &mut *self.gas_meter.borrow_mut(),
            self.storage,
            prefix,
        )
        .into_storage_result()
    }

    fn eval(
        &self,
        vp_code: Vec<u8>,
        input_data: Vec<u8>,
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
                &mut *self.gas_meter.borrow_mut(),
                self.tx,
                self.tx_index,
                &mut iterators,
                self.verifiers,
                &mut result_buffer,
                self.keys_changed,
                &eval_runner,
                &mut vp_wasm_cache,
            );
            match eval_runner.eval_native_result(ctx, vp_code, input_data) {
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
            let _ = (vp_code, input_data);
            unimplemented!(
                "The \"wasm-runtime\" feature must be enabled to use the \
                 `eval` function."
            )
        }
    }

    fn verify_tx_signature(
        &self,
        pk: &crate::types::key::common::PublicKey,
        sig: &crate::types::key::common::Signature,
    ) -> Result<bool, storage_api::Error> {
        Ok(self.tx.verify_sig(pk, sig).is_ok())
    }

    fn verify_masp(&self, _tx: Vec<u8>) -> Result<bool, storage_api::Error> {
        unimplemented!("no masp native vp")
    }

    fn get_tx_code_hash(&self) -> Result<Hash, storage_api::Error> {
        vp_env::get_tx_code_hash(&mut *self.gas_meter.borrow_mut(), self.tx)
            .into_storage_result()
    }

    fn read_pre<T: borsh::BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.pre().read(key).map_err(Into::into)
    }

    fn read_bytes_pre(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.pre().read_bytes(key).map_err(Into::into)
    }

    fn read_post<T: borsh::BorshDeserialize>(
        &'view self,
        key: &Key,
    ) -> Result<Option<T>, storage_api::Error> {
        self.post().read(key).map_err(Into::into)
    }

    fn read_bytes_post(
        &'view self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, storage_api::Error> {
        self.post().read_bytes(key).map_err(Into::into)
    }

    fn has_key_pre(&'view self, key: &Key) -> Result<bool, storage_api::Error> {
        self.pre().has_key(key).map_err(Into::into)
    }

    fn has_key_post(
        &'view self,
        key: &Key,
    ) -> Result<bool, storage_api::Error> {
        self.post().has_key(key).map_err(Into::into)
    }

    fn iter_pre_next(
        &'view self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        self.pre().iter_next(iter).map_err(Into::into)
    }

    fn iter_post_next(
        &'view self,
        iter: &mut Self::PrefixIter,
    ) -> Result<Option<(String, Vec<u8>)>, storage_api::Error> {
        self.post().iter_next(iter).map_err(Into::into)
    }
}
