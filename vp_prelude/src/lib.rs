//! This crate contains library code for validity predicate WASM. Most of the
//! code is re-exported from the `namada_vm_env` crate.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod ibc {
    pub use namada_core::types::ibc::IbcEvent;
    pub use namada_ibc::storage::is_ibc_key;
}

// used in the VP input
use core::convert::AsRef;
use core::slice;
pub use std::collections::{BTreeSet, HashSet};
use std::convert::TryFrom;
use std::marker::PhantomData;

pub use namada_core::borsh::{
    BorshDeserialize, BorshSerialize, BorshSerializeExt,
};
pub use namada_core::types::address::Address;
use namada_core::types::chain::CHAIN_ID_LENGTH;
use namada_core::types::hash::{Hash, HASH_LENGTH};
use namada_core::types::internal::HostEnvResult;
use namada_core::types::storage::{
    BlockHash, BlockHeight, Epoch, Header, TxIndex, BLOCK_HASH_LENGTH,
};
pub use namada_core::types::*;
pub use namada_governance::pgf::storage as pgf_storage;
pub use namada_governance::storage as gov_storage;
pub use namada_macros::validity_predicate;
pub use namada_storage::{
    iter_prefix, iter_prefix_bytes, Error, OptionExt, ResultExt, StorageRead,
};
pub use namada_tx::{Section, Tx};
use namada_vm_env::vp::*;
use namada_vm_env::{read_from_buffer, read_key_val_bytes_from_buffer};
pub use namada_vp_env::{collection_validation, VpEnv};
pub use sha2::{Digest, Sha256, Sha384, Sha512};
pub use {
    namada_account as account, namada_parameters as parameters,
    namada_proof_of_stake as proof_of_stake, namada_token as token,
};

pub fn sha256(bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(bytes);
    Hash(*digest.as_ref())
}

pub fn is_tx_whitelisted(ctx: &Ctx) -> VpResult {
    let tx_hash = ctx.get_tx_code_hash()?;
    let key = parameters::storage::get_tx_whitelist_storage_key();
    let whitelist: Vec<String> = ctx.read_pre(&key)?.unwrap_or_default();
    // if whitelist is empty, allow any transaction
    Ok(whitelist.is_empty()
        || (tx_hash.is_some()
            && whitelist
                .contains(&tx_hash.unwrap().to_string().to_lowercase())))
}

pub fn is_vp_whitelisted(ctx: &Ctx, vp_hash: &[u8]) -> VpResult {
    let vp_hash = Hash::try_from(vp_hash).unwrap();
    let key = parameters::storage::get_vp_whitelist_storage_key();
    let whitelist: Vec<String> = ctx.read_pre(&key)?.unwrap_or_default();
    // if whitelist is empty, allow any transaction
    Ok(whitelist.is_empty()
        || whitelist.contains(&vp_hash.to_string().to_lowercase()))
}

/// Log a string. The message will be printed at the `tracing::Level::Info`.
pub fn log_string<T: AsRef<str>>(msg: T) {
    let msg = msg.as_ref();
    unsafe {
        namada_vp_log_string(msg.as_ptr() as _, msg.len() as _);
    }
}

/// Checks if a proposal id is being executed
pub fn is_proposal_accepted(ctx: &Ctx, proposal_id: u64) -> VpResult {
    let proposal_execution_key =
        gov_storage::keys::get_proposal_execution_key(proposal_id);

    ctx.has_key_pre(&proposal_execution_key)
}

/// Verify section signatures
pub fn verify_signatures(ctx: &Ctx, tx: &Tx, owner: &Address) -> VpResult {
    let max_signatures_per_transaction =
        parameters::max_signatures_per_transaction(&ctx.pre())?;

    let public_keys_index_map =
        account::public_keys_index_map(&ctx.pre(), owner)?;
    let threshold = account::threshold(&ctx.pre(), owner)?.unwrap_or(1);

    // Serialize parameters
    let max_signatures = max_signatures_per_transaction.serialize_to_vec();
    let public_keys_map = public_keys_index_map.serialize_to_vec();
    let targets = [tx.raw_header_hash()].serialize_to_vec();
    let signer = owner.serialize_to_vec();

    let valid = unsafe {
        namada_vp_verify_tx_section_signature(
            targets.as_ptr() as _,
            targets.len() as _,
            public_keys_map.as_ptr() as _,
            public_keys_map.len() as _,
            signer.as_ptr() as _,
            signer.len() as _,
            threshold,
            max_signatures.as_ptr() as _,
            max_signatures.len() as _,
        )
    };

    Ok(HostEnvResult::is_success(valid))
}

/// Checks whether a transaction is valid, which happens in two cases:
/// - tx is whitelisted, or
/// - tx is executed by an approved governance proposal (no need to be
///   whitelisted)
pub fn is_valid_tx(ctx: &Ctx, tx_data: &Tx) -> VpResult {
    if is_tx_whitelisted(ctx)? {
        accept()
    } else {
        let proposal_id = tx_data
            .data()
            .as_ref()
            .and_then(|x| u64::try_from_slice(x).ok());

        proposal_id.map_or(reject(), |id| is_proposal_accepted(ctx, id))
    }
}

/// Format and log a string in a debug build.
///
/// In WASM target debug build, the message will be printed at the
/// `tracing::Level::Info` when executed in the VM. An optimized build will
/// omit any `debug_log!` statements unless `-C debug-assertions` is passed to
/// the compiler.
///
/// In non-WASM target, the message is simply printed out to stdout.
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {{
        (
            if cfg!(target_arch = "wasm32") {
                if cfg!(debug_assertions)
                {
                    log_string(format!($($arg)*));
                }
            } else {
                println!($($arg)*);
            }
        )
    }};
}

#[derive(Debug)]
pub struct Ctx(());

impl Ctx {
    /// Create a host context. The context on WASM side is only provided by
    /// the VM once its being executed (in here it's implicit). But
    /// because we want to have interface identical with the native
    /// VPs, in which the context is explicit, in here we're just
    /// using an empty `Ctx` to "fake" it.
    ///
    /// # Safety
    ///
    /// When using `#[validity_predicate]` macro from `namada_macros`,
    /// the constructor should not be called from transactions and validity
    /// predicates implementation directly - they receive `&Self` as
    /// an argument provided by the macro that wrap the low-level WASM
    /// interface with Rust native types.
    ///
    /// Otherwise, this should only be called once to initialize this "fake"
    /// context in order to benefit from type-safety of the host environment
    /// methods implemented on the context.
    #[allow(clippy::new_without_default)]
    pub const unsafe fn new() -> Self {
        Self(())
    }

    /// Read access to the prior storage (state before tx execution)
    /// via [`trait@StorageRead`].
    pub fn pre(&self) -> CtxPreStorageRead<'_> {
        CtxPreStorageRead { _ctx: self }
    }

    /// Read access to the posterior storage (state after tx execution)
    /// via [`trait@StorageRead`].
    pub fn post(&self) -> CtxPostStorageRead<'_> {
        CtxPostStorageRead { _ctx: self }
    }
}

/// Read access to the prior storage (state before tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPreStorageRead<'a> {
    _ctx: &'a Ctx,
}

/// Read access to the posterior storage (state after tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPostStorageRead<'a> {
    _ctx: &'a Ctx,
}

/// Result of `VpEnv` or `namada_storage::StorageRead` method call
pub type EnvResult<T> = Result<T, Error>;

/// Validity predicate result
pub type VpResult = EnvResult<bool>;

/// Accept a transaction
pub fn accept() -> VpResult {
    Ok(true)
}

/// Reject a transaction
pub fn reject() -> VpResult {
    Ok(false)
}

#[derive(Debug)]
pub struct KeyValIterator<T>(pub u64, pub PhantomData<T>);

impl<'view> VpEnv<'view> for Ctx {
    type Post = CtxPostStorageRead<'view>;
    type Pre = CtxPreStorageRead<'view>;
    type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)>;

    fn pre(&'view self) -> Self::Pre {
        CtxPreStorageRead { _ctx: self }
    }

    fn post(&'view self) -> Self::Post {
        CtxPostStorageRead { _ctx: self }
    }

    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_temp(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer)
            .and_then(|t| T::try_from_slice(&t[..]).ok()))
    }

    fn read_bytes_temp(
        &self,
        key: &storage::Key,
    ) -> Result<Option<Vec<u8>>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_temp(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer))
    }

    fn get_chain_id(&self) -> Result<String, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_block_header(height)
    }

    fn get_block_hash(&self) -> Result<BlockHash, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_block_hash()
    }

    fn get_block_epoch(&self) -> Result<Epoch, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex, Error> {
        get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address, Error> {
        // Both `CtxPreStorageRead` and `CtxPostStorageRead` have the same impl
        get_native_token()
    }

    fn get_ibc_events(
        &self,
        event_type: String,
    ) -> Result<Vec<ibc::IbcEvent>, Error> {
        let read_result = unsafe {
            namada_vp_get_ibc_events(
                event_type.as_ptr() as _,
                event_type.len() as _,
            )
        };
        match read_from_buffer(read_result, namada_vp_result_buffer) {
            Some(value) => Ok(Vec::<ibc::IbcEvent>::try_from_slice(&value[..])
                .expect("The conversion shouldn't fail")),
            None => Ok(Vec::new()),
        }
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, Error> {
        iter_prefix_pre_impl(prefix)
    }

    fn eval(&self, vp_code_hash: Hash, input_data: Tx) -> Result<bool, Error> {
        let input_data_bytes = borsh::to_vec(&input_data).unwrap();
        let result = unsafe {
            namada_vp_eval(
                vp_code_hash.0.as_ptr() as _,
                vp_code_hash.0.len() as _,
                input_data_bytes.as_ptr() as _,
                input_data_bytes.len() as _,
            )
        };
        Ok(HostEnvResult::is_success(result))
    }

    fn get_tx_code_hash(&self) -> Result<Option<Hash>, Error> {
        let result = Vec::with_capacity(HASH_LENGTH + 1);
        unsafe {
            namada_vp_get_tx_code_hash(result.as_ptr() as _);
        }
        let slice =
            unsafe { slice::from_raw_parts(result.as_ptr(), HASH_LENGTH + 1) };
        Ok(if slice[0] == 1 {
            Some(Hash(
                slice[1..HASH_LENGTH + 1]
                    .try_into()
                    .expect("Cannot convert the hash"),
            ))
        } else {
            None
        })
    }

    fn charge_gas(&self, used_gas: u64) -> Result<(), Error> {
        unsafe { namada_vp_charge_gas(used_gas) };
        Ok(())
    }

    fn get_pred_epochs(&self) -> namada_storage::Result<storage::Epochs> {
        todo!()
    }
}

impl StorageRead for CtxPreStorageRead<'_> {
    type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)> where Self: 'iter;

    fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_pre(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer))
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool, Error> {
        let key = key.to_string();
        let found =
            unsafe { namada_vp_has_key_pre(key.as_ptr() as _, key.len() as _) };
        Ok(HostEnvResult::is_success(found))
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, Error> {
        iter_prefix_pre_impl(prefix)
    }

    // ---- Methods below share the same implementation in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let read_result = unsafe { namada_vp_iter_next(iter.0) };
        Ok(read_key_val_bytes_from_buffer(
            read_result,
            namada_vp_result_buffer,
        ))
    }

    fn get_chain_id(&self) -> Result<String, Error> {
        get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, Error> {
        get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, Error> {
        get_block_header(height)
    }

    fn get_block_hash(&self) -> Result<BlockHash, Error> {
        get_block_hash()
    }

    fn get_block_epoch(&self) -> Result<Epoch, Error> {
        get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex, Error> {
        get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address, Error> {
        get_native_token()
    }

    fn get_pred_epochs(&self) -> namada_storage::Result<storage::Epochs> {
        todo!()
    }
}

impl StorageRead for CtxPostStorageRead<'_> {
    type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)> where Self:'iter;

    fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_vp_read_post(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_vp_result_buffer))
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool, Error> {
        let key = key.to_string();
        let found = unsafe {
            namada_vp_has_key_post(key.as_ptr() as _, key.len() as _)
        };
        Ok(HostEnvResult::is_success(found))
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, Error> {
        iter_prefix_post_impl(prefix)
    }

    // ---- Methods below share the same implementation in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let read_result = unsafe { namada_vp_iter_next(iter.0) };
        Ok(read_key_val_bytes_from_buffer(
            read_result,
            namada_vp_result_buffer,
        ))
    }

    fn get_chain_id(&self) -> Result<String, Error> {
        get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, Error> {
        get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, Error> {
        get_block_header(height)
    }

    fn get_block_hash(&self) -> Result<BlockHash, Error> {
        get_block_hash()
    }

    fn get_block_epoch(&self) -> Result<Epoch, Error> {
        get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex, Error> {
        get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address, Error> {
        get_native_token()
    }

    fn get_pred_epochs(&self) -> namada_storage::Result<storage::Epochs> {
        todo!()
    }
}

fn iter_prefix_pre_impl(
    prefix: &storage::Key,
) -> Result<KeyValIterator<(String, Vec<u8>)>, Error> {
    let prefix = prefix.to_string();
    let iter_id = unsafe {
        namada_vp_iter_prefix_pre(prefix.as_ptr() as _, prefix.len() as _)
    };
    Ok(KeyValIterator(iter_id, PhantomData))
}

fn iter_prefix_post_impl(
    prefix: &storage::Key,
) -> Result<KeyValIterator<(String, Vec<u8>)>, Error> {
    let prefix = prefix.to_string();
    let iter_id = unsafe {
        namada_vp_iter_prefix_post(prefix.as_ptr() as _, prefix.len() as _)
    };
    Ok(KeyValIterator(iter_id, PhantomData))
}

fn get_chain_id() -> Result<String, Error> {
    let result = Vec::with_capacity(CHAIN_ID_LENGTH);
    unsafe {
        namada_vp_get_chain_id(result.as_ptr() as _);
    }
    let slice =
        unsafe { slice::from_raw_parts(result.as_ptr(), CHAIN_ID_LENGTH) };
    Ok(
        String::from_utf8(slice.to_vec())
            .expect("Cannot convert the ID string"),
    )
}

fn get_block_height() -> Result<BlockHeight, Error> {
    Ok(BlockHeight(unsafe { namada_vp_get_block_height() }))
}

fn get_block_header(height: BlockHeight) -> Result<Option<Header>, Error> {
    let read_result = unsafe { namada_vp_get_block_header(height.0) };
    match read_from_buffer(read_result, namada_vp_result_buffer) {
        Some(value) => Ok(Some(
            Header::try_from_slice(&value[..])
                .expect("The conversion shouldn't fail"),
        )),
        None => Ok(None),
    }
}

fn get_block_hash() -> Result<BlockHash, Error> {
    let result = Vec::with_capacity(BLOCK_HASH_LENGTH);
    unsafe {
        namada_vp_get_block_hash(result.as_ptr() as _);
    }
    let slice =
        unsafe { slice::from_raw_parts(result.as_ptr(), BLOCK_HASH_LENGTH) };
    Ok(BlockHash::try_from(slice).expect("Cannot convert the hash"))
}

fn get_block_epoch() -> Result<Epoch, Error> {
    Ok(Epoch(unsafe { namada_vp_get_block_epoch() }))
}

fn get_tx_index() -> Result<TxIndex, Error> {
    Ok(TxIndex(unsafe { namada_vp_get_tx_index() }))
}

fn get_native_token() -> Result<Address, Error> {
    let result = Vec::with_capacity(address::ADDRESS_LEN);
    unsafe {
        namada_vp_get_native_token(result.as_ptr() as _);
    }
    let slice =
        unsafe { slice::from_raw_parts(result.as_ptr(), address::ADDRESS_LEN) };
    let address_str =
        std::str::from_utf8(slice).expect("Cannot decode native address");
    Ok(Address::decode(address_str).expect("Cannot decode native address"))
}
