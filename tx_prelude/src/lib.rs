//! This crate contains library code for transaction WASM. Most of the code is
//! re-exported from the `namada_vm_env` crate.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod ibc;
pub mod key;
pub mod proof_of_stake;
pub mod token;

use core::slice;
use std::marker::PhantomData;

pub use borsh::{BorshDeserialize, BorshSerialize};
pub use namada_core::ledger::governance::storage as gov_storage;
pub use namada_core::ledger::parameters::storage as parameters_storage;
pub use namada_core::ledger::slash_fund::storage as slash_fund_storage;
pub use namada_core::ledger::storage::types::encode;
pub use namada_core::ledger::storage_api::{
    self, governance, iter_prefix, iter_prefix_bytes, Error, OptionExt,
    ResultExt, StorageRead, StorageWrite,
};
pub use namada_core::ledger::tx_env::TxEnv;
pub use namada_core::proto::{Signed, SignedTxData};
pub use namada_core::types::address::Address;
use namada_core::types::chain::CHAIN_ID_LENGTH;
use namada_core::types::internal::HostEnvResult;
use namada_core::types::storage::TxIndex;
pub use namada_core::types::storage::{
    self, BlockHash, BlockHeight, Epoch, BLOCK_HASH_LENGTH,
};
use namada_core::types::time::Rfc3339String;
pub use namada_core::types::*;
pub use namada_macros::transaction;
use namada_vm_env::tx::*;
use namada_vm_env::{read_from_buffer, read_key_val_bytes_from_buffer};

pub use crate::ibc::IbcActions;

/// Log a string. The message will be printed at the `tracing::Level::Info`.
pub fn log_string<T: AsRef<str>>(msg: T) {
    let msg = msg.as_ref();
    unsafe {
        namada_tx_log_string(msg.as_ptr() as _, msg.len() as _);
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

/// Execution context provides access to the host environment functions
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
    /// When using `#[transaction]` macro from `namada_macros`,
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
}

/// Result of `TxEnv`, `storage_api::StorageRead` or `storage_api::StorageWrite`
/// method call
pub type EnvResult<T> = Result<T, Error>;

/// Transaction result
pub type TxResult = EnvResult<()>;

#[derive(Debug)]
pub struct KeyValIterator<T>(pub u64, pub PhantomData<T>);

impl StorageRead for Ctx {
    type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)>;

    fn read_bytes(&self, key: &storage::Key) -> Result<Option<Vec<u8>>, Error> {
        let key = key.to_string();
        let read_result =
            unsafe { namada_tx_read(key.as_ptr() as _, key.len() as _) };
        Ok(read_from_buffer(read_result, namada_tx_result_buffer))
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool, Error> {
        let key = key.to_string();
        let found =
            unsafe { namada_tx_has_key(key.as_ptr() as _, key.len() as _) };
        Ok(HostEnvResult::is_success(found))
    }

    fn get_chain_id(&self) -> Result<String, Error> {
        let result = Vec::with_capacity(CHAIN_ID_LENGTH);
        unsafe {
            namada_tx_get_chain_id(result.as_ptr() as _);
        }
        let slice =
            unsafe { slice::from_raw_parts(result.as_ptr(), CHAIN_ID_LENGTH) };
        Ok(String::from_utf8(slice.to_vec())
            .expect("Cannot convert the ID string"))
    }

    fn get_block_header(
        &self,
    ) -> Result<namada_core::types::storage::Header, Error> {
        Ok(BlockHeight(unsafe { namada_tx_get_block_height() }))
    }

    fn get_block_height(
        &self,
    ) -> Result<namada_core::types::storage::BlockHeight, Error> {
        Ok(BlockHeight(unsafe { namada_tx_get_block_height() }))
    }

    fn get_block_hash(
        &self,
    ) -> Result<namada_core::types::storage::BlockHash, Error> {
        let result = Vec::with_capacity(BLOCK_HASH_LENGTH);
        unsafe {
            namada_tx_get_block_hash(result.as_ptr() as _);
        }
        let slice = unsafe {
            slice::from_raw_parts(result.as_ptr(), BLOCK_HASH_LENGTH)
        };
        Ok(BlockHash::try_from(slice).expect("Cannot convert the hash"))
    }

    fn get_block_epoch(
        &self,
    ) -> Result<namada_core::types::storage::Epoch, Error> {
        Ok(Epoch(unsafe { namada_tx_get_block_epoch() }))
    }

    /// Get the native token address
    fn get_native_token(&self) -> Result<Address, Error> {
        let result = Vec::with_capacity(address::ADDRESS_LEN);
        unsafe {
            namada_tx_get_native_token(result.as_ptr() as _);
        }
        let slice = unsafe {
            slice::from_raw_parts(result.as_ptr(), address::ADDRESS_LEN)
        };
        let address_str =
            std::str::from_utf8(slice).expect("Cannot decode native address");
        Ok(Address::decode(address_str).expect("Cannot decode native address"))
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, Error> {
        let prefix = prefix.to_string();
        let iter_id = unsafe {
            namada_tx_iter_prefix(prefix.as_ptr() as _, prefix.len() as _)
        };
        Ok(KeyValIterator(iter_id, PhantomData))
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let read_result = unsafe { namada_tx_iter_next(iter.0) };
        Ok(read_key_val_bytes_from_buffer(
            read_result,
            namada_tx_result_buffer,
        ))
    }

    fn get_tx_index(&self) -> Result<TxIndex, storage_api::Error> {
        let tx_index = unsafe { namada_tx_get_tx_index() };
        Ok(TxIndex(tx_index))
    }
}

impl StorageWrite for Ctx {
    fn write_bytes(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> storage_api::Result<()> {
        let key = key.to_string();
        unsafe {
            namada_tx_write(
                key.as_ptr() as _,
                key.len() as _,
                val.as_ref().as_ptr() as _,
                val.as_ref().len() as _,
            )
        };
        Ok(())
    }

    fn delete(&mut self, key: &storage::Key) -> storage_api::Result<()> {
        let key = key.to_string();
        unsafe { namada_tx_delete(key.as_ptr() as _, key.len() as _) };
        Ok(())
    }
}

impl TxEnv for Ctx {
    fn get_block_time(&self) -> Result<time::Rfc3339String, Error> {
        let read_result = unsafe { namada_tx_get_block_time() };
        let time_value = read_from_buffer(read_result, namada_tx_result_buffer)
            .expect("The block time should exist");
        Ok(Rfc3339String(
            String::try_from_slice(&time_value[..])
                .expect("The conversion shouldn't fail"),
        ))
    }

    fn write_temp<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<(), Error> {
        let buf = val.try_to_vec().unwrap();
        self.write_bytes_temp(key, buf)
    }

    fn write_bytes_temp(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.to_string();
        unsafe {
            namada_tx_write_temp(
                key.as_ptr() as _,
                key.len() as _,
                val.as_ref().as_ptr() as _,
                val.as_ref().len() as _,
            )
        };
        Ok(())
    }

    fn insert_verifier(&mut self, addr: &Address) -> Result<(), Error> {
        let addr = addr.encode();
        unsafe {
            namada_tx_insert_verifier(addr.as_ptr() as _, addr.len() as _)
        }
        Ok(())
    }

    fn init_account(
        &mut self,
        code: impl AsRef<[u8]>,
    ) -> Result<Address, Error> {
        let code = code.as_ref();
        let result = Vec::with_capacity(address::ESTABLISHED_ADDRESS_BYTES_LEN);
        unsafe {
            namada_tx_init_account(
                code.as_ptr() as _,
                code.len() as _,
                result.as_ptr() as _,
            )
        };
        let slice = unsafe {
            slice::from_raw_parts(
                result.as_ptr(),
                address::ESTABLISHED_ADDRESS_BYTES_LEN,
            )
        };
        Ok(Address::try_from_slice(slice)
            .expect("Decoding address created by the ledger shouldn't fail"))
    }

    fn update_validity_predicate(
        &mut self,
        addr: &Address,
        code: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let addr = addr.encode();
        let code = code.as_ref();
        unsafe {
            namada_tx_update_validity_predicate(
                addr.as_ptr() as _,
                addr.len() as _,
                code.as_ptr() as _,
                code.len() as _,
            )
        };
        Ok(())
    }

    fn emit_ibc_event(&mut self, event: &ibc::IbcEvent) -> Result<(), Error> {
        let event = BorshSerialize::try_to_vec(event).unwrap();
        unsafe {
            namada_tx_emit_ibc_event(event.as_ptr() as _, event.len() as _)
        };
        Ok(())
    }
}
