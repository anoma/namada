//! This crate contains library code for transaction WASM. Most of the code is
//! re-exported from the `namada_vm_env` crate.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod account;
pub mod ibc;
pub mod key;
pub mod pgf;
pub mod proof_of_stake;
pub mod token;

use core::slice;
use std::marker::PhantomData;

use masp_primitives::transaction::Transaction;
pub use namada_core::borsh::{
    BorshDeserialize, BorshSerialize, BorshSerializeExt,
};
pub use namada_core::ledger::eth_bridge;
use namada_core::types::account::AccountPublicKeysMap;
pub use namada_core::types::address::Address;
use namada_core::types::chain::CHAIN_ID_LENGTH;
pub use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::internal::HostEnvResult;
use namada_core::types::key::common;
use namada_core::types::storage::TxIndex;
pub use namada_core::types::storage::{
    self, BlockHash, BlockHeight, Epoch, Header, BLOCK_HASH_LENGTH,
};
pub use namada_core::types::{encode, eth_bridge_pool, *};
pub use namada_governance::storage as gov_storage;
pub use namada_macros::transaction;
pub use namada_parameters::storage as parameters_storage;
pub use namada_storage::{
    collections, iter_prefix, iter_prefix_bytes, Error, OptionExt, ResultExt,
    StorageRead, StorageWrite,
};
pub use namada_tx::{data as transaction, Section, Tx};
pub use namada_tx_env::TxEnv;
use namada_vm_env::tx::*;
use namada_vm_env::{read_from_buffer, read_key_val_bytes_from_buffer};
pub use {namada_governance as governance, namada_parameters as parameters};

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
#[derive(Debug, Clone)]
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

/// Result of `TxEnv`, `namada_storage::StorageRead` or
/// `namada_storage::StorageWrite` method call
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

    fn get_block_height(&self) -> Result<BlockHeight, Error> {
        Ok(BlockHeight(unsafe { namada_tx_get_block_height() }))
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, Error> {
        let read_result = unsafe { namada_tx_get_block_header(height.0) };
        match read_from_buffer(read_result, namada_tx_result_buffer) {
            Some(value) => Ok(Some(
                Header::try_from_slice(&value[..])
                    .expect("The conversion shouldn't fail"),
            )),
            None => Ok(None),
        }
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

    fn get_pred_epochs(
        &self,
    ) -> Result<namada_core::types::storage::Epochs, Error> {
        let read_result = unsafe { namada_tx_get_pred_epochs() };
        let bytes = read_from_buffer(read_result, namada_tx_result_buffer)
            .ok_or(Error::SimpleMessage(
                "Missing result from `namada_tx_get_pred_epochs` call",
            ))?;
        Ok(namada_core::types::decode(bytes)
            .expect("Cannot decode pred epochs"))
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

    fn get_tx_index(&self) -> Result<TxIndex, namada_storage::Error> {
        let tx_index = unsafe { namada_tx_get_tx_index() };
        Ok(TxIndex(tx_index))
    }
}

impl StorageWrite for Ctx {
    fn write_bytes(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> namada_storage::Result<()> {
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

    fn delete(&mut self, key: &storage::Key) -> namada_storage::Result<()> {
        let key = key.to_string();
        unsafe { namada_tx_delete(key.as_ptr() as _, key.len() as _) };
        Ok(())
    }
}

impl TxEnv for Ctx {
    fn write_temp<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<(), Error> {
        let buf = val.serialize_to_vec();
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
        code_hash: impl AsRef<[u8]>,
        code_tag: &Option<String>,
    ) -> Result<Address, Error> {
        let code_hash = code_hash.as_ref();
        let code_tag = code_tag.serialize_to_vec();
        let result = Vec::with_capacity(address::ESTABLISHED_ADDRESS_BYTES_LEN);
        unsafe {
            namada_tx_init_account(
                code_hash.as_ptr() as _,
                code_hash.len() as _,
                code_tag.as_ptr() as _,
                code_tag.len() as _,
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
        code_hash: impl AsRef<[u8]>,
        code_tag: &Option<String>,
    ) -> Result<(), Error> {
        let addr = addr.encode();
        let code_hash = code_hash.as_ref();
        let code_tag = code_tag.serialize_to_vec();
        unsafe {
            namada_tx_update_validity_predicate(
                addr.as_ptr() as _,
                addr.len() as _,
                code_hash.as_ptr() as _,
                code_hash.len() as _,
                code_tag.as_ptr() as _,
                code_tag.len() as _,
            )
        };
        Ok(())
    }

    fn emit_ibc_event(&mut self, event: &ibc::IbcEvent) -> Result<(), Error> {
        let event = borsh::to_vec(event).unwrap();
        unsafe {
            namada_tx_emit_ibc_event(event.as_ptr() as _, event.len() as _)
        };
        Ok(())
    }

    fn charge_gas(&mut self, used_gas: u64) -> Result<(), Error> {
        unsafe { namada_tx_charge_gas(used_gas) };
        Ok(())
    }

    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<ibc::IbcEvent>, Error> {
        let event_type = event_type.as_ref().to_string();
        let read_result = unsafe {
            namada_tx_get_ibc_events(
                event_type.as_ptr() as _,
                event_type.len() as _,
            )
        };
        match read_from_buffer(read_result, namada_tx_result_buffer) {
            Some(value) => Ok(Vec::<ibc::IbcEvent>::try_from_slice(&value[..])
                .expect("The conversion shouldn't fail")),
            None => Ok(Vec::new()),
        }
    }

    fn set_commitment_sentinel(&mut self) {
        unsafe { namada_tx_set_commitment_sentinel() }
    }
}

/// Execute IBC tx.
// Temp. workaround for <https://github.com/anoma/namada/issues/1831>
pub fn tx_ibc_execute() {
    unsafe { namada_tx_ibc_execute() }
}

/// Verify section signatures against the given list of keys
pub fn verify_signatures_of_pks(
    ctx: &Ctx,
    tx: &Tx,
    pks: Vec<common::PublicKey>,
) -> EnvResult<bool> {
    let max_signatures_per_transaction =
        parameters::max_signatures_per_transaction(ctx)?;

    // Require signatures from all the given keys
    let threshold = u8::try_from(pks.len()).into_storage_result()?;
    let public_keys_index_map = AccountPublicKeysMap::from_iter(pks);

    // Serialize parameters
    let max_signatures = max_signatures_per_transaction.serialize_to_vec();
    let public_keys_map = public_keys_index_map.serialize_to_vec();
    let targets = [tx.raw_header_hash()].serialize_to_vec();

    let valid = unsafe {
        namada_tx_verify_tx_section_signature(
            targets.as_ptr() as _,
            targets.len() as _,
            public_keys_map.as_ptr() as _,
            public_keys_map.len() as _,
            threshold,
            max_signatures.as_ptr() as _,
            max_signatures.len() as _,
        )
    };

    Ok(HostEnvResult::is_success(valid))
}

/// Update the masp note commitment tree in storage with the new notes
pub fn update_masp_note_commitment_tree(
    transaction: &Transaction,
) -> EnvResult<bool> {
    // Serialize transaction
    let transaction = transaction.serialize_to_vec();

    let valid = unsafe {
        namada_tx_update_masp_note_commitment_tree(
            transaction.as_ptr() as _,
            transaction.len() as _,
        )
    };

    Ok(HostEnvResult::is_success(valid))
}
