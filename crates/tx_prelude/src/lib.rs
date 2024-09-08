//! This crate contains library code for transaction WASM.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

pub mod account;
pub mod ibc;
pub mod key;
pub mod pgf;
pub mod proof_of_stake;
pub mod token;

use namada_account::AccountPublicKeysMap;
pub use namada_governance::storage as gov_storage;
pub use namada_macros::transaction;
pub use namada_parameters::storage as parameters_storage;
use namada_token::MaspTransaction;
pub use namada_tx_env::ctx::*;
pub use namada_tx_env::{debug_log, TxEnv};
use namada_vm_env::tx::{
    namada_tx_update_masp_note_commitment_tree,
    namada_tx_verify_tx_section_signature,
};
use namada_vm_env::HostEnvResult;
pub use proof_of_stake::PosCtxExt;
pub use {
    namada_gas as gas, namada_governance as governance,
    namada_parameters as parameters,
};

/// Verify section signatures against the given list of keys
pub fn verify_signatures_of_pks(
    tx: &Tx,
    pks: Vec<common::PublicKey>,
) -> Result<bool> {
    // Require signatures from all the given keys
    let threshold = u8::try_from(pks.len()).into_storage_result()?;
    let public_keys_index_map = AccountPublicKeysMap::from_iter(pks);

    // Serialize parameters
    let public_keys_map = public_keys_index_map.serialize_to_vec();
    let targets = [tx.raw_header_hash()].serialize_to_vec();

    let valid = unsafe {
        namada_tx_verify_tx_section_signature(
            targets.as_ptr() as _,
            targets.len() as _,
            public_keys_map.as_ptr() as _,
            public_keys_map.len() as _,
            threshold,
        )
    };

    Ok(HostEnvResult::is_success(valid))
}
/// Update the masp note commitment tree in storage with the new notes
pub fn update_masp_note_commitment_tree(
    transaction: &MaspTransaction,
) -> Result<bool> {
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
