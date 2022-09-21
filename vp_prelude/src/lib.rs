//! This crate contains library code for validity predicate WASM. Most of the
//! code is re-exported from the `namada_vm_env` crate.

#![doc(html_favicon_url = "https://dev.anoma.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.anoma.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

use core::convert::AsRef;

use namada_vm_env::vp_prelude::hash::Hash;
pub use namada_vm_env::vp_prelude::*;
pub use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn sha256(bytes: &[u8]) -> Hash {
    let digest = Sha256::digest(bytes);
    Hash(*digest.as_ref())
}

pub fn is_tx_whitelisted() -> bool {
    let tx_hash = get_tx_code_hash();
    let key = parameters::storage::get_tx_whitelist_storage_key();
    let whitelist: Vec<String> = read_pre(&key.to_string()).unwrap_or_default();
    // if whitelist is empty, allow any transaction
    whitelist.is_empty() || whitelist.contains(&tx_hash.to_string())
}

pub fn is_vp_whitelisted(vp_bytes: &[u8]) -> bool {
    let vp_hash = sha256(vp_bytes);
    let key = parameters::storage::get_vp_whitelist_storage_key();
    let whitelist: Vec<String> = read_pre(&key.to_string()).unwrap_or_default();
    // if whitelist is empty, allow any transaction
    whitelist.is_empty() || whitelist.contains(&vp_hash.to_string())
}

/// Checks if a proposal id is being executed
pub fn is_proposal_accepted(proposal_id: u64) -> bool {
    let proposal_execution_key =
        gov_storage::get_proposal_execution_key(proposal_id);

    has_key_pre(&proposal_execution_key.to_string())
}

/// Checks whether a transaction is valid, which happens in two cases:
/// - tx is whitelisted, or
/// - tx is executed by an approved governance proposal (no need to be whitelisted)
pub fn is_valid_tx(tx_data: &[u8]) -> bool {
    if is_tx_whitelisted() {
        return true
    } else {
        let proposal_id = u64::try_from_slice(tx_data).ok();

        proposal_id.map_or(false, |id| is_proposal_accepted(id))
    }
}

/// Log a string in a debug build. The message will be printed at the
/// `tracing::Level::Info`. Any `debug_log!` statements are only enabled in
/// non optimized builds by default. An optimized build will not execute
/// `debug_log!` statements unless `-C debug-assertions` is passed to the
/// compiler.
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {{
        (if cfg!(debug_assertions) { log_string(format!($($arg)*)) })
    }}
}
