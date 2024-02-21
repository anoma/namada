//! The core public types, storage_api, VpEnv and TxEnv.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod bytes;
pub mod event;
pub mod hints;
pub mod ledger;
pub mod types;

pub use {ibc, tendermint, tendermint_proto};
/// Borsh binary encoding (re-exported) from official crate with custom ext.
pub mod borsh {
    pub use borsh::*;
    pub use borsh_ext::*;
}
