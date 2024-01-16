//! Shared code for the node, client etc.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

#[cfg(feature = "testing")]
pub mod bench_utils;
pub mod cli;
pub mod client;
pub mod config;
pub mod logging;
pub mod node;
pub mod wallet;
pub mod wasm_loader;

// This is here only to include the std's docs in our docs.
// Taken from <https://github.com/rust-lang/rfcs/issues/2324#issuecomment-502437904>.
#[doc(inline)]
pub use std;

pub mod facade {
    // TODO: re-import v0_37 only
    pub use namada::{tendermint, tendermint_proto, tendermint_rpc};
    pub use tendermint_config;
    pub mod tower_abci {
        pub use tower_abci::v037::*;
        pub use tower_abci::BoxError;
    }
}
