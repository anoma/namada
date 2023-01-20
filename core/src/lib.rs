//! The core public types, storage_api, VpEnv and TxEnv.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod bytes;
pub mod hints;
pub mod ledger;
pub mod proto;
pub mod types;

#[cfg(not(feature = "abcipp"))]
pub use {ibc, ibc_proto, tendermint, tendermint_proto};
#[cfg(feature = "abcipp")]
pub use {
    ibc_abcipp as ibc, ibc_proto_abcipp as ibc_proto,
    tendermint_abcipp as tendermint,
    tendermint_proto_abcipp as tendermint_proto,
};

// A handy macro for tests
#[cfg(test)]
#[macro_use]
extern crate assert_matches;
