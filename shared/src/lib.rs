//! The shared code for the Anoma ledger, gossip and wasms.

#![doc(html_favicon_url = "https://dev.anoma.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.anoma.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

#[cfg(feature = "abcipp")]
pub use {ibc_abcipp, ibc_proto_abcipp, tendermint_abcipp, tendermint_proto_abcipp};
#[cfg(feature = "abcipp")]
pub use {ibc, ibc_proto, tendermint, tendermint_proto};

pub mod bytes;
pub mod ledger;
pub mod proto;
pub mod types;
pub mod vm;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
