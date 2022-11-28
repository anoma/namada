//! The shared code for the Anoma ledger, gossip and wasms.

#![doc(html_favicon_url = "https://dev.anoma.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.anoma.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

#[cfg(feature = "tendermint-rpc")]
pub use tendermint_rpc;
#[cfg(feature = "tendermint-rpc-abcipp")]
pub use tendermint_rpc_abcipp as tendermint_rpc;
#[cfg(not(feature = "abcipp"))]
pub use {ibc, ibc_proto, tendermint, tendermint_proto};
#[cfg(feature = "abcipp")]
pub use {
    ibc_abcipp as ibc, ibc_proto_abcipp as ibc_proto,
    tendermint_abcipp as tendermint,
    tendermint_proto_abcipp as tendermint_proto,
};
pub use {namada_core as core, namada_proof_of_stake as proof_of_stake};
pub mod ledger;
pub use namada_core::proto;
pub mod types;
pub mod vm;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
