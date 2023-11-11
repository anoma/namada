//! The shared code for the Namada ledger, gossip and wasms.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub use namada_core::{ibc, ibc_proto, tendermint, tendermint_proto};
#[cfg(feature = "tendermint-rpc")]
pub use tendermint_rpc;
pub use {bip39, namada_core as core, namada_proof_of_stake as proof_of_stake};
pub mod ledger;
pub use namada_core::proto;
pub use namada_sdk;
pub mod types;
pub mod vm;

pub mod eth_bridge {
    //! Namada Ethereum bridge re-exports.
    pub use ethers;
    pub use namada_core::types::ethereum_structs as structs;
    pub use namada_ethereum_bridge::*;
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
