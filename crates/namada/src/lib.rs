//! The shared code for the Namada ledger, gossip and wasms.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub use namada_core::{
    address, chain, dec, decode, encode, eth_abi, eth_bridge_pool,
    ethereum_events, ethereum_structs, hash, internal, keccak, key, masp,
    storage, string_encoding, tendermint, tendermint_proto, time, uint,
    validity_predicate, voting_power,
};
pub use namada_sdk::{control_flow, io};
#[cfg(feature = "tendermint-rpc")]
pub use tendermint_rpc;
pub use {
    bip39, namada_account as account, namada_core as core,
    namada_ethereum_bridge as ethereum_bridge, namada_gas as gas,
    namada_governance as governance, namada_ibc as ibc,
    namada_parameters as parameters, namada_proof_of_stake as proof_of_stake,
    namada_replay_protection as replay_protection, namada_sdk as sdk,
    namada_state as state, namada_token as token, namada_tx as tx,
    namada_vote_ext as vote_ext,
};

pub mod ledger;
pub use namada_tx::proto;
pub mod vm;

pub mod eth_bridge {
    //! Namada Ethereum bridge re-exports.
    pub use ethers;
    pub use namada_core::ethereum_structs as structs;
    pub use namada_ethereum_bridge::*;
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
