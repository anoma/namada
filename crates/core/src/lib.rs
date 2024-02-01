//! The core public types, storage_api, VpEnv and TxEnv.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod bytes;
pub mod event;
pub mod hints;

pub use {masp_primitives, tendermint, tendermint_proto};
/// Borsh binary encoding (re-exported) from official crate with custom ext.
pub mod borsh {
    pub use borsh::*;
    pub use borsh_ext::*;
}

pub mod account;
pub mod address;
pub mod chain;
pub mod dec;
pub mod eth_abi;
pub mod eth_bridge_pool;
pub mod ethereum_events;
pub mod ethereum_structs;
pub mod hash;
pub mod ibc;
pub mod internal;
pub mod keccak;
pub mod key;
pub mod masp;
pub mod parameters;
pub mod sign;
pub mod storage;
pub mod string_encoding;
pub mod time;
pub mod token;
pub mod uint;
pub mod validity_predicate;
pub mod voting_power;

use borsh_ext::BorshSerializeExt;
use thiserror::Error;

use crate::borsh::{BorshDeserialize, BorshSerialize};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Deserialization error: {0}")]
    DeserializationError(std::io::Error),
}

/// Encode a value with borsh
pub fn encode<T>(value: &T) -> Vec<u8>
where
    T: BorshSerialize,
{
    value.serialize_to_vec()
}

/// Decode a value with borsh
pub fn decode<T>(bytes: impl AsRef<[u8]>) -> Result<T, DecodeError>
where
    T: BorshDeserialize,
{
    T::try_from_slice(bytes.as_ref()).map_err(DecodeError::DeserializationError)
}
