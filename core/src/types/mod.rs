//! Types definitions.

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
