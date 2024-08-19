//! Types for signing

use std::cmp::Ordering;

use data_encoding::HEXUPPER;
use namada_core::address::Address;
use namada_core::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::key::common;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum SigIndexDecodeError {
    #[error("Invalid signature index bytes: {0}")]
    Encoding(std::io::Error),
    #[error("Invalid signature index JSON string")]
    JsonString,
    #[error("Invalid signature index: {0}")]
    Hex(data_encoding::DecodeError),
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
)]
/// Signature index within a multisig
pub struct SignatureIndex {
    /// PK that can be used to verify signature
    pub pubkey: common::PublicKey,
    /// Index in multisig
    pub index: Option<(Address, u8)>,
    /// Signature
    pub signature: common::Signature,
}

impl SignatureIndex {
    /// Instantiate from a single signature and a matching PK.
    pub fn from_single_signature(
        pubkey: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self {
            pubkey,
            signature,
            index: None,
        }
    }

    /// Convert to a vector
    pub fn to_vec(&self) -> Vec<Self> {
        vec![self.clone()]
    }

    /// Serialize as a string.
    pub fn serialize(&self) -> String {
        let signature_bytes = self.serialize_to_vec();
        HEXUPPER.encode(&signature_bytes)
    }

    /// Deserialize from a string slice
    pub fn deserialize(data: &[u8]) -> Result<Self, SigIndexDecodeError> {
        if let Ok(hex) = serde_json::from_slice::<String>(data) {
            match HEXUPPER.decode(hex.as_bytes()) {
                Ok(bytes) => Self::try_from_slice(&bytes)
                    .map_err(SigIndexDecodeError::Encoding),
                Err(e) => Err(SigIndexDecodeError::Hex(e)),
            }
        } else {
            Err(SigIndexDecodeError::JsonString)
        }
    }
}

impl Ord for SignatureIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pubkey.cmp(&other.pubkey)
    }
}

impl PartialOrd for SignatureIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
