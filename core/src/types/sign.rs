//! Types for signing

use std::cmp::Ordering;

use data_encoding::HEXUPPER;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::address::Address;
use super::key::common;
use crate::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum SigIndexDecodeError {
    #[error("Invalid signature index bytes: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Invalid signature index JSON string")]
    InvalidJsonString,
    #[error("Invalid signature index: {0}")]
    InvalidHex(data_encoding::DecodeError),
}

#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
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
                    .map_err(SigIndexDecodeError::InvalidEncoding),
                Err(e) => Err(SigIndexDecodeError::InvalidHex(e)),
            }
        } else {
            Err(SigIndexDecodeError::InvalidJsonString)
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
