//! Types for signing

use std::cmp::Ordering;

use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::address::Address;
use super::key::common;
use crate::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

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
