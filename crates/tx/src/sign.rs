//! Types for signing

use std::cmp::Ordering;
use std::io;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::key::common;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

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

    /// Serialize signature to pretty JSON into an I/O stream
    pub fn to_writer_json<W>(&self, writer: W) -> serde_json::Result<()>
    where
        W: io::Write,
    {
        serde_json::to_writer_pretty(writer, self)
    }

    /// Try to parse a signature from JSON string bytes
    pub fn try_from_json_bytes(
        bytes: &[u8],
    ) -> Result<SignatureIndex, serde_json::Error> {
        serde_json::from_slice::<SignatureIndex>(bytes)
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

#[cfg(test)]
mod test {
    use namada_core::key::SigScheme;
    use namada_core::{address, key};

    use super::*;

    #[test]
    fn test_signature_serialization() {
        let sk = key::testing::keypair_1();
        let pubkey = sk.to_public();
        let data = [0_u8];
        let signature = key::common::SigScheme::sign(&sk, &data);
        let sig_index = SignatureIndex {
            pubkey,
            index: Some((address::testing::established_address_1(), 1)),
            signature,
        };

        let mut buffer = vec![];
        sig_index.to_writer_json(&mut buffer).unwrap();

        let deserialized =
            SignatureIndex::try_from_json_bytes(&buffer).unwrap();
        assert_eq!(sig_index, deserialized);
    }
}
