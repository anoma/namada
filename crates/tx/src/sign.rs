//! Types for signing

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::io;
use std::marker::PhantomData;

use borsh::schema::{self, Declaration, Definition};
use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::key::{SerializeWithBorsh, SigScheme, Signable, common};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Represents an error in signature verification
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum VerifySigError {
    #[error("{0}")]
    VerifySig(#[from] namada_core::key::VerifySigError),
    #[error("{0}")]
    Gas(#[from] namada_gas::Error),
    #[error("The wrapper signature is invalid.")]
    InvalidWrapperSignature,
    #[error("The section signature is invalid: {0}")]
    InvalidSectionSignature(String),
    #[error("The number of PKs overflows u8::MAX")]
    PksOverflow,
    #[error("Authorization contains repeated public keys")]
    RepeatedPks,
    #[error("An expected signature is missing.")]
    MissingSignature,
}

/// A generic signed data wrapper for serialize-able types.
///
/// The default serialization method is [`BorshSerialize`].
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Signed<T, S = SerializeWithBorsh> {
    /// Arbitrary data to be signed
    pub data: T,
    /// The signature of the data
    pub sig: common::Signature,
    /// The method to serialize the data with,
    /// before it being signed
    _serialization: PhantomData<S>,
}

impl<S, T: Eq> Eq for Signed<T, S> {}

impl<S, T: PartialEq> PartialEq for Signed<T, S> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.sig == other.sig
    }
}

impl<S, T: Hash> Hash for Signed<T, S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.sig.hash(state);
    }
}

impl<S, T: PartialOrd> PartialOrd for Signed<T, S> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.data.partial_cmp(&other.data)
    }
}
impl<S, T: Ord> Ord for Signed<T, S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.cmp(&other.data)
    }
}

impl<S, T: BorshSchema> BorshSchema for Signed<T, S> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        let fields = schema::Fields::NamedFields(vec![
            ("data".to_string(), T::declaration()),
            ("sig".to_string(), <common::Signature>::declaration()),
        ]);
        let definition = schema::Definition::Struct { fields };
        schema::add_definition(Self::declaration(), definition, definitions);
        T::add_definitions_recursively(definitions);
        <common::Signature>::add_definitions_recursively(definitions);
    }

    fn declaration() -> schema::Declaration {
        format!("Signed<{}>", T::declaration())
    }
}

impl<T, S> Signed<T, S> {
    /// Initialize a new [`Signed`] instance from an existing signature.
    #[inline]
    pub fn new_from(data: T, sig: common::Signature) -> Self {
        Self {
            data,
            sig,
            _serialization: PhantomData,
        }
    }
}

impl<T, S: Signable<T>> Signed<T, S> {
    /// Initialize a new [`Signed`] instance.
    pub fn new(keypair: &common::SecretKey, data: T) -> Self {
        let to_sign = S::as_signable(&data);
        let sig =
            common::SigScheme::sign_with_hasher::<S::Hasher>(keypair, to_sign);
        Self::new_from(data, sig)
    }

    /// Verify that the data has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify(
        &self,
        pk: &common::PublicKey,
    ) -> std::result::Result<(), VerifySigError> {
        let signed_bytes = S::as_signable(&self.data);
        common::SigScheme::verify_signature_with_hasher::<S::Hasher>(
            pk,
            &signed_bytes,
            &self.sig,
        )
        .map_err(Into::into)
    }
}

/// Get a signature for data
pub fn standalone_signature<T, S: Signable<T>>(
    keypair: &common::SecretKey,
    data: &T,
) -> common::Signature {
    let to_sign = S::as_signable(data);
    common::SigScheme::sign_with_hasher::<S::Hasher>(keypair, to_sign)
}

/// Verify that the input data has been signed by the secret key
/// counterpart of the given public key.
pub fn verify_standalone_sig<T, S: Signable<T>>(
    data: &T,
    pk: &common::PublicKey,
    sig: &common::Signature,
) -> std::result::Result<(), VerifySigError> {
    let signed_data = S::as_signable(data);
    common::SigScheme::verify_signature_with_hasher::<S::Hasher>(
        pk,
        &signed_data,
        sig,
    )
    .map_err(Into::into)
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
    use assert_matches::assert_matches;
    use namada_core::key::SigScheme;
    use namada_core::{address, key};

    use super::*;

    #[test]
    fn test_signature_serialization() {
        let sk = key::testing::keypair_1();
        let pubkey = sk.to_public();
        let data = [0_u8];
        let signature = key::common::SigScheme::sign(&sk, data);
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

    #[test]
    fn test_standalone_signing() {
        let sk1 = key::testing::keypair_1();
        let sk2 = key::testing::keypair_2();
        let data = vec![30_u8, 1, 5];
        let sig =
            standalone_signature::<Vec<u8>, SerializeWithBorsh>(&sk1, &data);

        assert_matches!(
            verify_standalone_sig::<Vec<u8>, SerializeWithBorsh>(
                &data,
                &sk1.to_public(),
                &sig
            ),
            Ok(())
        );

        let wrong_sig =
            standalone_signature::<Vec<u8>, SerializeWithBorsh>(&sk2, &data);
        assert_matches!(
            verify_standalone_sig::<Vec<u8>, SerializeWithBorsh>(
                &data,
                &sk1.to_public(),
                &wrong_sig
            ),
            Err(VerifySigError::VerifySig(_))
        );
    }
}
