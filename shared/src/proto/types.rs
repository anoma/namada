use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use borsh::schema::{Declaration, Definition};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::generated::types;
use crate::types::key::*;
use crate::types::time::DateTimeUtc;
use crate::types::transaction::hash_tx;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Error decoding an IntentGossipMessage from bytes: {0}")]
    IntentDecodingError(prost::DecodeError),
    #[error("Error decoding an DkgGossipMessage from bytes: {0}")]
    DkgDecodingError(prost::DecodeError),
    #[error("Intent is empty")]
    NoIntentError,
    #[error("Dkg is empty")]
    NoDkgError,
    #[error("Timestamp is empty")]
    NoTimestampError,
    #[error("Timestamp is invalid: {0}")]
    InvalidTimestamp(prost_types::TimestampOutOfSystemRangeError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// This can be used to sign an arbitrary tx. The signature is produced and
/// verified on the tx data concatenated with the tx code, however the tx code
/// itself is not part of this structure.
///
/// Because the signature is not checked by the ledger, we don't inline it into
/// the `Tx` type directly. Instead, the signature is attached to the `tx.data`,
/// which is can then be checked by a validity predicate wasm.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct SignedTxData {
    /// The original tx data bytes, if any
    pub data: Option<Vec<u8>>,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: common::Signature,
}

/// A serialization method to provide to [`Signed`], such
/// that we may sign serialized data.
pub trait SignedSerialize<T> {
    /// A byte vector containing the serialized data.
    type Output: AsRef<[u8]>;

    /// Encodes `data` as a byte vector,
    /// with some arbitrary serialization method.
    fn serialize(data: &T) -> Self::Output;
}

/// Tag type that indicates we should use [`BorshSerialize`]
/// to sign data in a [`Signed`] wrapper.
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct SerializeWithBorsh;

impl<T: BorshSerialize> SignedSerialize<T> for SerializeWithBorsh {
    type Output = Vec<u8>;

    fn serialize(data: &T) -> Vec<u8> {
        data.try_to_vec()
            .expect("Encoding data for signing shouldn't fail")
    }
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

impl<S, T: BorshSchema> BorshSchema for Signed<T, S> {
    fn add_definitions_recursively(
        definitions: &mut HashMap<Declaration, Definition>,
    ) {
        let fields = borsh::schema::Fields::NamedFields(borsh::maybestd::vec![
            ("data".to_string(), T::declaration()),
            ("sig".to_string(), <common::Signature>::declaration())
        ]);
        let definition = borsh::schema::Definition::Struct { fields };
        Self::add_definition(Self::declaration(), definition, definitions);
        T::add_definitions_recursively(definitions);
        <common::Signature>::add_definitions_recursively(definitions);
    }

    fn declaration() -> borsh::schema::Declaration {
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

impl<T, S: SignedSerialize<T>> Signed<T, S> {
    /// Initialize a new [`Signed`] instance.
    pub fn new(keypair: &common::SecretKey, data: T) -> Self {
        let to_sign = S::serialize(&data);
        let sig = common::SigScheme::sign(keypair, to_sign.as_ref());
        Self::new_from(data, sig)
    }

    /// Verify that the data has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify(
        &self,
        pk: &common::PublicKey,
    ) -> std::result::Result<(), VerifySigError> {
        let bytes = S::serialize(&self.data);
        common::SigScheme::verify_signature_raw(pk, bytes.as_ref(), &self.sig)
    }
}

#[derive(
    Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, BorshSchema, Hash,
)]
pub struct Tx {
    pub code: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTimeUtc,
}

impl TryFrom<&[u8]> for Tx {
    type Error = Error;

    fn try_from(tx_bytes: &[u8]) -> Result<Self> {
        let tx = types::Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;
        let timestamp = match tx.timestamp {
            Some(t) => t.try_into().map_err(Error::InvalidTimestamp)?,
            None => return Err(Error::NoTimestampError),
        };
        Ok(Tx {
            code: tx.code,
            data: tx.data,
            timestamp,
        })
    }
}

impl From<Tx> for types::Tx {
    fn from(tx: Tx) -> Self {
        let timestamp = Some(tx.timestamp.into());
        types::Tx {
            code: tx.code,
            data: tx.data,
            timestamp,
        }
    }
}

impl Tx {
    pub fn new(code: Vec<u8>, data: Option<Vec<u8>>) -> Self {
        Tx {
            code,
            data,
            timestamp: DateTimeUtc::now(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let tx: types::Tx = self.clone().into();
        tx.encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        hash_tx(&self.to_bytes()).0
    }

    pub fn code_hash(&self) -> [u8; 32] {
        hash_tx(&self.code).0
    }

    /// Sign a transaction using [`SignedTxData`].
    pub fn sign(self, keypair: &common::SecretKey) -> Self {
        let to_sign = self.hash();
        let sig = common::SigScheme::sign(keypair, &to_sign);
        let signed = SignedTxData {
            data: self.data,
            sig,
        }
        .try_to_vec()
        .expect("Encoding transaction data shouldn't fail");
        Tx {
            code: self.code,
            data: Some(signed),
            timestamp: self.timestamp,
        }
    }

    /// Verify that the transaction has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify_sig(
        &self,
        pk: &common::PublicKey,
        sig: &common::Signature,
    ) -> std::result::Result<(), VerifySigError> {
        // Try to get the transaction data from decoded `SignedTxData`
        let tx_data = self.data.clone().ok_or(VerifySigError::MissingData)?;
        let signed_tx_data = SignedTxData::try_from_slice(&tx_data[..])
            .expect("Decoding transaction data shouldn't fail");
        let data = signed_tx_data.data;
        let tx = Tx {
            code: self.code.clone(),
            data,
            timestamp: self.timestamp,
        };
        let signed_data = tx.hash();
        common::SigScheme::verify_signature_raw(pk, &signed_data, sig)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IntentGossipMessage {
    pub intent: Intent,
}

impl TryFrom<&[u8]> for IntentGossipMessage {
    type Error = Error;

    fn try_from(intent_bytes: &[u8]) -> Result<Self> {
        let intent = types::IntentGossipMessage::decode(intent_bytes)
            .map_err(Error::IntentDecodingError)?;
        match &intent.msg {
            Some(types::intent_gossip_message::Msg::Intent(intent)) => {
                Ok(IntentGossipMessage {
                    intent: intent.clone().try_into()?,
                })
            }
            None => Err(Error::NoIntentError),
        }
    }
}

impl From<IntentGossipMessage> for types::IntentGossipMessage {
    fn from(message: IntentGossipMessage) -> Self {
        types::IntentGossipMessage {
            msg: Some(types::intent_gossip_message::Msg::Intent(
                message.intent.into(),
            )),
        }
    }
}

impl IntentGossipMessage {
    pub fn new(intent: Intent) -> Self {
        IntentGossipMessage { intent }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let message: types::IntentGossipMessage = self.clone().into();
        message
            .encode(&mut bytes)
            .expect("encoding an intent gossip message failed");
        bytes
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub struct DkgGossipMessage {
    pub dkg: Dkg,
}

impl TryFrom<&[u8]> for DkgGossipMessage {
    type Error = Error;

    fn try_from(dkg_bytes: &[u8]) -> Result<Self> {
        let message = types::DkgGossipMessage::decode(dkg_bytes)
            .map_err(Error::DkgDecodingError)?;
        match &message.dkg_message {
            Some(types::dkg_gossip_message::DkgMessage::Dkg(dkg)) => {
                Ok(DkgGossipMessage {
                    dkg: dkg.clone().into(),
                })
            }
            None => Err(Error::NoDkgError),
        }
    }
}

impl From<DkgGossipMessage> for types::DkgGossipMessage {
    fn from(message: DkgGossipMessage) -> Self {
        types::DkgGossipMessage {
            dkg_message: Some(types::dkg_gossip_message::DkgMessage::Dkg(
                message.dkg.into(),
            )),
        }
    }
}

#[allow(dead_code)]
impl DkgGossipMessage {
    pub fn new(dkg: Dkg) -> Self {
        DkgGossipMessage { dkg }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let message: types::DkgGossipMessage = self.clone().into();
        message
            .encode(&mut bytes)
            .expect("encoding a DKG gossip message failed");
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Intent {
    pub data: Vec<u8>,
    pub timestamp: DateTimeUtc,
}

impl TryFrom<types::Intent> for Intent {
    type Error = Error;

    fn try_from(intent: types::Intent) -> Result<Self> {
        let timestamp = match intent.timestamp {
            Some(t) => t.try_into().map_err(Error::InvalidTimestamp)?,
            None => return Err(Error::NoTimestampError),
        };
        Ok(Intent {
            data: intent.data,
            timestamp,
        })
    }
}

impl From<Intent> for types::Intent {
    fn from(intent: Intent) -> Self {
        let timestamp = Some(intent.timestamp.into());
        types::Intent {
            data: intent.data,
            timestamp,
        }
    }
}

impl Intent {
    pub fn new(data: Vec<u8>) -> Self {
        Intent {
            data,
            timestamp: DateTimeUtc::now(),
        }
    }

    pub fn id(&self) -> IntentId {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        IntentId::from(hasher.finish().to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntentId(pub Vec<u8>);

impl<T: Into<Vec<u8>>> From<T> for IntentId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Display for IntentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub struct Dkg {
    pub data: String,
}

impl From<types::Dkg> for Dkg {
    fn from(dkg: types::Dkg) -> Self {
        Dkg { data: dkg.data }
    }
}

impl From<Dkg> for types::Dkg {
    fn from(dkg: Dkg) -> Self {
        types::Dkg { data: dkg.data }
    }
}

#[allow(dead_code)]
impl Dkg {
    pub fn new(data: String) -> Self {
        Dkg { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx() {
        let code = "wasm code".as_bytes().to_owned();
        let data = "arbitrary data".as_bytes().to_owned();
        let tx = Tx::new(code.clone(), Some(data.clone()));

        let bytes = tx.to_bytes();
        let tx_from_bytes =
            Tx::try_from(bytes.as_ref()).expect("decoding failed");
        assert_eq!(tx_from_bytes, tx);

        let types_tx = types::Tx {
            code,
            data: Some(data),
            timestamp: None,
        };
        let mut bytes = vec![];
        types_tx.encode(&mut bytes).expect("encoding failed");
        match Tx::try_from(bytes.as_ref()) {
            Err(Error::NoTimestampError) => {}
            _ => panic!("unexpected result"),
        }
    }

    #[test]
    fn test_intent_gossip_message() {
        let data = "arbitrary data".as_bytes().to_owned();
        let intent = Intent::new(data);
        let message = IntentGossipMessage::new(intent);

        let bytes = message.to_bytes();
        let message_from_bytes = IntentGossipMessage::try_from(bytes.as_ref())
            .expect("decoding failed");
        assert_eq!(message_from_bytes, message);
    }

    #[test]
    fn test_dkg_gossip_message() {
        let data = "arbitrary string".to_owned();
        let dkg = Dkg::new(data);
        let message = DkgGossipMessage::new(dkg);

        let bytes = message.to_bytes();
        let message_from_bytes = DkgGossipMessage::try_from(bytes.as_ref())
            .expect("decoding failed");
        assert_eq!(message_from_bytes, message);
    }

    #[test]
    fn test_intent() {
        let data = "arbitrary data".as_bytes().to_owned();
        let intent = Intent::new(data.clone());

        let types_intent: types::Intent = intent.clone().into();
        let intent_from_types =
            Intent::try_from(types_intent).expect("no timestamp");
        assert_eq!(intent_from_types, intent);

        let types_intent = types::Intent {
            data,
            timestamp: None,
        };
        match Intent::try_from(types_intent) {
            Err(Error::NoTimestampError) => {}
            _ => panic!("unexpected result"),
        }
    }

    #[test]
    fn test_dkg() {
        let data = "arbitrary string".to_owned();
        let dkg = Dkg::new(data);

        let types_dkg: types::Dkg = dkg.clone().into();
        let dkg_from_types = Dkg::from(types_dkg);
        assert_eq!(dkg_from_types, dkg);
    }
}
