use std::convert::{TryFrom, TryInto};
use std::hash::{Hash, Hasher};

#[cfg(feature = "ferveo-tpke")]
use ark_ec::AffineCurve;
#[cfg(feature = "ferveo-tpke")]
use ark_ec::PairingEngine;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::generated::types;
#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
use crate::tendermint_proto::abci::ResponseDeliverTx;
use crate::types::key::*;
use crate::types::time::DateTimeUtc;
#[cfg(feature = "ferveo-tpke")]
use crate::types::token::Transfer;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::encrypted::EncryptedTx;
use crate::types::transaction::hash_tx;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::process_tx;
use crate::types::transaction::DecryptedTx;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::EllipticCurve;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::EncryptionKey;
use crate::types::transaction::TxType;
use crate::types::transaction::WrapperTx;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Error deserializing transaction field bytes: {0}")]
    TxDeserializingError(std::io::Error),
    #[error("Error decoding an DkgGossipMessage from bytes: {0}")]
    DkgDecodingError(prost::DecodeError),
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
/// which can then be checked by a validity predicate wasm.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct SignedTxData {
    /// The original tx data bytes, if any
    pub data: Option<Vec<u8>>,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: Option<common::Signature>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, Deserialize, Serialize)]
pub struct SignedOuterTxData {
    /// The original tx data bytes, if any
    pub data: TxType,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: Option<common::Signature>,
}

/// A generic signed data wrapper for Borsh encode-able data.
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Signed<T: BorshSerialize + BorshDeserialize> {
    /// Arbitrary data to be signed
    pub data: T,
    /// The signature of the data
    pub sig: common::Signature,
}

impl<T> PartialEq for Signed<T>
where
    T: BorshSerialize + BorshDeserialize + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.sig == other.sig
    }
}

impl<T> Eq for Signed<T> where
    T: BorshSerialize + BorshDeserialize + Eq + PartialEq
{
}

impl<T> Hash for Signed<T>
where
    T: BorshSerialize + BorshDeserialize + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.sig.hash(state);
    }
}

impl<T> PartialOrd for Signed<T>
where
    T: BorshSerialize + BorshDeserialize + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.data.partial_cmp(&other.data)
    }
}

impl<T> Signed<T>
where
    T: BorshSerialize + BorshDeserialize,
{
    /// Initialize a new signed data.
    pub fn new(keypair: &common::SecretKey, data: T) -> Self {
        let to_sign = data
            .try_to_vec()
            .expect("Encoding data for signing shouldn't fail");
        let sig = common::SigScheme::sign(keypair, to_sign);
        Self { data, sig }
    }

    /// Verify that the data has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify(
        &self,
        pk: &common::PublicKey,
    ) -> std::result::Result<(), VerifySigError> {
        let bytes = self
            .data
            .try_to_vec()
            .expect("Encoding data for verifying signature shouldn't fail");
        common::SigScheme::verify_signature_raw(pk, &bytes, &self.sig)
    }
}

/// A SigningTx but with the full code embedded. This structure will almost
/// certainly be bigger than SigningTxs and contains enough information to
/// execute the transaction.
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Deserialize,
)]
pub struct Tx {
    pub outer_code: Vec<u8>,
    pub outer_data: SignedOuterTxData,
    pub outer_timestamp: DateTimeUtc,
    pub outer_extra: Vec<u8>,
    /// the encrypted inner transaction if data contains a WrapperTx
    pub inner_tx: Option<InnerTx>,
}

/// A SigningTx but with the full code embedded. This structure will almost
/// certainly be bigger than SigningTxs and contains enough information to
/// execute the transaction.
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct InnerTx {
    pub code: Vec<u8>,
    pub data: Option<SignedTxData>,
    pub timestamp: DateTimeUtc,
    pub extra: Vec<u8>,
}

impl From<SignedOuterTxData> for SignedTxData {
    fn from(data: SignedOuterTxData) -> Self {
        Self {
            data: Some(data.data.try_to_vec().unwrap()),
            sig: data.sig,
        }
    }
}

impl From<Tx> for InnerTx {
    fn from(tx: Tx) -> Self {
        Self {
            code: tx.outer_code,
            data: Some(tx.outer_data.into()),
            timestamp: tx.outer_timestamp,
            extra: tx.outer_extra,
        }
    }
}

impl TryFrom<&[u8]> for Tx {
    type Error = Error;

    fn try_from(tx_bytes: &[u8]) -> Result<Self> {
        let tx = types::Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;
        let timestamp = match tx.timestamp {
            Some(t) => t.try_into().map_err(Error::InvalidTimestamp)?,
            None => return Err(Error::NoTimestampError),
        };
        let inner_tx = tx
            .inner_tx
            .map(|x| {
                BorshDeserialize::try_from_slice(&x)
                    .map_err(Error::TxDeserializingError)
            })
            .transpose()?;
        let data = BorshDeserialize::try_from_slice(
            &tx
                .data
                .ok_or(Error::TxDeserializingError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Missing data",
                )))?
        ).map_err(Error::TxDeserializingError)?;
        Ok(Tx {
            outer_code: tx.code,
            outer_data: data,
            outer_extra: tx.extra,
            outer_timestamp: timestamp,
            inner_tx,
        })
    }
}

impl TryFrom<&[u8]> for InnerTx {
    type Error = Error;

    fn try_from(tx_bytes: &[u8]) -> Result<Self> {
        let tx = types::Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;
        let timestamp = match tx.timestamp {
            Some(t) => t.try_into().map_err(Error::InvalidTimestamp)?,
            None => return Err(Error::NoTimestampError),
        };
        let data = tx
            .data
            .map(|x| {
                BorshDeserialize::try_from_slice(&x)
                    .map_err(Error::TxDeserializingError)
            })
            .transpose()?;
        Ok(InnerTx {
            code: tx.code,
            data,
            extra: tx.extra,
            timestamp,
        })
    }
}

impl From<Tx> for types::Tx {
    fn from(tx: Tx) -> Self {
        let timestamp = Some(tx.outer_timestamp.into());
        let inner_tx = tx.inner_tx.map(|x| {
            x.try_to_vec()
                .expect("Unable to serialize encrypted transaction")
        });
        let data = Some(
            tx.outer_data.try_to_vec()
                .expect("Unable to serialize encrypted transaction")
        );
        types::Tx {
            code: tx.outer_code,
            data,
            extra: tx.outer_extra,
            timestamp,
            inner_tx,
        }
    }
}

#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
impl From<Tx> for ResponseDeliverTx {
    #[cfg(not(feature = "ferveo-tpke"))]
    fn from(_tx: Tx) -> ResponseDeliverTx {
        Default::default()
    }

    /// Annotate the Tx with meta-data based on its contents
    #[cfg(feature = "ferveo-tpke")]
    fn from(tx: Tx) -> ResponseDeliverTx {
        use crate::tendermint_proto::abci::{Event, EventAttribute};

        #[cfg(feature = "ABCI")]
        fn encode_str(x: &str) -> Vec<u8> {
            x.as_bytes().to_vec()
        }
        #[cfg(not(feature = "ABCI"))]
        fn encode_str(x: &str) -> String {
            x.to_string()
        }
        #[cfg(feature = "ABCI")]
        fn encode_string(x: String) -> Vec<u8> {
            x.into_bytes()
        }
        #[cfg(not(feature = "ABCI"))]
        fn encode_string(x: String) -> String {
            x
        }
        let empty_vec = vec![];
        let tx_data = tx.data();
        if let Ok(transfer) = Transfer::try_from_slice(
            tx.data().as_ref().unwrap_or(&empty_vec),
        ) {
            let events = vec![Event {
                r#type: "transfer".to_string(),
                attributes: vec![
                    EventAttribute {
                        key: encode_str("source"),
                        value: encode_string(transfer.source.encode()),
                        index: true,
                    },
                    EventAttribute {
                        key: encode_str("target"),
                        value: encode_string(transfer.target.encode()),
                        index: true,
                    },
                    EventAttribute {
                        key: encode_str("token"),
                        value: encode_string(transfer.token.encode()),
                        index: true,
                    },
                    EventAttribute {
                        key: encode_str("amount"),
                        value: encode_string(
                            transfer.amount.to_string(),
                        ),
                        index: true,
                    },
                ],
            }];
            ResponseDeliverTx {
                events,
                info: "Transfer tx".to_string(),
                ..Default::default()
            }
        } else {
            Default::default()
        }
    }
}

impl Tx {
    pub fn new(code: Vec<u8>, data: SignedOuterTxData) -> Self {
        Tx {
            outer_code: code,
            outer_data: data,
            outer_timestamp: DateTimeUtc::now(),
            inner_tx: None,
            outer_extra: vec![],
        }
    }

    pub fn header(&self) -> TxType {
        self.outer_data.data.clone()
    }

    pub fn code(&self) -> Option<Vec<u8>> {
        if let Some(inner_tx) = &self.inner_tx {
            Some(inner_tx.code.clone())
        } else {
            None
        }
    }

    pub fn extra(&self) -> Option<Vec<u8>> {
        if let Some(inner_tx) = &self.inner_tx {
            Some(inner_tx.extra.clone())
        } else {
            None
        }
    }

    pub fn data(&self) -> Option<Vec<u8>> {
        if let Some(InnerTx { data: Some(SignedTxData { data, ..}), .. }) = &self.inner_tx {
            data.clone()
        } else {
            None
        }
    }

    pub fn data_hash(&self) -> Option<crate::types::hash::Hash> {
        if let Some(tx) = &self.inner_tx {
            Some(crate::types::hash::Hash(tx.partial_hash()))
        } else {
            None
        }
    }

    pub fn inner_tx(&self) -> Option<InnerTx> {
        self.inner_tx.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let tx: types::Tx = self.clone().into();
        tx.encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    /// Produce a reduced version of this transaction that is sufficient for
    /// signing. Specifically replaces code and extra with their hashes, and
    /// leaves out inner tx.
    pub fn signing_tx(&self) -> types::Tx {
        let timestamp = Some(self.outer_timestamp.into());
        let data = Some(self.outer_data.try_to_vec()
            .expect("Unable to serialize encrypted transaction"));
        types::Tx {
            code: hash_tx(&self.outer_code).0.to_vec(),
            extra: hash_tx(&self.outer_extra).0.to_vec(),
            data,
            timestamp,
            inner_tx: None,
        }
    }

    /// Hash this transaction leaving out the inner tx, but instead of including
    /// the transaction code and extra data in the hash, include their hashes
    /// instead.
    pub fn partial_hash(&self) -> [u8; 32] {
        let mut bytes = vec![];
        self.signing_tx()
            .encode(&mut bytes)
            .expect("encoding a transaction failed");
        hash_tx(&bytes).0
    }

    /// Get the hash of this transaction's code
    pub fn code_hash(&self) -> Option<[u8; 32]> {
        self.code().map(|x| hash_tx(&x).0)
    }

    /// Get the hash of this transaction's extra data
    pub fn extra_hash(&self) -> [u8; 32] {
        hash_tx(&self.outer_extra).0
    }

    /// Sign a transaction using [`SignedTxData`].
    pub fn sign(self, keypair: &common::SecretKey) -> Self {
        let to_sign = self.partial_hash();
        let sig = common::SigScheme::sign(keypair, to_sign);
        let signed = SignedOuterTxData {
            data: self.outer_data.data,
            sig: Some(sig),
        };
        Tx {
            outer_code: self.outer_code,
            outer_data: signed,
            outer_extra: self.outer_extra,
            outer_timestamp: self.outer_timestamp,
            inner_tx: self.inner_tx,
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
        let signed_tx_data = self.outer_data.clone();
        let mut data = signed_tx_data.clone();
        data.sig = None;
        let tx = Tx {
            outer_code: self.outer_code.clone(),
            outer_extra: self.outer_extra.clone(),
            outer_data: data,
            outer_timestamp: self.outer_timestamp,
            inner_tx: self.inner_tx.clone(),
        };
        let signed_data = tx.partial_hash();
        common::SigScheme::verify_signature_raw(pk, &signed_data, sig)
    }

    pub fn verify_signature(
        &self,
        pk: &common::PublicKey,
        hash: &crate::types::hash::Hash,
    ) -> std::result::Result<(), VerifySigError> {
        let inner_tx = self.inner_tx();
        if self.partial_hash() == hash.0 {
            self.outer_data
                .sig.as_ref().ok_or(VerifySigError::MissingData)
                .and_then(|sig| self.verify_sig(pk, &sig))
        } else if inner_tx.is_some() && inner_tx.as_ref().unwrap().partial_hash() == hash.0 {
            inner_tx.clone().unwrap()
                .data.ok_or(VerifySigError::MissingData)?
                .sig.ok_or(VerifySigError::MissingData)
                .and_then(|sig| inner_tx.unwrap().verify_sig(pk, &sig))
        } else {
            Err(VerifySigError::MissingData)
        }
    }

    #[cfg(feature = "ferveo-tpke")]
    /// Attach the given transaction to this one. Useful when the data field
    /// contains a WrapperTx and its tx_hash field needs a witness.
    pub fn attach_inner_tx(
        mut self,
        tx: &InnerTx,
        encryption_key: EncryptionKey,
    ) -> Self {
        self.inner_tx = Some(tx.clone());
        self
    }

    /// A validity check on the ciphertext.
    #[cfg(feature = "ferveo-tpke")]
    pub fn validate_ciphertext(&self) -> bool {
        true
    }
}

impl From<InnerTx> for types::InnerTx {
    fn from(tx: InnerTx) -> Self {
        let timestamp = Some(tx.timestamp.into());
        let data = tx.data.map(|x| {
            x.try_to_vec()
                .expect("Unable to serialize encrypted transaction")
        });
        types::InnerTx {
            code: tx.code,
            data,
            extra: tx.extra,
            timestamp,
        }
    }
}

impl InnerTx {
    pub fn new(code: Vec<u8>, data: Option<SignedTxData>) -> Self {
        InnerTx {
            code,
            data,
            timestamp: DateTimeUtc::now(),
            extra: vec![],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let tx: types::InnerTx = self.clone().into();
        tx.encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    /// Produce a reduced version of this transaction that is sufficient for
    /// signing. Specifically replaces code and extra with their hashes, and
    /// leaves out inner tx.
    pub fn signing_tx(&self) -> types::Tx {
        let timestamp = Some(self.timestamp.into());
        let data = self.data.as_ref().map(|x| {
            x.try_to_vec()
                .expect("Unable to serialize encrypted transaction")
        });
        types::Tx {
            code: hash_tx(&self.code).0.to_vec(),
            extra: hash_tx(&self.extra).0.to_vec(),
            data,
            timestamp,
            inner_tx: None,
        }
    }

    /// Hash this transaction leaving out the inner tx, but instead of including
    /// the transaction code and extra data in the hash, include their hashes
    /// instead.
    pub fn partial_hash(&self) -> [u8; 32] {
        let mut bytes = vec![];
        self.signing_tx()
            .encode(&mut bytes)
            .expect("encoding a transaction failed");
        hash_tx(&bytes).0
    }

    /// Get the hash of this transaction's code
    pub fn code_hash(&self) -> [u8; 32] {
        hash_tx(&self.code).0
    }

    /// Get the hash of this transaction's extra data
    pub fn extra_hash(&self) -> [u8; 32] {
        hash_tx(&self.extra).0
    }

    /// Sign a transaction using [`SignedTxData`].
    pub fn sign(self, keypair: &common::SecretKey) -> Self {
        let to_sign = self.partial_hash();
        let sig = common::SigScheme::sign(keypair, to_sign);
        let signed = SignedTxData {
            data: self.data.and_then(|x| x.data),
            sig: Some(sig),
        };
        InnerTx {
            code: self.code,
            data: Some(signed),
            extra: self.extra,
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
        let signed_tx_data = self.data.clone().ok_or(VerifySigError::MissingData)?;
        let mut data = signed_tx_data.clone();
        data.sig = None;
        let tx = InnerTx {
            code: self.code.clone(),
            extra: self.extra.clone(),
            data: Some(data),
            timestamp: self.timestamp,
        };
        let signed_data = tx.partial_hash();
        common::SigScheme::verify_signature_raw(pk, &signed_data, sig)
    }

    /// A validity check on the ciphertext.
    #[cfg(feature = "ferveo-tpke")]
    pub fn validate_ciphertext(&self) -> bool {
        true
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
        let tx = InnerTx::new(code.clone(), Some(SignedTxData {data: Some(data.clone()), sig: None}));

        let bytes = tx.to_bytes();
        let tx_from_bytes =
            InnerTx::try_from(bytes.as_ref()).expect("decoding failed");
        assert_eq!(tx_from_bytes, tx);

        let types_tx = types::Tx {
            code,
            data: Some(data),
            timestamp: None,
            inner_tx: None,
            extra: vec![],
        };
        let mut bytes = vec![];
        types_tx.encode(&mut bytes).expect("encoding failed");
        match Tx::try_from(bytes.as_ref()) {
            Err(Error::NoTimestampError) => {}
            _ => panic!("unexpected result"),
        }
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
    fn test_dkg() {
        let data = "arbitrary string".to_owned();
        let dkg = Dkg::new(data);

        let types_dkg: types::Dkg = dkg.clone().into();
        let dkg_from_types = Dkg::from(types_dkg);
        assert_eq!(dkg_from_types, dkg);
    }
}
