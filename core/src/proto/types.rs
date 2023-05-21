use std::collections::HashSet;
use std::convert::TryFrom;

#[cfg(feature = "ferveo-tpke")]
use ark_ec::AffineCurve;
#[cfg(feature = "ferveo-tpke")]
use ark_ec::PairingEngine;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use masp_primitives::transaction::builder::Builder;
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::transaction::Transaction;
use masp_primitives::zip32::ExtendedFullViewingKey;
use prost::Message;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::generated::types;
#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
use crate::tendermint_proto::abci::ResponseDeliverTx;
use crate::types::address::Address;
use crate::types::chain::ChainId;
use crate::types::key::*;
use crate::types::storage::Epoch;
use crate::types::time::DateTimeUtc;
#[cfg(feature = "ferveo-tpke")]
use crate::types::token::Transfer;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::protocol::ProtocolTx;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::EllipticCurve;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::EncryptionKey;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::WrapperTxErr;
use crate::types::transaction::{hash_tx, DecryptedTx, TxType, WrapperTx};

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
    InvalidTimestamp(prost_types::TimestampError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A section representing transaction data
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Data {
    pub salt: [u8; 8],
    pub data: Vec<u8>,
}

impl Data {
    /// Make a new data section with the given bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            salt: DateTimeUtc::now().0.timestamp_millis().to_le_bytes(),
            data,
        }
    }

    /// Hash this data section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(
            self.try_to_vec().expect("unable to serialize data section"),
        );
        hasher
    }
}

/// Error representing the case where the supplied code has incorrect hash
pub struct CommitmentError;

/// Represents either some code bytes or their SHA-256 hash
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub enum Commitment {
    /// Result of applying hash function to bytes
    Hash(crate::types::hash::Hash),
    /// Result of applying identity function to bytes
    Id(Vec<u8>),
}

impl Commitment {
    /// Substitute bytes with their SHA-256 hash
    pub fn contract(&mut self) {
        if let Self::Id(code) = self {
            *self = Self::Hash(hash_tx(code));
        }
    }

    /// Substitute a code hash with the supplied bytes if the hashes are
    /// consistent, otherwise return an error
    pub fn expand(
        &mut self,
        code: Vec<u8>,
    ) -> std::result::Result<(), CommitmentError> {
        match self {
            Self::Id(c) if *c == code => Ok(()),
            Self::Hash(hash) if *hash == hash_tx(&code) => {
                *self = Self::Id(code);
                Ok(())
            }
            _ => Err(CommitmentError),
        }
    }

    /// Return the contained hash commitment
    pub fn hash(&self) -> crate::types::hash::Hash {
        match self {
            Self::Id(code) => hash_tx(code),
            Self::Hash(hash) => *hash,
        }
    }

    /// Return the result of applying identity function if there is any
    pub fn id(&self) -> Option<Vec<u8>> {
        if let Self::Id(code) = self {
            Some(code.clone())
        } else {
            None
        }
    }
}

/// A section representing transaction code
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Code {
    /// Additional random data
    pub salt: [u8; 8],
    /// Actual transaction code
    pub code: Commitment,
}

impl Code {
    /// Make a new code section with the given bytes
    pub fn new(code: Vec<u8>) -> Self {
        Self {
            salt: DateTimeUtc::now().0.timestamp_millis().to_le_bytes(),
            code: Commitment::Id(code),
        }
    }

    /// Make a new code section with the given hash
    pub fn from_hash(hash: crate::types::hash::Hash) -> Self {
        Self {
            salt: DateTimeUtc::now().0.timestamp_millis().to_le_bytes(),
            code: Commitment::Hash(hash),
        }
    }

    /// Hash this code section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.salt);
        hasher.update(self.code.hash());
        hasher
    }
}

/// A section representing the signature over another section
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Signature {
    /// Additional random data
    salt: [u8; 8],
    /// The hash of the section being signed
    target: crate::types::hash::Hash,
    /// The signature over the above has
    pub signature: common::Signature,
    /// The public key to verrify the above siggnature
    pub_key: common::PublicKey,
}

impl Signature {
    /// Sign the given section hash with the given key and return a section
    pub fn new(
        target: &crate::types::hash::Hash,
        sec_key: &common::SecretKey,
    ) -> Self {
        Self {
            salt: DateTimeUtc::now().0.timestamp_millis().to_le_bytes(),
            target: *target,
            signature: common::SigScheme::sign(sec_key, target),
            pub_key: sec_key.ref_to(),
        }
    }

    /// Hash this signature section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(
            self.try_to_vec()
                .expect("unable to serialize signature section"),
        );
        hasher
    }
}

/// Represents a section obtained by encrypting another section
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ferveo-tpke", serde(from = "SerializedCiphertext"))]
#[cfg_attr(feature = "ferveo-tpke", serde(into = "SerializedCiphertext"))]
#[cfg_attr(
    not(feature = "ferveo-tpke"),
    derive(BorshSerialize, BorshDeserialize, BorshSchema)
)]
pub struct Ciphertext {
    /// The ciphertext corresponding to the original section serialization
    #[cfg(feature = "ferveo-tpke")]
    pub ciphertext: tpke::Ciphertext<EllipticCurve>,
    /// Ciphertext representation when ferveo not available
    #[cfg(not(feature = "ferveo-tpke"))]
    pub opaque: Vec<u8>,
}

impl Ciphertext {
    /// Make a ciphertext section based on the given sections. Note that this
    /// encryption is not idempotent
    #[cfg(feature = "ferveo-tpke")]
    pub fn new(sections: Vec<Section>, pubkey: &EncryptionKey) -> Self {
        let mut rng = rand::thread_rng();
        let bytes = sections
            .try_to_vec()
            .expect("unable to serialize sections");
        Self {
            ciphertext: tpke::encrypt(&bytes, pubkey.0, &mut rng),
        }
    }

    /// Decrypt this ciphertext back to the original plaintext sections.
    #[cfg(feature = "ferveo-tpke")]
    pub fn decrypt(
        &self,
        privkey: <EllipticCurve as PairingEngine>::G2Affine,
    ) -> std::io::Result<Vec<Section>> {
        let bytes = tpke::decrypt(&self.ciphertext, privkey);
        Vec::<Section>::try_from_slice(&bytes)
    }

    /// Get the hash of this ciphertext section. This operation is done in such
    /// a way it matches the hash of the type pun
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(
            self.try_to_vec().expect("unable to serialize decrypted tx"),
        );
        hasher
    }
}

#[cfg(feature = "ferveo-tpke")]
impl borsh::ser::BorshSerialize for Ciphertext {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        use ark_serialize::CanonicalSerialize;
        let tpke::Ciphertext {
            nonce,
            ciphertext,
            auth_tag,
        } = &self.ciphertext;
        // Serialize the nonce into bytes
        let mut nonce_buffer = Vec::<u8>::new();
        nonce.serialize(&mut nonce_buffer).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, err)
        })?;
        // serialize the auth_tag to bytes
        let mut tag_buffer = Vec::<u8>::new();
        auth_tag.serialize(&mut tag_buffer).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, err)
        })?;
        let mut payload = Vec::new();
        // serialize the three byte arrays
        BorshSerialize::serialize(
            &(nonce_buffer, ciphertext, tag_buffer),
            &mut payload,
        )?;
        // now serialize the ciphertext payload with length
        BorshSerialize::serialize(&payload, writer)
    }
}

#[cfg(feature = "ferveo-tpke")]
impl borsh::BorshDeserialize for Ciphertext {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        type VecTuple = (u32, Vec<u8>, Vec<u8>, Vec<u8>);
        let (_length, nonce, ciphertext, auth_tag): VecTuple =
            BorshDeserialize::deserialize(buf)?;
        Ok(Self {
            ciphertext: tpke::Ciphertext {
                nonce: ark_serialize::CanonicalDeserialize::deserialize(
                    &*nonce,
                )
                .map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, err)
                })?,
                ciphertext,
                auth_tag: ark_serialize::CanonicalDeserialize::deserialize(
                    &*auth_tag,
                )
                .map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, err)
                })?,
            },
        })
    }
}

#[cfg(feature = "ferveo-tpke")]
impl borsh::BorshSchema for Ciphertext {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `(Vec<u8>, Vec<u8>, Vec<u8>)`
        let elements = "u8".into();
        let definition = borsh::schema::Definition::Sequence { elements };
        definitions.insert("Vec<u8>".into(), definition);
        let elements =
            vec!["Vec<u8>".into(), "Vec<u8>".into(), "Vec<u8>".into()];
        let definition = borsh::schema::Definition::Tuple { elements };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "Ciphertext".into()
    }
}

/// A helper struct for serializing EncryptedTx structs
/// as an opaque blob
#[cfg(feature = "ferveo-tpke")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct SerializedCiphertext {
    payload: Vec<u8>,
}

#[cfg(feature = "ferveo-tpke")]
impl From<Ciphertext> for SerializedCiphertext {
    fn from(tx: Ciphertext) -> Self {
        SerializedCiphertext {
            payload: tx
                .try_to_vec()
                .expect("Unable to serialize encrypted transaction"),
        }
    }
}

#[cfg(feature = "ferveo-tpke")]
impl From<SerializedCiphertext> for Ciphertext {
    fn from(ser: SerializedCiphertext) -> Self {
        BorshDeserialize::deserialize(&mut ser.payload.as_ref())
            .expect("Unable to deserialize encrypted transactions")
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransactionSerde(Vec<u8>);

impl From<Vec<u8>> for TransactionSerde {
    fn from(tx: Vec<u8>) -> Self {
        Self(tx)
    }
}

impl From<TransactionSerde> for Vec<u8> {
    fn from(tx: TransactionSerde) -> Vec<u8> {
        tx.0
    }
}

fn borsh_serde<T, S>(
    obj: &impl BorshSerialize,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: From<Vec<u8>>,
    T: serde::Serialize,
{
    Into::<T>::into(obj.try_to_vec().unwrap()).serialize(ser)
}

fn serde_borsh<'de, T, S, U>(ser: S) -> std::result::Result<U, S::Error>
where
    S: serde::Deserializer<'de>,
    T: Into<Vec<u8>>,
    T: serde::Deserialize<'de>,
    U: BorshDeserialize,
{
    BorshDeserialize::try_from_slice(&Into::<Vec<u8>>::into(T::deserialize(
        ser,
    )?))
    .map_err(S::Error::custom)
}

/// A structure to facilitate Serde (de)serializations of Builders
#[derive(serde::Serialize, serde::Deserialize)]
struct BuilderSerde(Vec<u8>);

impl From<Vec<u8>> for BuilderSerde {
    fn from(tx: Vec<u8>) -> Self {
        Self(tx)
    }
}

impl From<BuilderSerde> for Vec<u8> {
    fn from(tx: BuilderSerde) -> Vec<u8> {
        tx.0
    }
}

/// A structure to facilitate Serde (de)serializations of SaplingMetadata
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SaplingMetadataSerde(Vec<u8>);

impl From<Vec<u8>> for SaplingMetadataSerde {
    fn from(tx: Vec<u8>) -> Self {
        Self(tx)
    }
}

impl From<SaplingMetadataSerde> for Vec<u8> {
    fn from(tx: SaplingMetadataSerde) -> Vec<u8> {
        tx.0
    }
}

/// A section providing the auxiliary inputs used to construct a MASP
/// transaction
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct MaspBuilder {
    /// The MASP transaction that this section witnesses
    pub target: crate::types::hash::Hash,
    /// The decoded set of asset types used by the transaction. Useful for
    /// offline wallets trying to display AssetTypes.
    pub asset_types: HashSet<(Address, Epoch)>,
    /// Track how Info objects map to descriptors and outputs
    #[serde(
        serialize_with = "borsh_serde::<SaplingMetadataSerde, _>",
        deserialize_with = "serde_borsh::<SaplingMetadataSerde, _, _>"
    )]
    pub metadata: SaplingMetadata,
    /// The data that was used to construct the target transaction
    #[serde(
        serialize_with = "borsh_serde::<BuilderSerde, _>",
        deserialize_with = "serde_borsh::<BuilderSerde, _, _>"
    )]
    pub builder: Builder<(), (), ExtendedFullViewingKey, ()>,
}

impl MaspBuilder {
    /// Get the hash of this ciphertext section. This operation is done in such
    /// a way it matches the hash of the type pun
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(
            self.try_to_vec().expect("unable to serialize MASP builder"),
        );
        hasher
    }
}

impl borsh::BorshSchema for MaspBuilder {
    fn add_definitions_recursively(
        _definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
    }

    fn declaration() -> borsh::schema::Declaration {
        "Builder".into()
    }
}

/// A section of a transaction. Carries an independent piece of information
/// necessary for the processing of a transaction.
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub enum Section {
    /// Transaction data that needs to be sent to hardware wallets
    Data(Data),
    /// Transaction data that does not need to be sent to hardware wallets
    ExtraData(Code),
    /// Transaction code. Sending to hardware wallets optional
    Code(Code),
    /// A transaction signature. Often produced by hardware wallets
    Signature(Signature),
    /// Ciphertext obtained by encrypting arbitrary transaction sections
    Ciphertext(Ciphertext),
    /// Embedded MASP transaction section
    #[serde(
        serialize_with = "borsh_serde::<TransactionSerde, _>",
        deserialize_with = "serde_borsh::<TransactionSerde, _, _>"
    )]
    MaspTx(Transaction),
    /// A section providing the auxiliary inputs used to construct a MASP
    /// transaction. Only send to wallet, never send to protocol.
    MaspBuilder(MaspBuilder),
}

impl Section {
    /// Hash this section. Section hashes are useful for signatures and also for
    /// allowing transaction sections to cross reference.
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        // Get the index corresponding to this variant
        let discriminant =
            self.try_to_vec().expect("sections should serialize")[0];
        // Use Borsh's discriminant in the Section's hash
        hasher.update([discriminant]);
        match self {
            Self::Data(data) => data.hash(hasher),
            Self::ExtraData(extra) => extra.hash(hasher),
            Self::Code(code) => code.hash(hasher),
            Self::Signature(sig) => sig.hash(hasher),
            Self::Ciphertext(ct) => ct.hash(hasher),
            Self::MaspBuilder(mb) => mb.hash(hasher),
            Self::MaspTx(tx) => {
                hasher.update(tx.txid().as_ref());
                hasher
            }
        }
    }

    /// Sign over the hash of this section and return a signature section that
    /// can be added to the container transaction
    pub fn sign(&self, sec_key: &common::SecretKey) -> Signature {
        let mut hasher = Sha256::new();
        self.hash(&mut hasher);
        Signature::new(
            &crate::types::hash::Hash(hasher.finalize().into()),
            sec_key,
        )
    }

    /// Extract the data from this section if possible
    pub fn data(&self) -> Option<Data> {
        if let Self::Data(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the extra data from this section if possible
    pub fn extra_data_sec(&self) -> Option<Code> {
        if let Self::ExtraData(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the extra data from this section if possible
    pub fn extra_data(&self) -> Option<Vec<u8>> {
        if let Self::ExtraData(data) = self {
            data.code.id()
        } else {
            None
        }
    }

    /// Extract the code from this section is possible
    pub fn code_sec(&self) -> Option<Code> {
        if let Self::Code(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the code from this section is possible
    pub fn code(&self) -> Option<Vec<u8>> {
        if let Self::Code(data) = self {
            data.code.id()
        } else {
            None
        }
    }

    /// Extract the signature from this section if possible
    pub fn signature(&self) -> Option<Signature> {
        if let Self::Signature(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the ciphertext from this section if possible
    pub fn ciphertext(&self) -> Option<Ciphertext> {
        if let Self::Ciphertext(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the MASP transaction from this section if possible
    pub fn masp_tx(&self) -> Option<Transaction> {
        if let Self::MaspTx(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }

    /// Extract the MASP builder from this section if possible
    pub fn masp_builder(&self) -> Option<MaspBuilder> {
        if let Self::MaspBuilder(data) = self {
            Some(data.clone())
        } else {
            None
        }
    }
}

/// A Namada transaction header indicating where transaction subcomponents can
/// be found
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Header {
    /// The chain which this transaction is being submitted to
    pub chain_id: ChainId,
    /// The time at which this transaction expires
    pub expiration: Option<DateTimeUtc>,
    /// A transaction timestamp
    pub timestamp: DateTimeUtc,
    /// The SHA-256 hash of the transaction's code section
    pub code_hash: crate::types::hash::Hash,
    /// The SHA-256 hash of the transaction's data section
    pub data_hash: crate::types::hash::Hash,
    /// The type of this transaction
    pub tx_type: TxType,
}

impl Header {
    /// Make a new header of the given transaction type
    pub fn new(tx_type: TxType) -> Self {
        Self {
            tx_type,
            chain_id: ChainId::default(),
            expiration: None,
            timestamp: DateTimeUtc::now(),
            code_hash: crate::types::hash::Hash::default(),
            data_hash: crate::types::hash::Hash::default(),
        }
    }

    /// Get the hash of this transaction header.
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(
            self.try_to_vec()
                .expect("unable to serialize transaction header"),
        );
        hasher
    }

    /// Get the wrapper header if it is present
    pub fn wrapper(&self) -> Option<WrapperTx> {
        if let TxType::Wrapper(wrapper) = &self.tx_type {
            Some(*wrapper.clone())
        } else {
            None
        }
    }

    /// Get the decrypted header if it is present
    pub fn decrypted(&self) -> Option<DecryptedTx> {
        if let TxType::Decrypted(decrypted) = &self.tx_type {
            Some(decrypted.clone())
        } else {
            None
        }
    }

    #[cfg(feature = "ferveo-tpke")]
    /// Get the protocol header if it is present
    pub fn protocol(&self) -> Option<ProtocolTx> {
        if let TxType::Protocol(protocol) = &self.tx_type {
            Some(*protocol.clone())
        } else {
            None
        }
    }
}

/// Errors relating to decrypting a wrapper tx and its
/// encrypted payload from a Tx type
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TxError {
    #[error("{0}")]
    Unsigned(String),
    #[error("{0}")]
    SigError(String),
    #[error("Failed to deserialize Tx: {0}")]
    Deserialization(String),
}

/// A Namada transaction is represented as a header followed by a series of
/// seections providing additional details.
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Tx {
    /// Type indicating how to process transaction
    pub header: Header,
    /// Additional details necessary to process transaction
    pub sections: Vec<Section>,
}

/// Deserialize Tx from protobufs
impl TryFrom<&[u8]> for Tx {
    type Error = Error;

    fn try_from(tx_bytes: &[u8]) -> Result<Self> {
        let tx = types::Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;
        BorshDeserialize::try_from_slice(&tx.data)
            .map_err(Error::TxDeserializingError)
    }
}

impl Tx {
    /// Create a transaction of the given type
    pub fn new(header: TxType) -> Self {
        Tx {
            header: Header::new(header),
            sections: vec![],
        }
    }

    /// Get the transaction header
    pub fn header(&self) -> Header {
        self.header.clone()
    }

    /// Get the transaction header hash
    pub fn header_hash(&self) -> crate::types::hash::Hash {
        crate::types::hash::Hash(
            self.header.hash(&mut Sha256::new()).finalize_reset().into(),
        )
    }

    /// Update the header whilst maintaining existing cross-references
    pub fn update_header(&mut self, tx_type: TxType) -> &mut Self {
        self.header.tx_type = tx_type;
        self
    }

    /// Get the transaction section with the given hash
    pub fn get_section(
        &self,
        hash: &crate::types::hash::Hash,
    ) -> Option<&Section> {
        for section in &self.sections {
            let sechash = crate::types::hash::Hash(
                section.hash(&mut Sha256::new()).finalize_reset().into(),
            );
            if sechash == *hash {
                return Some(section);
            }
        }
        None
    }

    /// Add a new section to the transaction
    pub fn add_section(&mut self, section: Section) -> &mut Section {
        self.sections.push(section);
        self.sections.last_mut().unwrap()
    }

    /// Get the hash of this transaction's code from the heeader
    pub fn code_sechash(&self) -> &crate::types::hash::Hash {
        &self.header.code_hash
    }

    /// Set the transaction code hash stored in the header
    pub fn set_code_sechash(&mut self, hash: crate::types::hash::Hash) {
        self.header.code_hash = hash
    }

    /// Get the code designated by the transaction code hash in the header
    pub fn code(&self) -> Option<Vec<u8>> {
        match self.get_section(self.code_sechash()) {
            Some(Section::Code(section)) => section.code.id(),
            _ => None,
        }
    }

    /// Add the given code to the transaction and set code hash in the header
    pub fn set_code(&mut self, code: Code) -> &mut Section {
        let sec = Section::Code(code);
        let mut hasher = Sha256::new();
        sec.hash(&mut hasher);
        let hash = crate::types::hash::Hash(hasher.finalize().into());
        self.set_code_sechash(hash);
        self.sections.push(sec);
        self.sections.last_mut().unwrap()
    }

    /// Get the transaction data hash stored in the header
    pub fn data_sechash(&self) -> &crate::types::hash::Hash {
        &self.header.data_hash
    }

    /// Set the transaction data hash stored in the header
    pub fn set_data_sechash(&mut self, hash: crate::types::hash::Hash) {
        self.header.data_hash = hash
    }

    /// Add the given code to the transaction and set the hash in the header
    pub fn set_data(&mut self, data: Data) -> &mut Section {
        let sec = Section::Data(data);
        let mut hasher = Sha256::new();
        sec.hash(&mut hasher);
        let hash = crate::types::hash::Hash(hasher.finalize().into());
        self.set_data_sechash(hash);
        self.sections.push(sec);
        self.sections.last_mut().unwrap()
    }

    /// Get the data designated by the transaction data hash in the header
    pub fn data(&self) -> Option<Vec<u8>> {
        match self.get_section(self.data_sechash()) {
            Some(Section::Data(data)) => Some(data.data.clone()),
            _ => None,
        }
    }

    /// Convert this transaction into protobufs
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let tx: types::Tx = types::Tx {
            data: self.try_to_vec().expect("encoding a transaction failed"),
        };
        tx.encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    /// Verify that the section with the given hash has been signed by the given
    /// public key
    pub fn verify_signature(
        &self,
        pk: &common::PublicKey,
        hash: &crate::types::hash::Hash,
    ) -> std::result::Result<(), VerifySigError> {
        for section in &self.sections {
            if let Section::Signature(sig_sec) = section {
                if sig_sec.pub_key == *pk && sig_sec.target == *hash {
                    return common::SigScheme::verify_signature_raw(
                        pk,
                        &hash.0,
                        &sig_sec.signature,
                    );
                }
            }
        }
        Err(VerifySigError::MissingData)
    }

    /// Validate any and all ciphertexts stored in this transaction
    #[cfg(feature = "ferveo-tpke")]
    pub fn validate_ciphertext(&self) -> bool {
        let mut valid = true;
        for section in &self.sections {
            if let Section::Ciphertext(ct) = section {
                valid = valid && ct.ciphertext.check(
                    &<EllipticCurve as PairingEngine>::G1Prepared::from(
                        -<EllipticCurve as PairingEngine>::G1Affine::prime_subgroup_generator(),
                    )
                );
            }
        }
        valid
    }

    /// Decrypt any and all ciphertexts stored in this transaction use the
    /// given decryption key
    #[cfg(feature = "ferveo-tpke")]
    pub fn decrypt(
        &mut self,
        privkey: <EllipticCurve as PairingEngine>::G2Affine,
    ) -> std::result::Result<(), WrapperTxErr> {
        // Iterate backwrds to sidestep the effects of deletion on indexing
        for i in (0..self.sections.len()).rev() {
            if let Section::Ciphertext(ct) = &self.sections[i] {
                // Add all the deecrypted sections
                self.sections.extend(
                    ct.decrypt(privkey).map_err(|_| WrapperTxErr::InvalidTx)?
                );
                // Remove the original ciphertext
                self.sections.remove(i);
            }
        }
        self.data().ok_or(WrapperTxErr::DecryptedHash)?;
        self.get_section(self.code_sechash())
            .ok_or(WrapperTxErr::DecryptedHash)?;
        Ok(())
    }

    /// Encrypt all sections in this transaction other than the header and
    /// signatures over it
    #[cfg(feature = "ferveo-tpke")]
    pub fn encrypt(&mut self, pubkey: &EncryptionKey) {
        let header_hash = self.header_hash();
        let mut plaintexts = vec![];
        // Iterate backwrds to sidestep the effects of deletion on indexing
        for i in (0..self.sections.len()).rev() {
            match &self.sections[i] {
                Section::Signature(sig) if sig.target == header_hash => {}
                // Add eligible section to the list of sections to encrypt
                _ => plaintexts.push(self.sections.remove(i)),
            }
        }
        // Encrypt all eligible sections in one go
        self.sections.push(Section::Ciphertext(Ciphertext::new(
            plaintexts,
            pubkey,
        )));
    }

    /// Determines the type of the input Tx
    ///
    /// If it is a raw Tx, signed or not, the Tx is
    /// returned unchanged inside an enum variant stating its type.
    ///
    /// If it is a decrypted tx, signing it adds no security so we
    /// extract the signed data without checking the signature (if it
    /// is signed) or return as is. Either way, it is returned in
    /// an enum variant stating its type.
    ///
    /// If it is a WrapperTx, we extract the signed data of
    /// the Tx and verify it is of the appropriate form. This means
    /// 1. The wrapper tx is indeed signed
    /// 2. The signature is valid
    pub fn validate_header(&self) -> std::result::Result<(), TxError> {
        match &self.header.tx_type {
            // verify signature and extract signed data
            TxType::Wrapper(wrapper) => {
                self.verify_signature(&wrapper.pk, &self.header_hash())
                    .map_err(|err| {
                        TxError::SigError(format!(
                            "WrapperTx signature verification failed: {}",
                            err
                        ))
                    })?;
                Ok(())
            }
            // verify signature and extract signed data
            #[cfg(feature = "ferveo-tpke")]
            TxType::Protocol(protocol) => {
                self.verify_signature(&protocol.pk, &self.header_hash())
                    .map_err(|err| {
                        TxError::SigError(format!(
                            "ProtocolTx signature verification failed: {}",
                            err
                        ))
                    })?;
                Ok(())
            }
            // we extract the signed data, but don't check the signature
            TxType::Decrypted(_) => Ok(()),
            // return as is
            TxType::Raw => Ok(()),
        }
    }

    /// Filter out all the sections that must not be submitted to the protocol
    /// and return them.
    pub fn protocol_filter(&mut self) -> Vec<Section> {
        let mut filtered = Vec::new();
        for i in (0..self.sections.len()).rev() {
            if let Section::MaspBuilder(_) = self.sections[i] {
                // MASP Builders containin extended full viewing keys amongst
                // other private information and must be removed prior to
                // submission to protocol
                filtered.push(self.sections.remove(i));
            }
        }
        filtered
    }

    /// Filter out all the sections that need not be sent to the hardware wallet
    /// and return them
    pub fn wallet_filter(&mut self) -> Vec<Section> {
        let mut filtered = Vec::new();
        for i in (0..self.sections.len()).rev() {
            match &mut self.sections[i] {
                // This section is known to be large and can be contracted
                Section::Code(section) => {
                    filtered.push(Section::Code(section.clone()));
                    section.code.contract();
                }
                // This section is known to be large and can be contracted
                Section::ExtraData(section) => {
                    filtered.push(Section::ExtraData(section.clone()));
                    section.code.contract();
                }
                // Everything else is fine to add
                _ => {}
            }
        }
        filtered
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

        // If data cannot be extracteed, then attach no events
        let tx_data = if let Some(data) = tx.data() {
            data
        } else {
            return Default::default();
        };
        // If the data is not a Transfer, then attach no events
        let transfer = if let Ok(transfer) = Transfer::try_from_slice(&tx_data)
        {
            transfer
        } else {
            return Default::default();
        };
        // Otherwise attach all Transfer events
        let events = vec![Event {
            r#type: "transfer".to_string(),
            attributes: vec![
                EventAttribute {
                    key: "source".to_string(),
                    value: transfer.source.encode(),
                    index: true,
                },
                EventAttribute {
                    key: "target".to_string(),
                    value: transfer.target.encode(),
                    index: true,
                },
                EventAttribute {
                    key: "token".to_string(),
                    value: transfer.token.encode(),
                    index: true,
                },
                EventAttribute {
                    key: "amount".to_string(),
                    value: transfer.amount.to_string(),
                    index: true,
                },
            ],
        }];
        ResponseDeliverTx {
            events,
            info: "Transfer tx".to_string(),
            ..Default::default()
        }
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

    /// Test that encryption and decryption are inverses.
    #[cfg(feature = "ferveo-tpke")]
    #[test]
    fn test_encrypt_decrypt() {
        // The trivial public - private keypair
        let pubkey = EncryptionKey(<EllipticCurve as PairingEngine>::G1Affine::prime_subgroup_generator());
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
        // generate encrypted payload
        let plaintext = vec![
            Section::Data(Data::new("Super secret stuff".as_bytes().to_vec())),
        ];
        let encrypted = Ciphertext::new(plaintext.clone(), &pubkey);
        // check that encryption doesn't do trivial things
        assert_ne!(
            encrypted.ciphertext.ciphertext,
            plaintext.try_to_vec().expect("Test failed")
        );
        // decrypt the payload and check we got original data back
        let decrypted = encrypted.decrypt(privkey);
        assert_eq!(
            decrypted
                .expect("Test failed")
                .try_to_vec()
                .expect("Test failed"),
            plaintext.try_to_vec().expect("Test failed"),
        );
    }

    /// Test that serializing and deserializing again via Borsh produces
    /// original payload
    #[cfg(feature = "ferveo-tpke")]
    #[test]
    fn test_encrypted_tx_round_trip_borsh() {
        // The trivial public - private keypair
        let pubkey = EncryptionKey(<EllipticCurve as PairingEngine>::G1Affine::prime_subgroup_generator());
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
        // generate encrypted payload
        let plaintext = vec![
            Section::Data(Data::new("Super secret stuff".as_bytes().to_vec())),
        ];
        let encrypted = Ciphertext::new(plaintext.clone(), &pubkey);
        // serialize via Borsh
        let borsh = encrypted.try_to_vec().expect("Test failed");
        // deserialize again
        let new_encrypted: Ciphertext =
            BorshDeserialize::deserialize(&mut borsh.as_ref())
                .expect("Test failed");
        // check that decryption works as expected
        let decrypted = new_encrypted.decrypt(privkey);
        assert_eq!(
            decrypted
                .expect("Test failed")
                .try_to_vec()
                .expect("Test failed"),
            plaintext.try_to_vec().expect("Test failed"),
        );
    }

    /// Test that serializing and deserializing again via Serde produces
    /// original payload
    #[cfg(feature = "ferveo-tpke")]
    #[test]
    fn test_encrypted_tx_round_trip_serde() {
        // The trivial public - private keypair
        let pubkey = EncryptionKey(<EllipticCurve as PairingEngine>::G1Affine::prime_subgroup_generator());
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
        // generate encrypted payload
        let plaintext = vec![
            Section::Data(Data::new("Super secret stuff".as_bytes().to_vec())),
        ];
        let encrypted = Ciphertext::new(plaintext.clone(), &pubkey);
        // serialize via Serde
        let js = serde_json::to_string(&encrypted).expect("Test failed");
        // deserialize it again
        let new_encrypted: Ciphertext =
            serde_json::from_str(&js).expect("Test failed");
        let decrypted = new_encrypted.decrypt(privkey);
        // check that decryption works as expected
        assert_eq!(
            decrypted
                .expect("Test failed")
                .try_to_vec()
                .expect("Test failed"),
            plaintext.try_to_vec().expect("Test failed"),
        );
    }
}
