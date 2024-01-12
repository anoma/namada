use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use borsh::schema::{add_definition, Declaration, Definition};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use data_encoding::HEXUPPER;
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
use crate::ledger::gas;
use crate::ledger::storage::{KeccakHasher, Sha256Hasher, StorageHasher};
use crate::types::account::AccountPublicKeysMap;
use crate::types::address::Address;
use crate::types::chain::ChainId;
use crate::types::keccak::{keccak_hash, KeccakHash};
use crate::types::key::{self, *};
use crate::types::storage::Epoch;
use crate::types::time::DateTimeUtc;
use crate::types::token::MaspDenom;
use crate::types::transaction::protocol::ProtocolTx;
use crate::types::transaction::{
    hash_tx, DecryptedTx, Fee, GasLimit, TxType, WrapperTx,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Error deserializing transaction field bytes: {0}")]
    TxDeserializingError(std::io::Error),
    #[error("Error deserializing transaction")]
    OfflineTxDeserializationError,
    #[error("Timestamp is empty")]
    NoTimestampError,
    #[error("Timestamp is invalid: {0}")]
    InvalidTimestamp(prost_types::TimestampError),
    #[error("The section signature is invalid: {0}")]
    InvalidSectionSignature(String),
    #[error("Couldn't serialize transaction from JSON at {0}")]
    InvalidJSONDeserialization(String),
    #[error("The wrapper signature is invalid.")]
    InvalidWrapperSignature,
    #[error("Signature verification went out of gas: {0}")]
    OutOfGas(gas::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// This can be used to sign an arbitrary tx. The signature is produced and
/// verified on the tx data concatenated with the tx code, however the tx code
/// itself is not part of this structure.
///
/// Because the signature is not checked by the ledger, we don't inline it into
/// the `Tx` type directly. Instead, the signature is attached to the `tx.data`,
/// which can then be checked by a validity predicate wasm.
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
///
/// This is a higher level version of [`key::SignableBytes`].
pub trait Signable<T> {
    /// A byte vector containing the serialized data.
    type Output: key::SignableBytes;

    /// The hashing algorithm to use to sign serialized
    /// data with.
    type Hasher: 'static + StorageHasher;

    /// Encodes `data` as a byte vector, with some arbitrary serialization
    /// method.
    ///
    /// The returned output *must* be deterministic based on
    /// `data`, so that two callers signing the same `data` will be
    /// signing the same `Self::Output`.
    fn as_signable(data: &T) -> Self::Output;
}

/// Tag type that indicates we should use [`BorshSerialize`]
/// to sign data in a [`Signed`] wrapper.
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct SerializeWithBorsh;

/// Tag type that indicates we should use ABI serialization
/// to sign data in a [`Signed`] wrapper.
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct SignableEthMessage;

impl<T: BorshSerialize> Signable<T> for SerializeWithBorsh {
    type Hasher = Sha256Hasher;
    type Output = Vec<u8>;

    fn as_signable(data: &T) -> Vec<u8> {
        data.serialize_to_vec()
    }
}

impl Signable<KeccakHash> for SignableEthMessage {
    type Hasher = KeccakHasher;
    type Output = KeccakHash;

    fn as_signable(hash: &KeccakHash) -> KeccakHash {
        keccak_hash({
            let mut eth_message = Vec::from("\x19Ethereum Signed Message:\n32");
            eth_message.extend_from_slice(hash.as_ref());
            eth_message
        })
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
impl<S, T: Ord> Ord for Signed<T, S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.cmp(&other.data)
    }
}

impl<S, T: BorshSchema> BorshSchema for Signed<T, S> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        let fields = borsh::schema::Fields::NamedFields(vec![
            ("data".to_string(), T::declaration()),
            ("sig".to_string(), <common::Signature>::declaration()),
        ]);
        let definition = borsh::schema::Definition::Struct { fields };
        add_definition(Self::declaration(), definition, definitions);
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
}

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
        hasher.update(self.serialize_to_vec());
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
    /// The tag for the transaction code
    pub tag: Option<String>,
}

impl Code {
    /// Make a new code section with the given bytes
    pub fn new(code: Vec<u8>, tag: Option<String>) -> Self {
        Self {
            salt: DateTimeUtc::now().0.timestamp_millis().to_le_bytes(),
            code: Commitment::Id(code),
            tag,
        }
    }

    /// Make a new code section with the given hash
    pub fn from_hash(
        hash: crate::types::hash::Hash,
        tag: Option<String>,
    ) -> Self {
        Self {
            salt: DateTimeUtc::now().0.timestamp_millis().to_le_bytes(),
            code: Commitment::Hash(hash),
            tag,
        }
    }

    /// Hash this code section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.salt);
        hasher.update(self.code.hash());
        hasher.update(self.tag.serialize_to_vec());
        hasher
    }
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
pub struct SignatureIndex {
    pub pubkey: common::PublicKey,
    pub index: Option<(Address, u8)>,
    pub signature: common::Signature,
}

impl SignatureIndex {
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

    pub fn to_vec(&self) -> Vec<Self> {
        vec![self.clone()]
    }

    pub fn serialize(&self) -> String {
        let signature_bytes = self.serialize_to_vec();
        HEXUPPER.encode(&signature_bytes)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if let Ok(hex) = serde_json::from_slice::<String>(data) {
            match HEXUPPER.decode(hex.as_bytes()) {
                Ok(bytes) => Self::try_from_slice(&bytes)
                    .map_err(Error::TxDeserializingError),
                Err(_) => Err(Error::OfflineTxDeserializationError),
            }
        } else {
            Err(Error::OfflineTxDeserializationError)
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

/// Indicates the list of public keys against which signatures will be verified
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub enum Signer {
    /// The address of a multisignature account
    Address(Address),
    /// The public keys that constitute a signer
    PubKeys(Vec<common::PublicKey>),
}

/// A section representing a multisig over another section
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
    /// The hash of the section being signed
    pub targets: Vec<crate::types::hash::Hash>,
    /// The public keys against which the signatures should be verified
    pub signer: Signer,
    /// The signature over the above hash
    pub signatures: BTreeMap<u8, common::Signature>,
}

impl Signature {
    /// Sign the given section hash with the given key and return a section
    pub fn new(
        targets: Vec<crate::types::hash::Hash>,
        secret_keys: BTreeMap<u8, common::SecretKey>,
        signer: Option<Address>,
    ) -> Self {
        // If no signer address is given, then derive the signer's public keys
        // from the given secret keys.
        let signer = if let Some(addr) = signer {
            Signer::Address(addr)
        } else {
            // Make sure the corresponding public keys can be represented by a
            // vector instead of a map
            assert!(
                secret_keys.keys().cloned().eq(0..(secret_keys.len() as u8)),
                "secret keys must be enumerated when signer address is absent"
            );
            Signer::PubKeys(secret_keys.values().map(RefTo::ref_to).collect())
        };

        // Commit to the given targets
        let partial = Self {
            targets,
            signer,
            signatures: BTreeMap::new(),
        };
        let target = partial.get_raw_hash();
        // Turn the map of secret keys into a map of signatures over the
        // commitment made above
        let signatures = secret_keys
            .iter()
            .map(|(index, secret_key)| {
                (*index, common::SigScheme::sign(secret_key, target))
            })
            .collect();
        Self {
            signatures,
            ..partial
        }
    }

    pub fn total_signatures(&self) -> u8 {
        self.signatures.len() as u8
    }

    /// Hash this signature section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }

    /// Get the hash of this section
    pub fn get_hash(&self) -> crate::types::hash::Hash {
        crate::types::hash::Hash(
            self.hash(&mut Sha256::new()).finalize_reset().into(),
        )
    }

    pub fn get_raw_hash(&self) -> crate::types::hash::Hash {
        Self {
            signer: Signer::PubKeys(vec![]),
            signatures: BTreeMap::new(),
            ..self.clone()
        }
        .get_hash()
    }

    /// Verify that the signature contained in this section is valid
    pub fn verify_signature<F>(
        &self,
        verified_pks: &mut HashSet<u8>,
        public_keys_index_map: &AccountPublicKeysMap,
        signer: &Option<Address>,
        consume_verify_sig_gas: &mut F,
    ) -> std::result::Result<u8, VerifySigError>
    where
        F: FnMut() -> std::result::Result<(), crate::ledger::gas::Error>,
    {
        // Records whether there are any successful verifications
        let mut verifications = 0;
        match &self.signer {
            // Verify the signatures against the given public keys if the
            // account addresses match
            Signer::Address(addr) if Some(addr) == signer.as_ref() => {
                for (idx, sig) in &self.signatures {
                    if let Some(pk) =
                        public_keys_index_map.get_public_key_from_index(*idx)
                    {
                        consume_verify_sig_gas()?;
                        common::SigScheme::verify_signature(
                            &pk,
                            &self.get_raw_hash(),
                            sig,
                        )?;
                        verified_pks.insert(*idx);
                        verifications += 1;
                    }
                }
            }
            // If the account addresses do not match, then there is no efficient
            // way to map signatures to the given public keys
            Signer::Address(_) => {}
            // Verify the signatures against the subset of this section's public
            // keys that are also in the given map
            Signer::PubKeys(pks) => {
                for (idx, pk) in pks.iter().enumerate() {
                    if let Some(map_idx) =
                        public_keys_index_map.get_index_from_public_key(pk)
                    {
                        consume_verify_sig_gas()?;
                        common::SigScheme::verify_signature(
                            pk,
                            &self.get_raw_hash(),
                            &self.signatures[&(idx as u8)],
                        )?;
                        verified_pks.insert(map_idx);
                        verifications += 1;
                    }
                }
            }
        }
        Ok(verifications)
    }
}

/// A section representing a multisig over another section
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct CompressedSignature {
    /// The hash of the section being signed
    pub targets: Vec<u8>,
    /// The public keys against which the signatures should be verified
    pub signer: Signer,
    /// The signature over the above hash
    pub signatures: BTreeMap<u8, common::Signature>,
}

impl CompressedSignature {
    /// Decompress this signature object with respect to the given transaction
    /// by looking up the necessary section hashes. Used by constrained hardware
    /// wallets.
    pub fn expand(self, tx: &Tx) -> Signature {
        let mut targets = Vec::new();
        for idx in self.targets {
            if idx == 0 {
                // The "zeroth" section is the header
                targets.push(tx.header_hash());
            } else if idx == 255 {
                // The 255th section is the raw header
                targets.push(tx.raw_header_hash());
            } else {
                targets.push(tx.sections[idx as usize - 1].get_hash());
            }
        }
        Signature {
            targets,
            signer: self.signer,
            signatures: self.signatures,
        }
    }
}

/// Represents a section obtained by encrypting another section
#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct Ciphertext {
    /// Ciphertext representation when ferveo not available
    pub opaque: Vec<u8>,
}

impl Ciphertext {
    /// Get the hash of this ciphertext section. This operation is done in such
    /// a way it matches the hash of the type pun
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
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
    Into::<T>::into(obj.serialize_to_vec()).serialize(ser)
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
    pub asset_types: HashSet<(Address, MaspDenom, Option<Epoch>)>,
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
        hasher.update(self.serialize_to_vec());
        hasher
    }
}

impl borsh::BorshSchema for MaspBuilder {
    fn add_definitions_recursively(
        _definitions: &mut BTreeMap<
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
    /// A transaction header/protocol signature
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
    /// Wrap a header with a section for the purposes of computing hashes
    Header(Header),
}

impl Section {
    /// Hash this section. Section hashes are useful for signatures and also for
    /// allowing transaction sections to cross reference.
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        // Get the index corresponding to this variant
        let discriminant = self.serialize_to_vec()[0];
        // Use Borsh's discriminant in the Section's hash
        hasher.update([discriminant]);
        match self {
            Self::Data(data) => data.hash(hasher),
            Self::ExtraData(extra) => extra.hash(hasher),
            Self::Code(code) => code.hash(hasher),
            Self::Signature(signature) => signature.hash(hasher),
            Self::Ciphertext(ct) => ct.hash(hasher),
            Self::MaspBuilder(mb) => mb.hash(hasher),
            Self::MaspTx(tx) => {
                hasher.update(tx.txid().as_ref());
                hasher
            }
            Self::Header(header) => header.hash(hasher),
        }
    }

    /// Get the hash of this section
    pub fn get_hash(&self) -> crate::types::hash::Hash {
        crate::types::hash::Hash(
            self.hash(&mut Sha256::new()).finalize_reset().into(),
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
        hasher.update(self.serialize_to_vec());
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

impl Default for Tx {
    fn default() -> Self {
        Self {
            header: Header::new(TxType::Raw),
            sections: vec![],
        }
    }
}

impl Tx {
    /// Initialize a new transaction builder
    pub fn new(chain_id: ChainId, expiration: Option<DateTimeUtc>) -> Self {
        Tx {
            sections: vec![],
            header: Header {
                chain_id,
                expiration,
                ..Header::new(TxType::Raw)
            },
        }
    }

    /// Create a transaction of the given type
    pub fn from_type(header: TxType) -> Self {
        Tx {
            header: Header::new(header),
            sections: vec![],
        }
    }

    /// Serialize tx to hex string
    pub fn serialize(&self) -> String {
        let tx_bytes = self.serialize_to_vec();
        HEXUPPER.encode(&tx_bytes)
    }

    // Deserialize from hex encoding
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if let Ok(hex) = serde_json::from_slice::<String>(data) {
            match HEXUPPER.decode(hex.as_bytes()) {
                Ok(bytes) => Tx::try_from_slice(&bytes)
                    .map_err(Error::TxDeserializingError),
                Err(_) => Err(Error::OfflineTxDeserializationError),
            }
        } else {
            Err(Error::OfflineTxDeserializationError)
        }
    }

    /// Get the transaction header
    pub fn header(&self) -> Header {
        self.header.clone()
    }

    /// Get the transaction header hash
    pub fn header_hash(&self) -> crate::types::hash::Hash {
        Section::Header(self.header.clone()).get_hash()
    }

    /// Gets the hash of the decrypted transaction's header
    pub fn raw_header_hash(&self) -> crate::types::hash::Hash {
        let mut raw_header = self.header();
        raw_header.tx_type = TxType::Raw;

        Section::Header(raw_header).get_hash()
    }

    /// Get hashes of all the sections in this transaction
    pub fn sechashes(&self) -> Vec<crate::types::hash::Hash> {
        let mut hashes = vec![self.header_hash()];
        for sec in &self.sections {
            hashes.push(sec.get_hash());
        }
        hashes
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
    ) -> Option<Cow<Section>> {
        if self.header_hash() == *hash {
            return Some(Cow::Owned(Section::Header(self.header.clone())));
        } else if self.raw_header_hash() == *hash {
            let mut header = self.header();
            header.tx_type = TxType::Raw;
            return Some(Cow::Owned(Section::Header(header)));
        }
        for section in &self.sections {
            if section.get_hash() == *hash {
                return Some(Cow::Borrowed(section));
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
        match self
            .get_section(self.code_sechash())
            .as_ref()
            .map(Cow::as_ref)
        {
            Some(Section::Code(section)) => section.code.id(),
            _ => None,
        }
    }

    /// Add the given code to the transaction and set code hash in the header
    pub fn set_code(&mut self, code: Code) -> &mut Section {
        let sec = Section::Code(code);
        self.set_code_sechash(sec.get_hash());
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
        self.set_data_sechash(sec.get_hash());
        self.sections.push(sec);
        self.sections.last_mut().unwrap()
    }

    /// Get the data designated by the transaction data hash in the header
    pub fn data(&self) -> Option<Vec<u8>> {
        match self
            .get_section(self.data_sechash())
            .as_ref()
            .map(Cow::as_ref)
        {
            Some(Section::Data(data)) => Some(data.data.clone()),
            _ => None,
        }
    }

    /// Convert this transaction into protobufs
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let tx: types::Tx = types::Tx {
            data: self.serialize_to_vec(),
        };
        tx.encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    /// Verify that the section with the given hash has been signed by the given
    /// public key
    pub fn verify_signatures<F>(
        &self,
        hashes: &[crate::types::hash::Hash],
        public_keys_index_map: AccountPublicKeysMap,
        signer: &Option<Address>,
        threshold: u8,
        max_signatures: Option<u8>,
        mut consume_verify_sig_gas: F,
    ) -> std::result::Result<Vec<&Signature>, Error>
    where
        F: FnMut() -> std::result::Result<(), crate::ledger::gas::Error>,
    {
        let max_signatures = max_signatures.unwrap_or(u8::MAX);
        // Records the public key indices used in successful signatures
        let mut verified_pks = HashSet::new();
        // Records the sections instrumental in verifying signatures
        let mut witnesses = Vec::new();

        for section in &self.sections {
            if let Section::Signature(signatures) = section {
                // Check that the hashes being checked are a subset of those in
                // this section. Also ensure that all the sections the signature
                // signs over are present.
                if hashes.iter().all(|x| {
                    signatures.targets.contains(x) || section.get_hash() == *x
                }) && signatures
                    .targets
                    .iter()
                    .all(|x| self.get_section(x).is_some())
                {
                    if signatures.total_signatures() > max_signatures {
                        return Err(Error::InvalidSectionSignature(
                            "too many signatures.".to_string(),
                        ));
                    }

                    // Finally verify that the signature itself is valid
                    let amt_verifieds = signatures
                        .verify_signature(
                            &mut verified_pks,
                            &public_keys_index_map,
                            signer,
                            &mut consume_verify_sig_gas,
                        )
                        .map_err(|e| {
                            if let VerifySigError::OutOfGas(inner) = e {
                                Error::OutOfGas(inner)
                            } else {
                                Error::InvalidSectionSignature(
                                    "found invalid signature.".to_string(),
                                )
                            }
                        });
                    // Record the section witnessing these signatures
                    if amt_verifieds? > 0 {
                        witnesses.push(signatures);
                    }
                    // Short-circuit these checks if the threshold is exceeded
                    if verified_pks.len() >= threshold.into() {
                        return Ok(witnesses);
                    }
                }
            }
        }
        Err(Error::InvalidSectionSignature(format!(
            "signature threshold not met: ({} < {})",
            verified_pks.len(),
            threshold
        )))
    }

    /// Verify that the sections with the given hashes have been signed together
    /// by the given public key. I.e. this function looks for one signature that
    /// covers over the given slice of hashes.
    /// Note that this method doesn't consider gas cost and hence it shouldn't
    /// be used from txs or VPs.
    pub fn verify_signature(
        &self,
        public_key: &common::PublicKey,
        hashes: &[crate::types::hash::Hash],
    ) -> Result<&Signature> {
        self.verify_signatures(
            hashes,
            AccountPublicKeysMap::from_iter([public_key.clone()].into_iter()),
            &None,
            1,
            None,
            || Ok(()),
        )
        .map(|x| *x.first().unwrap())
        .map_err(|_| Error::InvalidWrapperSignature)
    }

    pub fn compute_section_signature(
        &self,
        secret_keys: &[common::SecretKey],
        public_keys_index_map: &AccountPublicKeysMap,
        signer: Option<Address>,
    ) -> Vec<SignatureIndex> {
        let targets = vec![self.raw_header_hash()];
        let mut signatures = Vec::new();
        let section = Signature::new(
            targets,
            public_keys_index_map.index_secret_keys(secret_keys.to_vec()),
            signer,
        );
        match section.signer {
            Signer::Address(addr) => {
                for (idx, signature) in section.signatures {
                    signatures.push(SignatureIndex {
                        pubkey: public_keys_index_map
                            .get_public_key_from_index(idx)
                            .unwrap(),
                        index: Some((addr.clone(), idx)),
                        signature,
                    });
                }
            }
            Signer::PubKeys(pub_keys) => {
                for (idx, signature) in section.signatures {
                    signatures.push(SignatureIndex {
                        pubkey: pub_keys[idx as usize].clone(),
                        index: None,
                        signature,
                    });
                }
            }
        }
        signatures
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
    pub fn validate_tx(
        &self,
    ) -> std::result::Result<Option<&Signature>, TxError> {
        match &self.header.tx_type {
            // verify signature and extract signed data
            TxType::Wrapper(wrapper) => self
                .verify_signature(&wrapper.pk, &self.sechashes())
                .map(Option::Some)
                .map_err(|err| {
                    TxError::SigError(format!(
                        "WrapperTx signature verification failed: {}",
                        err
                    ))
                }),
            // verify signature and extract signed data
            TxType::Protocol(protocol) => self
                .verify_signature(&protocol.pk, &self.sechashes())
                .map(Option::Some)
                .map_err(|err| {
                    TxError::SigError(format!(
                        "ProtocolTx signature verification failed: {}",
                        err
                    ))
                }),
            // we extract the signed data, but don't check the signature
            TxType::Decrypted(_) => Ok(None),
            // return as is
            TxType::Raw => Ok(None),
        }
    }

    /// Filter out all the sections that must not be submitted to the protocol
    /// and return them.
    pub fn protocol_filter(&mut self) -> Vec<Section> {
        let mut filtered = Vec::new();
        for i in (0..self.sections.len()).rev() {
            if let Section::MaspBuilder(_) = self.sections[i] {
                // MASP Builders containing extended full viewing keys amongst
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

    /// Add an extra section to the tx builder by hash
    pub fn add_extra_section_from_hash(
        &mut self,
        hash: crate::types::hash::Hash,
        tag: Option<String>,
    ) -> crate::types::hash::Hash {
        let sechash = self
            .add_section(Section::ExtraData(Code::from_hash(hash, tag)))
            .get_hash();
        sechash
    }

    /// Add an extra section to the tx builder by code
    pub fn add_extra_section(
        &mut self,
        code: Vec<u8>,
        tag: Option<String>,
    ) -> (&mut Self, crate::types::hash::Hash) {
        let sechash = self
            .add_section(Section::ExtraData(Code::new(code, tag)))
            .get_hash();
        (self, sechash)
    }

    /// Add a masp tx section to the tx builder
    pub fn add_masp_tx_section(
        &mut self,
        tx: Transaction,
    ) -> (&mut Self, crate::types::hash::Hash) {
        let sechash = self.add_section(Section::MaspTx(tx)).get_hash();
        (self, sechash)
    }

    /// Add a masp builder section to the tx builder
    pub fn add_masp_builder(&mut self, builder: MaspBuilder) -> &mut Self {
        let _sec = self.add_section(Section::MaspBuilder(builder));
        self
    }

    /// Add wasm code to the tx builder from hash
    pub fn add_code_from_hash(
        &mut self,
        code_hash: crate::types::hash::Hash,
        tag: Option<String>,
    ) -> &mut Self {
        self.set_code(Code::from_hash(code_hash, tag));
        self
    }

    /// Add wasm code to the tx builder
    pub fn add_code(
        &mut self,
        code: Vec<u8>,
        tag: Option<String>,
    ) -> &mut Self {
        self.set_code(Code::new(code, tag));
        self
    }

    /// Add wasm data to the tx builder
    pub fn add_data(&mut self, data: impl BorshSerialize) -> &mut Self {
        let bytes = data.serialize_to_vec();
        self.set_data(Data::new(bytes));
        self
    }

    /// Add wasm data already serialized to the tx builder
    pub fn add_serialized_data(&mut self, bytes: Vec<u8>) -> &mut Self {
        self.set_data(Data::new(bytes));
        self
    }

    /// Add wrapper tx to the tx builder
    pub fn add_wrapper(
        &mut self,
        fee: Fee,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
        fee_unshield_hash: Option<crate::types::hash::Hash>,
    ) -> &mut Self {
        self.header.tx_type = TxType::Wrapper(Box::new(WrapperTx::new(
            fee,
            fee_payer,
            epoch,
            gas_limit,
            fee_unshield_hash,
        )));
        self
    }

    /// Add fee payer keypair to the tx builder
    pub fn sign_wrapper(&mut self, keypair: common::SecretKey) -> &mut Self {
        self.protocol_filter();
        self.add_section(Section::Signature(Signature::new(
            self.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        self
    }

    /// Add signing keys to the tx builder
    pub fn sign_raw(
        &mut self,
        keypairs: Vec<common::SecretKey>,
        account_public_keys_map: AccountPublicKeysMap,
        signer: Option<Address>,
    ) -> &mut Self {
        // The inner tx signer signs the Decrypted version of the Header
        let hashes = vec![self.raw_header_hash()];
        self.protocol_filter();

        let secret_keys = if signer.is_some() {
            account_public_keys_map.index_secret_keys(keypairs)
        } else {
            (0..).zip(keypairs.into_iter()).collect()
        };

        self.add_section(Section::Signature(Signature::new(
            hashes,
            secret_keys,
            signer,
        )));
        self
    }

    /// Add signatures
    pub fn add_signatures(
        &mut self,
        signatures: Vec<SignatureIndex>,
    ) -> &mut Self {
        self.protocol_filter();
        let mut pk_section = Signature {
            targets: vec![self.raw_header_hash()],
            signatures: BTreeMap::new(),
            signer: Signer::PubKeys(vec![]),
        };
        let mut sections = HashMap::new();
        // Put the supplied signatures into the correct sections
        for signature in signatures {
            if let Some((addr, idx)) = &signature.index {
                // Add the signature under the given multisig address
                let section =
                    sections.entry(addr.clone()).or_insert_with(|| Signature {
                        targets: vec![self.raw_header_hash()],
                        signatures: BTreeMap::new(),
                        signer: Signer::Address(addr.clone()),
                    });
                section.signatures.insert(*idx, signature.signature);
            } else if let Signer::PubKeys(pks) = &mut pk_section.signer {
                // Add the signature under its corresponding public key
                pk_section
                    .signatures
                    .insert(pks.len() as u8, signature.signature);
                pks.push(signature.pubkey);
            }
        }
        for section in std::iter::once(pk_section).chain(sections.into_values())
        {
            self.add_section(Section::Signature(section));
        }
        self
    }
}
