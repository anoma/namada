//! secp256k1 keys and related functionality

use std::fmt;
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Write};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXLOWER;
use libsecp256k1::RecoveryId;
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize, Serializer};

use super::{
    ParsePublicKeyError, ParseSecretKeyError, ParseSignatureError, RefTo,
    SchemeType, SigScheme as SigSchemeTrait, VerifySigError,
};

/// secp256k1 public key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(pub libsecp256k1::PublicKey);

impl super::PublicKey for PublicKey {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_pk<PK: super::PublicKey>(
        pk: &PK,
    ) -> Result<Self, ParsePublicKeyError> {
        if PK::TYPE == super::common::PublicKey::TYPE {
            super::common::PublicKey::try_from_pk(pk).and_then(|x| match x {
                super::common::PublicKey::Secp256k1(epk) => Ok(epk),
                _ => Err(ParsePublicKeyError::MismatchedScheme),
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice())
                .map_err(ParsePublicKeyError::InvalidEncoding)
        } else {
            Err(ParsePublicKeyError::MismatchedScheme)
        }
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let pk = libsecp256k1::PublicKey::parse_compressed(
            buf.get(0..libsecp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE)
                .ok_or_else(|| std::io::Error::from(ErrorKind::UnexpectedEof))?
                .try_into()
                .unwrap(),
        )
        .map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding secp256k1 public key: {}", e),
            )
        })?;
        *buf = &buf[libsecp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE..];
        Ok(PublicKey(pk))
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.serialize_compressed())?;
        Ok(())
    }
}

impl BorshSchema for PublicKey {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `[u8; COMPRESSED_PUBLIC_KEY_SIZE]`
        let elements = "u8".into();
        let length = libsecp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE as u32;
        let definition = borsh::schema::Definition::Array { elements, length };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "secp256k1::PublicKey".into()
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.serialize_compressed().hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0
            .serialize_compressed()
            .partial_cmp(&other.0.serialize_compressed())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .serialize_compressed()
            .cmp(&other.0.serialize_compressed())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0.serialize_compressed()))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = HEXLOWER
            .decode(s.as_bytes())
            .map_err(ParsePublicKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParsePublicKeyError::InvalidEncoding)
    }
}

impl From<libsecp256k1::PublicKey> for PublicKey {
    fn from(pk: libsecp256k1::PublicKey) -> Self {
        Self(pk)
    }
}

/// Secp256k1 secret key
#[derive(Debug, Clone)]
pub struct SecretKey(pub Box<libsecp256k1::SecretKey>);

impl super::SecretKey for SecretKey {
    type PublicKey = PublicKey;

    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sk<PK: super::SecretKey>(
        pk: &PK,
    ) -> Result<Self, ParseSecretKeyError> {
        if PK::TYPE == super::common::SecretKey::TYPE {
            super::common::SecretKey::try_from_sk(pk).and_then(|x| match x {
                super::common::SecretKey::Secp256k1(epk) => Ok(epk),
                _ => Err(ParseSecretKeyError::MismatchedScheme),
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice())
                .map_err(ParseSecretKeyError::InvalidEncoding)
        } else {
            Err(ParseSecretKeyError::MismatchedScheme)
        }
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let arr = self.0.serialize();
        serde::Serialize::serialize(&arr, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let arr_res: [u8; libsecp256k1::util::SECRET_KEY_SIZE] =
            serde::Deserialize::deserialize(deserializer)?;
        let key = libsecp256k1::SecretKey::parse_slice(&arr_res)
            .map_err(D::Error::custom);
        Ok(SecretKey(Box::new(key.unwrap())))
    }
}

impl BorshDeserialize for SecretKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        Ok(SecretKey(Box::new(
            libsecp256k1::SecretKey::parse(
                &(BorshDeserialize::deserialize(buf)?),
            )
            .map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding secp256k1 secret key: {}", e),
                )
            })?,
        )))
    }
}

impl BorshSerialize for SecretKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.serialize(), writer)
    }
}

impl BorshSchema for SecretKey {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `[u8; SECRET_KEY_SIZE]`
        let elements = "u8".into();
        let length = libsecp256k1::util::SECRET_KEY_SIZE as u32;
        let definition = borsh::schema::Definition::Array { elements, length };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "secp256k1::SecretKey".into()
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0.serialize()))
    }
}

impl FromStr for SecretKey {
    type Err = ParseSecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = HEXLOWER
            .decode(s.as_bytes())
            .map_err(ParseSecretKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParseSecretKeyError::InvalidEncoding)
    }
}

impl RefTo<PublicKey> for SecretKey {
    fn ref_to(&self) -> PublicKey {
        PublicKey(libsecp256k1::PublicKey::from_secret_key(&self.0))
    }
}

/// Secp256k1 signature
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature(pub libsecp256k1::Signature, pub RecoveryId);

impl super::Signature for Signature {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sig<PK: super::Signature>(
        pk: &PK,
    ) -> Result<Self, ParseSignatureError> {
        if PK::TYPE == super::common::Signature::TYPE {
            super::common::Signature::try_from_sig(pk).and_then(|x| match x {
                super::common::Signature::Secp256k1(epk) => Ok(epk),
                _ => Err(ParseSignatureError::MismatchedScheme),
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice())
                .map_err(ParseSignatureError::InvalidEncoding)
        } else {
            Err(ParseSignatureError::MismatchedScheme)
        }
    }
}

// Would ideally like Serialize, Deserialize to be implemented in libsecp256k1,
// may try to do so and merge upstream in the future.

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let arr = self.0.serialize();
        // TODO: implement the line below, currently cannot support [u8; 64]
        // serde::Serialize::serialize(&arr, serializer)

        let mut seq = serializer.serialize_tuple(arr.len())?;
        for elem in &arr[..] {
            seq.serialize_element(elem)?;
        }
        seq.serialize_element(&self.1.serialize())?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ByteArrayVisitor;

        impl<'de> Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; libsecp256k1::util::SIGNATURE_SIZE + 1];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&format!(
                    "an array of length {}",
                    libsecp256k1::util::SIGNATURE_SIZE
                ))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 65], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; libsecp256k1::util::SIGNATURE_SIZE + 1];
                #[allow(clippy::needless_range_loop)]
                for i in 0..libsecp256k1::util::SIGNATURE_SIZE + 1 {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        let arr_res = deserializer.deserialize_tuple(
            libsecp256k1::util::SIGNATURE_SIZE + 1,
            ByteArrayVisitor,
        )?;
        let sig_array: [u8; 64] = arr_res[..64].try_into().unwrap();
        let sig = libsecp256k1::Signature::parse_standard(&sig_array)
            .map_err(D::Error::custom);
        Ok(Signature(
            sig.unwrap(),
            RecoveryId::parse(arr_res[64]).map_err(Error::custom)?,
        ))
    }
}

impl BorshDeserialize for Signature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let (sig_bytes, recovery_id) = BorshDeserialize::deserialize(buf)?;

        Ok(Signature(
            libsecp256k1::Signature::parse_standard(&sig_bytes).map_err(
                |e| {
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("Error decoding secp256k1 signature: {}", e),
                    )
                },
            )?,
            RecoveryId::parse(recovery_id).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding secp256k1 signature: {}", e),
                )
            })?,
        ))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(
            &(self.0.serialize(), self.1.serialize()),
            writer,
        )
    }
}

impl BorshSchema for Signature {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `([u8; SIGNATURE_SIZE], u8)`
        let signature =
            <[u8; libsecp256k1::util::SIGNATURE_SIZE]>::declaration();
        <[u8; libsecp256k1::util::SIGNATURE_SIZE]>::add_definitions_recursively(
            definitions,
        );
        let recovery = "u8".into();
        let definition = borsh::schema::Definition::Tuple {
            elements: vec![signature, recovery],
        };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "secp256k1::Signature".into()
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.serialize().hash(state);
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.serialize().partial_cmp(&other.0.serialize())
    }
}

impl TryFrom<&[u8; 65]> for Signature {
    type Error = ParseSignatureError;

    fn try_from(sig: &[u8; 65]) -> Result<Self, Self::Error> {
        let sig_bytes = sig[..64].try_into().unwrap();
        let recovery_id = RecoveryId::parse(sig[64]).map_err(|err| {
            ParseSignatureError::InvalidEncoding(std::io::Error::new(
                ErrorKind::Other,
                err,
            ))
        })?;
        libsecp256k1::Signature::parse_standard(&sig_bytes)
            .map(|sig| Self(sig, recovery_id))
            .map_err(|err| {
                ParseSignatureError::InvalidEncoding(std::io::Error::new(
                    ErrorKind::Other,
                    err,
                ))
            })
    }
}

/// An implementation of the Secp256k1 signature scheme
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Default,
)]
pub struct SigScheme;

impl super::SigScheme for SigScheme {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    const TYPE: SchemeType = SchemeType::Secp256k1;

    #[cfg(feature = "rand")]
    fn generate<R>(csprng: &mut R) -> SecretKey
    where
        R: CryptoRng + RngCore,
    {
        SecretKey(Box::new(libsecp256k1::SecretKey::random(csprng)))
    }

    fn from_seed(_seed: [u8; 32]) -> SecretKey {
        unimplemented!()
    }

    /// Sign the data with a key
    fn sign(keypair: &SecretKey, data: impl AsRef<[u8]>) -> Self::Signature {
        #[cfg(not(any(test, feature = "secp256k1-sign-verify")))]
        {
            // to avoid `unused-variables` warn
            let _ = (keypair, data);
            panic!("\"secp256k1-sign-verify\" feature must be enabled");
        }

        #[cfg(any(test, feature = "secp256k1-sign-verify"))]
        {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data.as_ref());
            let message = libsecp256k1::Message::parse_slice(hash.as_ref())
                .expect("Message encoding should not fail");
            let (sig, recovery_id) = libsecp256k1::sign(&message, &keypair.0);
            Signature(sig, recovery_id)
        }
    }

    fn verify_signature<T: BorshSerialize>(
        pk: &Self::PublicKey,
        data: &T,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        #[cfg(not(any(test, feature = "secp256k1-sign-verify")))]
        {
            // to avoid `unused-variables` warn
            let _ = (pk, data, sig);
            panic!("\"secp256k1-sign-verify\" feature must be enabled");
        }

        #[cfg(any(test, feature = "secp256k1-sign-verify"))]
        {
            use sha2::{Digest, Sha256};
            let bytes = &data
                .try_to_vec()
                .map_err(VerifySigError::DataEncodingError)?[..];
            let hash = Sha256::digest(bytes);
            let message = &libsecp256k1::Message::parse_slice(hash.as_ref())
                .expect("Error parsing given data");
            let is_valid = libsecp256k1::verify(message, &sig.0, &pk.0);
            if is_valid {
                Ok(())
            } else {
                Err(VerifySigError::SigVerifyError(format!(
                    "Error verifying secp256k1 signature: {}",
                    libsecp256k1::Error::InvalidSignature
                )))
            }
        }
    }

    fn verify_signature_raw(
        pk: &Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        #[cfg(not(any(test, feature = "secp256k1-sign-verify")))]
        {
            // to avoid `unused-variables` warn
            let _ = (pk, data, sig);
            panic!("\"secp256k1-sign-verify\" feature must be enabled");
        }

        #[cfg(any(test, feature = "secp256k1-sign-verify"))]
        {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            let message = &libsecp256k1::Message::parse_slice(hash.as_ref())
                .expect("Error parsing raw data");
            let is_valid = libsecp256k1::verify(message, &sig.0, &pk.0);
            if is_valid {
                Ok(())
            } else {
                Err(VerifySigError::SigVerifyError(format!(
                    "Error verifying secp256k1 signature: {}",
                    libsecp256k1::Error::InvalidSignature
                )))
            }
        }
    }
}
