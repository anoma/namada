//! Types that are used in transactions.
use std::fmt;
use std::io::{Error, ErrorKind, Write};

use ark_bls12_381::Bls12_381 as EllipticCurve;
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tpke::Ciphertext;

use crate::types::address::Address;
use crate::types::key::ed25519::{
    verify_signature, PublicKey, Signature, VerifySigError,
};
use crate::types::storage::Epoch;
use crate::types::token::Amount;

/// TODO: Determine a sane number for this
const GAS_LIMIT_RESOLUTION: u64 = 1_000_000;
/// We use a specific choice of two groups and bilinear pairing
/// We use a wrapper type to add traits
#[derive(Clone, Debug)]
pub struct EncryptedTx(Ciphertext<EllipticCurve>);

impl borsh::ser::BorshSerialize for EncryptedTx {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let Ciphertext {
            nonce,
            ciphertext,
            auth_tag,
        } = &self.0;
        // Serialize the nonce into bytes
        let mut nonce_buffer = Vec::<u8>::new();
        nonce
            .serialize(&mut nonce_buffer)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        // serialize the auth_tag to bytes
        let mut tag_buffer = Vec::<u8>::new();
        auth_tag
            .serialize(&mut tag_buffer)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        // serialize the three byte arrays
        BorshSerialize::serialize(
            &(nonce_buffer, ciphertext, tag_buffer),
            writer,
        )?;
        Ok(())
    }
}

impl borsh::BorshDeserialize for EncryptedTx {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        type VecTuple = (Vec<u8>, Vec<u8>, Vec<u8>);
        let (nonce, ciphertext, auth_tag): VecTuple =
            BorshDeserialize::deserialize(buf)?;
        Ok(EncryptedTx(Ciphertext {
            nonce: CanonicalDeserialize::deserialize(&*nonce)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?,
            ciphertext,
            auth_tag: CanonicalDeserialize::deserialize(&*auth_tag)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?,
        }))
    }
}

impl Serialize for EncryptedTx {
    fn serialize<S>(&self, serialize: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let bytes = self
            .try_to_vec()
            .map_err(|err| serde::ser::Error::custom(format!("{:?}", err)))?;
        serialize.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for EncryptedTx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct TxVisitor;

        impl<'de> serde::de::Visitor<'de> for TxVisitor {
            type Value = EncryptedTx;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a serialized ciphertext of an Anoma tx")
            }

            fn visit_bytes<E>(self, mut v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                BorshDeserialize::deserialize(&mut v).map_err(|err| {
                    serde::de::Error::custom(format!("{:?}", err))
                })
            }
        }
        deserializer.deserialize_any(TxVisitor)
    }
}

/// A tx data type to update an account's validity predicate
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct UpdateVp {
    /// An address of the account
    pub addr: Address,
    /// The new VP code
    pub vp_code: Vec<u8>,
}

/// A fee is an amount of a specified token
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Fee {
    amount: Amount,
    token: Address,
}

/// Gas limits must be multiples of GAS_LIMIT_RESOLUTION
/// This is done to minimize the amount of information leak from
/// a wrapper tx. The larger the GAS_LIMIT_RESOLUTION, the
/// less info leaked.
///
/// This struct only stores the multiple of GAS_LIMIT_RESOLUTION,
/// not the raw amount
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct GasLimit {
    multiplier: u64,
}

impl GasLimit {
    /// We refund unused gas up to GAS_LIMIT_RESOLUTION
    pub fn refund_amount(&self, used_gas: u64) -> Amount {
        if used_gas < (u64::from(self) - GAS_LIMIT_RESOLUTION)
            || used_gas > u64::from(self)
        {
            0
        } else {
            u64::from(self) - used_gas
        }
        .into()
    }
}

/// Round the input number up to the next highest multiple
/// of GAS_LIMIT_RESOLUTION
impl From<u64> for GasLimit {
    fn from(amount: u64) -> GasLimit {
        GasLimit {
            multiplier: (amount / GAS_LIMIT_RESOLUTION) + 1,
        }
    }
}

/// Round the input number up to the next highest multiple
/// of GAS_LIMIT_RESOLUTION
impl From<Amount> for GasLimit {
    fn from(amount: Amount) -> GasLimit {
        GasLimit {
            multiplier: (u64::from(amount) / GAS_LIMIT_RESOLUTION) + 1,
        }
    }
}

/// Get back the gas limit as a raw number
impl From<&GasLimit> for u64 {
    fn from(limit: &GasLimit) -> u64 {
        limit.multiplier * GAS_LIMIT_RESOLUTION
    }
}

/// Get back the gas limit as a raw number, viewed as an Amount
impl From<GasLimit> for Amount {
    fn from(limit: GasLimit) -> Amount {
        Amount::from(limit.multiplier * GAS_LIMIT_RESOLUTION)
    }
}

/// A transaction with an encrypted payload as well
/// as some non-encrypted metadata for inclusion
/// and / or verification purposes
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct WrapperTx {
    /// The fee to be payed for including the tx
    pub fee: Fee,
    /// Used to determine an implicit account of the fee payer
    pub pk: PublicKey,
    /// The signature from the submitter of the tx
    pub sig: Signature,
    /// The epoch in which the tx is to be submitted. This determines
    /// which decryption key will be used
    pub epoch: Epoch,
    /// Max amount of gas that can be used when executing the inner tx
    gas_limit: GasLimit,
    /// the encrypted payload
    inner_tx: EncryptedTx,
}

impl WrapperTx {
    /// Get the address of the implicit account associated
    /// with the public key
    pub fn fee_payer(&self) -> Address {
        Address::from(&self.pk)
    }

    /// Check the signature of the transaction
    pub fn verify_signature(&self) -> Result<(), VerifySigError> {
        verify_signature(&self.pk, &self.fee, &self.sig)
    }

    /// A validity check on the ciphertext. Depends on a canonical choice of
    /// generator for the group G_1. At the moment, a choice is hard coded
    pub fn validate_ciphertext(&self) -> bool {
        self.inner_tx.0.check(&<EllipticCurve as PairingEngine>::G1Prepared::from(
            -<EllipticCurve as PairingEngine>::G1Affine::prime_subgroup_generator(),
        ))
    }
}
