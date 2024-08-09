use std::num::ParseIntError;
use std::str::FromStr;

pub use ark_bls12_381::Bls12_381 as EllipticCurve;
use namada_core::address::Address;
use namada_core::borsh::{
    BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
};
use namada_core::key::*;
use namada_core::token::{Amount, DenominatedAmount};
use namada_core::uint::Uint;
use namada_gas::{Gas, WholeGas};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors relating to decrypting a wrapper tx and its
/// encrypted payload from a Tx type
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum WrapperTxErr {
    #[error("The hash of the decrypted tx does not match the hash commitment")]
    DecryptedHash,
    #[error("The decryption did not produce a valid Tx")]
    InvalidTx,
    #[error("The given Tx data did not contain a valid WrapperTx")]
    InvalidWrapperTx,
    #[error(
        "Attempted to sign WrapperTx with keypair whose public key differs \
         from that in the WrapperTx"
    )]
    InvalidKeyPair,
    #[error("The given Tx fee amount overflowed")]
    OverflowingFee,
    #[error("Error while converting the denominated fee amount")]
    DenominatedFeeConversion,
}

/// Amount of some specified token to pay for fees.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    Eq,
)]
pub struct Fee {
    /// Amount of fees paid per gas unit.
    pub amount_per_gas_unit: DenominatedAmount,
    /// Address of the fee token.
    pub token: Address,
}

/// Gas limit of a transaction
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    Eq,
)]
pub struct GasLimit(u64);

/// Round the input number up to the next highest multiple
/// of GAS_LIMIT_RESOLUTION
impl From<u64> for GasLimit {
    fn from(amount: u64) -> GasLimit {
        Self(amount)
    }
}

/// Get back the gas limit as a raw number
impl From<GasLimit> for u64 {
    fn from(limit: GasLimit) -> u64 {
        limit.0
    }
}

impl From<GasLimit> for Uint {
    fn from(limit: GasLimit) -> Self {
        Uint::from_u64(limit.into())
    }
}

impl FromStr for GasLimit {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

/// Get back the gas limit as a raw number, viewed as an Amount
impl From<GasLimit> for Amount {
    fn from(limit: GasLimit) -> Amount {
        Amount::from_uint(limit.0, 0).unwrap()
    }
}

impl From<GasLimit> for WholeGas {
    fn from(value: GasLimit) -> Self {
        value.0.into()
    }
}

impl From<WholeGas> for GasLimit {
    fn from(value: WholeGas) -> Self {
        u64::from(value).into()
    }
}

impl GasLimit {
    /// Convert the gas limit into scaled gas
    pub fn as_scaled_gas(self, scale: u64) -> Result<Gas, std::io::Error> {
        Gas::from_whole_units(self.into(), scale).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "gas overflow",
            )
        })
    }
}

/// A transaction with an encrypted payload, an optional shielded pool
/// unshielding tx for fee payment and some non-encrypted metadata for
/// inclusion and / or verification purposes
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
    PartialEq,
)]
pub struct WrapperTx {
    /// The fee to be paid for including the tx
    pub fee: Fee,
    /// Used for signature verification and to determine an implicit
    /// account of the fee payer
    pub pk: common::PublicKey,
    /// Max amount of gas that can be used when executing the inner tx
    pub gas_limit: GasLimit,
}

impl WrapperTx {
    /// Create a new wrapper tx from the personal keypair,
    /// an optional unshielding tx, and the metadata surrounding the
    /// inclusion of the tx.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fee: Fee,
        pk: common::PublicKey,
        gas_limit: GasLimit,
    ) -> WrapperTx {
        Self { fee, pk, gas_limit }
    }

    /// Get the address of the implicit account associated
    /// with the public key
    /// NOTE: this is safe in case someone tried to use the masp address to
    /// pay fees. All of the masp funds are kept in the established address,
    /// while the implicit one has no funds leading to a tx failure
    pub fn fee_payer(&self) -> Address {
        Address::from(&self.pk)
    }

    /// Produce a SHA-256 hash of this section
    pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
        hasher.update(self.serialize_to_vec());
        hasher
    }

    /// Get the [`Amount`] of fees to be paid by the given wrapper. Returns
    /// an error if the amount overflows
    pub fn get_tx_fee(&self) -> Result<DenominatedAmount, WrapperTxErr> {
        self.fee
            .amount_per_gas_unit
            .checked_mul(Amount::from(self.gas_limit).into())
            .ok_or(WrapperTxErr::OverflowingFee)
    }
}

#[cfg(test)]
mod test_gas_limits {
    use super::*;

    /// Test serializing and deserializing again gives back original object
    /// Test that serializing converts GasLimit to u64 correctly
    #[test]
    fn test_gas_limit_roundtrip() {
        let limit = GasLimit(1);
        // Test serde roundtrip
        let js = serde_json::to_string(&1).expect("Test failed");
        let new_limit: u64 = serde_json::from_str(&js).expect("Test failed");
        assert_eq!(GasLimit(new_limit), limit);

        // Test borsh roundtrip
        let borsh = limit.serialize_to_vec();
        assert_eq!(
            limit,
            BorshDeserialize::deserialize(&mut borsh.as_ref())
                .expect("Test failed")
        );
    }
}
