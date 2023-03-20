//! This module contains the types necessary for handling ERC20
//! tokens amounts as specified in [EIP-20](https://eips.ethereum.org/EIPS/eip-20).
use std::fmt::{Display, Formatter};
use std::ops::{Add, Sub};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::Uint as ethUint;
use eyre::eyre;
use num_traits::{CheckedAdd, CheckedSub};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::types::ethereum_events::Uint;
use crate::types::token::{Amount, TokenAmount};

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error type
pub struct Error(#[from] eyre::Error);

/// An Ethereum event to be processed by the Namada ledger
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Hash,
    Ord,
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
/// An amount of a given ERC20 token along with a denomination
/// indicating the number of decimal places.
pub struct Erc20Amount {
    amount: Uint,
    denomination: u8,
}

impl Erc20Amount {
    /// Check if two types have the same precision
    pub fn same_denomination(&self, other: &Self) -> bool {
        self.denomination == other.denomination
    }

    /// Get the number of decimal places for this token
    pub fn denomination(&self) -> u8 {
        self.denomination
    }

    /// Check if the amount is zero.
    pub fn is_zero(&self) -> bool {
        self.amount == Uint::from(0)
    }

    /// Create a new `Erc20Amount` from various uint types.
    pub fn from_uint<T: Into<Uint>>(uint: T, denom: u8) -> Self {
        Self {
            amount: uint.into(),
            denomination: denom,
        }
    }

    /// Attempt to convert a `Decimal` to an `Erc20Amount` with the specified
    /// precision.
    pub fn from_decimal(decimal: Decimal, denom: u8) -> Result<Self, Error> {
        if (denom as u32) < decimal.scale() {
            Err(Error(eyre!(
                "This type has only {} decimal places but the given number \
                 has {}",
                denom,
                decimal.scale()
            )))
        } else {
            let value = ethUint::from(decimal.mantissa().unsigned_abs());
            match ethUint::from(10)
                .checked_pow(ethUint::from((denom as u32) - decimal.scale()))
                .and_then(|scaling| scaling.checked_mul(value))
            {
                Some(amount) => Ok(Self {
                    amount: amount.into(),
                    denomination: denom,
                }),
                None => Err(Error(eyre!(
                    "Could not convert to Erc20Amount, requires more than 256 \
                     bits."
                ))),
            }
        }
    }

    /// Attempt to convert a float to an `Erc20Amount` with the specified
    /// precision.
    pub fn from_float(float: impl Into<f64>, denom: u8) -> Result<Self, Error> {
        match Decimal::try_from(float.into()) {
            Err(e) => Err(Error(eyre!(
                "Unable to convert float to fixed precision decimal: {:?}",
                e
            ))),
            Ok(decimal) => Self::from_decimal(decimal, denom),
        }
    }

    /// Attempt to convert an unsigned interger to an `Erc20Amount` with the
    /// specified precision.
    pub fn from_int(uint: impl Into<u64>, denom: u8) -> Result<Self, Error> {
        match Decimal::try_from(uint.into()) {
            Err(e) => Err(Error(eyre!(
                "Unable to convert float to fixed precision decimal: {:?}",
                e
            ))),
            Ok(decimal) => Self::from_decimal(decimal, denom),
        }
    }
}

impl Display for Erc20Amount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let decimals = self.denomination as usize;
        let mut string = ethUint::from(self.amount).to_string();
        if string.len() > decimals {
            string.insert(string.len() - decimals, '.');
        } else {
            for _ in string.len()..decimals {
                string.insert(0, '0');
            }
            string.insert(0, '.');
            string.insert(0, '0');
        }
        f.write_str(&string)
    }
}

impl From<Erc20Amount> for Uint {
    fn from(amount: Erc20Amount) -> Self {
        amount.amount
    }
}

impl From<Erc20Amount> for ethUint {
    fn from(amount: Erc20Amount) -> Self {
        amount.amount.into()
    }
}

impl From<Amount> for Erc20Amount {
    fn from(amount: Amount) -> Self {
        Self {
            amount: Uint::from(u64::from(amount)),
            denomination: 6,
        }
    }
}

impl TryFrom<Erc20Amount> for Amount {
    type Error = Error;

    fn try_from(amount: Erc20Amount) -> Result<Self, Error> {
        if amount.denomination != 6 {
            return Err(Error(eyre!(
                "This ERC20 amount does not use the same precision as the \
                 `Amount` type."
            )));
        }
        for i in 1..4 {
            if amount.amount.0[i] != 0 {
                return Err(Error(eyre!(
                    "The amount of ERC20 tokens exceeded the supply for wNam."
                )));
            }
        }

        // This won't panic because of the above check.
        Ok(Self::from(u64::from(amount.amount)))
    }
}

impl TokenAmount for Erc20Amount {
    fn checked_add(&self, amount: &Self) -> Option<Self> {
        if self.denomination != amount.denomination {
            return None;
        }
        self.amount.checked_add(&amount.amount).map(|res| Self {
            amount: res,
            denomination: self.denomination,
        })
    }

    fn checked_sub(&self, amount: &Self) -> Option<Self> {
        if self.denomination != amount.denomination {
            return None;
        }
        self.amount.checked_sub(&amount.amount).map(|res| Self {
            amount: res,
            denomination: self.denomination,
        })
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn max(&self) -> Self {
        Self {
            amount: Uint([u64::MAX; 4]),
            denomination: self.denomination,
        }
    }

    fn zero(&self) -> Self {
        Self {
            amount: Uint::from(0),
            denomination: self.denomination,
        }
    }
}

impl Add<Uint> for Uint {
    type Output = Uint;

    fn add(self, rhs: Uint) -> Self::Output {
        Self::from(ethUint::from(self) + ethUint::from(rhs))
    }
}

impl CheckedAdd for Uint {
    fn checked_add(&self, amount: &Self) -> Option<Self> {
        ethUint::from(*self)
            .checked_add(ethUint::from(*amount))
            .map(Self::from)
    }
}

impl Sub<Uint> for Uint {
    type Output = Self;

    fn sub(self, rhs: Uint) -> Self::Output {
        Self::from(ethUint::from(self) - ethUint::from(rhs))
    }
}

impl CheckedSub for Uint {
    fn checked_sub(&self, amount: &Self) -> Option<Self> {
        ethUint::from(*self)
            .checked_sub(ethUint::from(*amount))
            .map(Self::from)
    }
}

#[cfg(test)]
mod test_erc20_tokens {
    use super::*;

    /// Conversions from decimal amounts should be correct if there
    /// are sufficient decimal places.
    #[test]
    fn test_from_decimals() {
        let amount = Erc20Amount::from_float(0.5, 2).expect("Test failed");
        assert_eq!(amount.amount.0[0], 50);
        assert!(Erc20Amount::from_float(0.875, 2).is_err());
        assert!(Erc20Amount::from_float(107.53, 1).is_err());
    }

    /// Test that we correctly display ERC20 amounts.
    #[test]
    fn test_erc20_amt_to_string() {
        let amount = Erc20Amount::from_float(0.875, 3).expect("Test failed");
        let displayed = amount.to_string();
        assert_eq!(displayed, "0.875");

        let amount = Erc20Amount::from_float(107.53, 2).expect("Test failed");
        let displayed = amount.to_string();
        assert_eq!(displayed, "107.53");

        let amount = Erc20Amount::from_float(11.2, 3).expect("Test failed");
        let displayed = amount.to_string();
        assert_eq!(displayed, "11.200");

        let amount = Erc20Amount::from_float(5, 3).expect("Test failed");
        let displayed = amount.to_string();
        assert_eq!(displayed, "5.000");

        let amount = Erc20Amount::from_float(0.01, 4).expect("Test failed");
        let displayed = amount.to_string();
        assert_eq!(displayed, "0.0100");
    }

    /// Test converting to and from NAM amounts succeeds.
    #[test]
    fn test_amount_roundtrip() {
        let amount = Amount::whole(1138);
        let erc20_amount = Erc20Amount::from(amount);
        assert_eq!(erc20_amount.to_string(), "1138.000000");
        assert_eq!(
            Amount::try_from(erc20_amount).expect("Test failed"),
            amount
        );
    }

    /// Test that converting an `Erc20Amount` to `Amount` that exceeds the
    /// supply of NAM fails.
    #[test]
    fn greater_than_nam_supply_fails() {
        let mut value = Uint::from(u64::MAX);
        let erc20_amount = Erc20Amount::from_uint::<Uint>(value, 6);
        assert!(Amount::try_from(erc20_amount).is_ok());
        value = value + 1;
        let erc20_amount = Erc20Amount::from_uint::<Uint>(value, 6);
        assert!(Amount::try_from(erc20_amount).is_err());
    }

    /// Test that numbers that require more than 256 bits to
    /// represent are caught and errors are returned.
    #[test]
    fn test_erc20amount_uint256_overflow() {
        // floor(log(2^256)) = 77
        assert!(Erc20Amount::from_float(0, 78).is_err());
        assert!(Erc20Amount::from_float(100, 77).is_err());
        assert!(Erc20Amount::from_float(0.10, 79).is_err());
    }

    /// Test that checked add and subtract for `Erc20Amount` behaves correctly
    /// and catches error conditions correctly.
    #[test]
    fn test_add_and_subtract() {
        let amount_1 = Erc20Amount::from_int(64u64, 75).expect("Test failed");
        let amount_2 = Erc20Amount::from_int(36u64, 75).expect("Test failed");
        assert!(amount_2.checked_sub(&amount_1).is_none());
        assert_eq!(
            amount_1.checked_sub(&amount_2).expect("Test failed"),
            Erc20Amount::from_int(28u64, 75).expect("Test failed")
        );
        assert!(amount_1.checked_add(&amount_1).is_none());
        assert_eq!(
            amount_2.checked_add(&amount_2).expect("Test failed"),
            Erc20Amount::from_int(72u64, 75).expect("Test failed")
        );
    }
}
