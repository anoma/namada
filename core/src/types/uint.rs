//! U256 type.

use std::fmt::{Display, Formatter};
use std::ops::{Add, Mul, Sub};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::{Token, Uint as ethUint};
use num_traits::{CheckedAdd, CheckedSub};
use serde::{Deserialize, Serialize};

use crate::types::eth_abi;

/// Namada native type to replace the ethabi::Uint type
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct Uint(pub [u64; 4]);

/// Maximum value.
pub const MAX: Uint = Uint([u64::MAX; 4]);

impl Uint {
    /// Convert to a little endian byte representation of
    /// a uint256.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        ethUint::from(self).to_little_endian(&mut bytes);
        bytes
    }

    /// Check if this value fits u64.
    #[inline]
    pub fn fits_word(&self) -> bool {
        let Uint(arr) = &self;
        for i in 1..4 {
            if arr[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Low word (u64).
    pub const fn low_u64(&self) -> u64 {
        let Uint(arr) = &self;
        arr[0]
    }

    /// Low 2 words (u128).
    pub const fn low_u128(&self) -> u128 {
        let Uint(arr) = &self;
        ((arr[1] as u128) << 64) + arr[0] as u128
    }
}

impl Display for Uint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        ethUint::from(self).fmt(f)
    }
}

impl eth_abi::Encode<1> for Uint {
    fn tokenize(&self) -> [Token; 1] {
        [Token::Uint(self.into())]
    }
}

impl From<ethUint> for Uint {
    fn from(value: ethUint) -> Self {
        Self(value.0)
    }
}

impl From<Uint> for ethUint {
    fn from(value: Uint) -> Self {
        Self(value.0)
    }
}

impl From<&Uint> for ethUint {
    fn from(value: &Uint) -> Self {
        Self(value.0)
    }
}

impl From<u64> for Uint {
    fn from(value: u64) -> Self {
        ethUint::from(value).into()
    }
}

impl From<u128> for Uint {
    fn from(value: u128) -> Self {
        ethUint::from(value).into()
    }
}

impl Add<u64> for Uint {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        (ethUint::from(self) + rhs).into()
    }
}

impl Add<Uint> for Uint {
    type Output = Uint;

    fn add(self, rhs: Uint) -> Self::Output {
        Self::from(ethUint::from(self) + rhs)
    }
}

impl Sub<Uint> for Uint {
    type Output = Self;

    fn sub(self, rhs: Uint) -> Self::Output {
        Self::from(ethUint::from(self) - rhs)
    }
}

impl Mul<u64> for Uint {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Self::from(ethUint::from(self) * rhs)
    }
}

impl CheckedAdd for Uint {
    fn checked_add(&self, amount: &Self) -> Option<Self> {
        ethUint::from(*self)
            .checked_add(ethUint::from(*amount))
            .map(Self::from)
    }
}

impl CheckedSub for Uint {
    fn checked_sub(&self, amount: &Self) -> Option<Self> {
        ethUint::from(*self)
            .checked_sub(ethUint::from(*amount))
            .map(Self::from)
    }
}
