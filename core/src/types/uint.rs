#![allow(clippy::assign_op_pattern)]
//! An unsigned 256 integer type. Used for, among other things,
//! the backing type of token amounts.
use std::cmp::Ordering;
use std::ops::{Add, AddAssign, BitXor, Neg, Sub};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use impl_num_traits::impl_uint_num_traits;
use serde::{Deserialize, Serialize};
use uint::construct_uint;

use crate::types::token;

construct_uint! {
    /// Namada native type to replace for unsigned 256 bit
    /// integers.
    #[derive(
        Serialize,
        Deserialize,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
    )]

    pub struct Uint(4);
}

impl_uint_num_traits!(Uint, 4);

/// The maximum 256 bit integer
pub const MAX_VALUE: Uint = Uint([u64::MAX; 4]);

impl Uint {
    /// Compute the two's complement of a number.
    fn negate(&self) -> Option<Self> {
        Self(
            self.0
                .into_iter()
                .map(|byte| byte.bitxor(u64::MAX))
                .collect::<Vec<_>>()
                .try_into()
                .expect("This cannot fail"),
        )
        .checked_add(Uint::from(1u64))
    }
}

/// The maximum absolute value a [`SignedUint`] may have.
/// Note the the last digit is 2^63 - 1. We add this cap so
/// we can use two's complement.
pub const MAX_SIGNED_VALUE: Uint =
    Uint([u64::MAX, u64::MAX, u64::MAX, 9223372036854775807]);

/// A signed 256 big integer.
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize,
)]
pub struct SignedUint(Uint);

impl SignedUint {
    /// Check if the amount is not negative (greater
    /// than or equal to zero)
    pub fn non_negative(&self) -> bool {
        self.0.0[3].leading_zeros() > 0
    }

    /// Get the absolute value
    pub fn abs(&self) -> Uint {
        if self.non_negative() {
            self.0
        } else {
            self.0.negate().unwrap()
        }
    }

    /// Check if this value is zero
    pub fn is_zero(&self) -> bool {
        self.0 == Uint::zero()
    }

    /// Get a string representation of `self` as a
    /// native token amount.
    pub fn to_string_native(&self) -> String {
        let mut sign = if self.non_negative() {
            String::from("-")
        } else {
            String::new()
        };
        sign.push_str(&token::Amount::from(*self).to_string_native());
        sign
    }
}

impl From<u64> for SignedUint {
    fn from(val: u64) -> Self {
        SignedUint::try_from(Uint::from(val))
            .expect("A u64 will always fit in this type")
    }
}

impl TryFrom<Uint> for SignedUint {
    type Error = Box<dyn 'static + std::error::Error>;

    fn try_from(value: Uint) -> Result<Self, Self::Error> {
        if value.0 <= MAX_SIGNED_VALUE.0 {
            Ok(Self(value))
        } else {
            Err("The given integer is too large to be represented asa \
                 SignedUint"
                .into())
        }
    }
}

impl Neg for SignedUint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.negate().expect("This should not fail"))
    }
}

impl PartialOrd for SignedUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.non_negative(), other.non_negative()) {
            (true, false) => Some(Ordering::Greater),
            (false, true) => Some(Ordering::Less),
            _ => {
                let this = self.abs();
                let that = other.abs();
                this.0.partial_cmp(&that.0)
            }
        }
    }
}

impl Ord for SignedUint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Add<SignedUint> for SignedUint {
    type Output = Self;

    fn add(self, rhs: SignedUint) -> Self::Output {
        match (self.non_negative(), rhs.non_negative()) {
            (true, true) => Self(self.0 + rhs.0),
            (false, false) => -Self(self.abs() + rhs.abs()),
            (true, false) => Self(self.0 - rhs.abs()),
            (false, true) => Self(rhs.0 - self.abs()),
        }
    }
}

impl AddAssign for SignedUint {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for SignedUint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl From<i128> for SignedUint {
    fn from(val: i128) -> Self {
        if val < 0 {
            let abs = Self((-val).into());
            -abs
        } else {
            Self(val.into())
        }
    }
}

impl From<i64> for SignedUint {
    fn from(val: i64) -> Self {
        Self::from(val as i128)
    }
}

impl From<i32> for SignedUint {
    fn from(val: i32) -> Self {
        Self::from(val as i128)
    }
}
