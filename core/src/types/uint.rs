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
    fn negate(&self) -> Self {
        Self(
            self.0
                .into_iter()
                .map(|byte| byte.bitxor(u64::MAX))
                .collect::<Vec<_>>()
                .try_into()
                .expect("This cannot fail"),
        )
        .overflowing_add(Uint::from(1u64))
        .0
        .canonical()
    }

    /// There are two valid representations of zero: plus and
    /// minus. We only allow the positive representation.
    fn canonical(self) -> Self {
        if self == MINUS_ZERO {
            Self::zero()
        } else {
            self
        }
    }
}

/// The maximum absolute value a [`SignedUint`] may have.
/// Note the the last digit is 2^63 - 1. We add this cap so
/// we can use two's complement.
pub const MAX_SIGNED_VALUE: Uint =
    Uint([u64::MAX, u64::MAX, u64::MAX, 9223372036854775807]);

const MINUS_ZERO: Uint = Uint([0u64, 0u64, 0u64, 9223372036854775808]);

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
            self.0.negate()
        }
    }

    /// Check if this value is zero
    pub fn is_zero(&self) -> bool {
        self.0 == Uint::zero()
    }

    /// Get a string representation of `self` as a
    /// native token amount.
    pub fn to_string_native(&self) -> String {
        let mut sign = if !self.non_negative() {
            String::from("-")
        } else {
            String::new()
        };
        sign.push_str(&token::Amount::from(*self).to_string_native());
        sign
    }

    /// Adds two [`SignedUint`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_AMOUNT`], else returns `None`.
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.non_negative() == other.non_negative() {
            self.abs().checked_add(other.abs())
                .and_then(|val| Self::try_from(val)
                    .ok()
                    .map(|val| if !self.non_negative() {
                        -val
                    } else {
                        val
                    }))
        } else {
            Some(*self + *other)
        }
    }

    /// Subtracts two [`SignedUint`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_AMOUNT`], else returns `None`.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.checked_add(&other.neg())
    }

    /// Changed the inner Uint into a canonical representation.
    fn canonical(self) -> Self {
        Self(self.0.canonical())
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
        if value <= MAX_SIGNED_VALUE {
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
        Self(self.0.negate())
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
            (true, false) => if self.0 >= rhs.abs() {
                Self(self.0 - rhs.abs())
            } else {
                -Self(rhs.abs() - self.0)
            }
            (false, true) => if rhs.0 >= self.abs() {
                Self(rhs.0 - self.abs())
            } else {
                -Self(self.abs() - rhs.0)
            },
        }.canonical()
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


#[cfg(test)]
mod test_uint {
    use super::*;

    /// Test that adding one to the max signed
    /// value gives zero.
    #[test]
    fn test_max_signed_value() {
        let signed = SignedUint::try_from(MAX_SIGNED_VALUE).expect("Test failed");
        let one = SignedUint::try_from(Uint::from(1u64)).expect("Test failed");
        let overflow = signed + one;
        assert_eq!(overflow, SignedUint::try_from(Uint::zero()).expect("Test failed"));
        assert!(signed.checked_add(&one).is_none());
        assert!((-signed).checked_sub(&one).is_none());
    }

    /// Sanity on our constants and that the minus zero representation
    /// is not allowed.
    #[test]
    fn test_minus_zero_not_allowed() {
        let larger = Uint([0, 0, 0, 2u64.pow(63)]);
        let smaller = Uint([u64::MAX, u64::MAX, u64::MAX, 2u64.pow(63) -1]);
        assert!(larger > smaller);
        assert_eq!(smaller, MAX_SIGNED_VALUE);
        assert_eq!(larger, MINUS_ZERO);
        assert!(SignedUint::try_from(MINUS_ZERO).is_err());
        let zero = Uint::zero();
        assert_eq!(zero, zero.negate());
    }

    /// Test that we correctly reserve the right bit for indicating the
    /// sign.
    #[test]
    fn test_non_negative() {
        let zero = SignedUint::try_from(Uint::zero()).expect("Test failed");
        assert!(zero.non_negative());
        assert!((-zero).non_negative());
        let negative = SignedUint(Uint([1u64, 0, 0, 2u64.pow(63)]));
        assert!(!negative.non_negative());
        assert!((-negative).non_negative());
        let positive = SignedUint(MAX_SIGNED_VALUE);
        assert!(positive.non_negative());
        assert!(!(-positive).non_negative());
    }

    /// Test that the absolute vale is computed correctly
    #[test]
    fn test_abs() {
        let zero = SignedUint::try_from(Uint::zero()).expect("Test failed");
        let neg_one = SignedUint(Uint::max_value());
        let neg_eight = SignedUint(Uint::max_value() - Uint::from(7));
        let two = SignedUint(Uint::from(2));
        let ten = SignedUint(Uint::from(10));

        assert_eq!(zero.abs(), Uint::zero());
        assert_eq!(neg_one.abs(), Uint::from(1));
        assert_eq!(neg_eight.abs(), Uint::from(8));
        assert_eq!(two.abs(), Uint::from(2));
        assert_eq!(ten.abs(), Uint::from(10));
    }

    /// Test that the absolute vale is computed correctly
    #[test]
    fn test_to_string_native() {
        let native_scaling = Uint::exp10(6);
        let zero = SignedUint::try_from(Uint::zero()).expect("Test failed");
        let neg_one = -SignedUint(native_scaling);
        let neg_eight = -SignedUint(Uint::from(8) * native_scaling);
        let two = SignedUint(Uint::from(2) * native_scaling);
        let ten = SignedUint(Uint::from(10) * native_scaling);

        assert_eq!(zero.to_string_native(), "0.000000");
        assert_eq!(neg_one.to_string_native(), "-1.000000");
        assert_eq!(neg_eight.to_string_native(), "-8.000000");
        assert_eq!(two.to_string_native(), "2.000000");
        assert_eq!(ten.to_string_native(), "10.000000");
    }

    /// Test that we correctly handle arithmetic with two's complement
    #[test]
    fn test_arithmetic() {
        let zero = SignedUint::try_from(Uint::zero()).expect("Test failed");
        let neg_one = SignedUint(Uint::max_value());
        let neg_eight = SignedUint(Uint::max_value() - Uint::from(7));
        let two = SignedUint(Uint::from(2));
        let ten = SignedUint(Uint::from(10));

        assert_eq!(zero + neg_one, neg_one);
        assert_eq!(neg_one - zero, neg_one);
        assert_eq!(zero - neg_one, SignedUint(Uint::one()));
        assert_eq!(two - neg_eight, ten);
        assert_eq!(two + ten, SignedUint(Uint::from(12)));
        assert_eq!(ten - two, -neg_eight);
        assert_eq!(two - ten, neg_eight);
        assert_eq!(neg_eight + neg_one, -SignedUint(Uint::from(9)));
        assert_eq!(neg_one - neg_eight, SignedUint(Uint::from(7)));
        assert_eq!(neg_eight - neg_one, -SignedUint(Uint::from(7)));
        assert_eq!(neg_eight - two, -ten);
        assert!((two - two).is_zero());
    }
}