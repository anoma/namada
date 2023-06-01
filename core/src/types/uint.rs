#![allow(clippy::assign_op_pattern)]
//! An unsigned 256 integer type. Used for, among other things,
//! the backing type of token amounts.
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Add, AddAssign, BitXor, Div, Mul, Neg, Rem, Sub, SubAssign};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use impl_num_traits::impl_uint_num_traits;
use serde::{Deserialize, Serialize};
use uint::construct_uint;

use crate::types::token;
use crate::types::token::{Amount, AmountParseError, MaspDenom};

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
    /// Divide two [`Uint`]s with scaled to allow the `denom` number
    /// of decimal places.
    ///
    /// This method is checked and will return `None` if
    ///  * `self` * 10^(`denom`) overflows 256 bits
    ///  * `other` is  zero (`checked_div` will return `None`).
    pub fn fixed_precision_div(&self, rhs: &Self, denom: u8) -> Option<Self> {
        let lhs = Uint::from(10)
            .checked_pow(Uint::from(denom))
            .and_then(|res| res.checked_mul(*self))?;
        lhs.checked_div(*rhs)
    }

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

/// The maximum absolute value a [`I256`] may have.
/// Note the the last digit is 2^63 - 1. We add this cap so
/// we can use two's complement.
pub const MAX_SIGNED_VALUE: Uint =
    Uint([u64::MAX, u64::MAX, u64::MAX, 9223372036854775807]);

const MINUS_ZERO: Uint = Uint([0u64, 0u64, 0u64, 9223372036854775808]);

/// A signed 256 big integer.
#[derive(
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct I256(pub Uint);

impl I256 {
    /// Check if the amount is not negative (greater
    /// than or equal to zero)
    pub fn non_negative(&self) -> bool {
        self.0.0[3].leading_zeros() > 0
    }

    /// Check if the amount is negative (less than zero)
    pub fn is_negative(&self) -> bool {
        !self.non_negative()
    }

    /// Check if the amount is positive (greater than zero)
    pub fn is_positive(&self) -> bool {
        self.non_negative() && !self.is_zero()
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

    /// Gives the zero value of an I256
    pub fn zero() -> I256 {
        Self(Uint::zero())
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

    /// Adds two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.non_negative() == other.non_negative() {
            self.abs().checked_add(other.abs()).and_then(|val| {
                Self::try_from(val)
                    .ok()
                    .map(|val| if !self.non_negative() { -val } else { val })
            })
        } else {
            Some(*self + *other)
        }
    }

    /// Subtracts two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.checked_add(&other.neg())
    }

    /// Changed the inner Uint into a canonical representation.
    fn canonical(self) -> Self {
        Self(self.0.canonical())
    }

    /// the maximum I256 value
    pub fn maximum() -> Self {
        Self(MAX_SIGNED_VALUE)
    }

    /// Attempt to convert a MASP-denominated integer to an I256
    /// using the given denomination.
    pub fn from_masp_denominated(
        value: impl Into<i128>,
        denom: MaspDenom,
    ) -> Result<Self, AmountParseError> {
        let value = value.into();
        let is_negative = value < 0;
        let value = value.unsigned_abs();
        let mut result = [0u64; 4];
        result[denom as usize] = value as u64;
        let result = Uint(result);
        if result <= MAX_SIGNED_VALUE {
            if is_negative {
                Ok(Self(result.negate()).canonical())
            } else {
                Ok(Self(result).canonical())
            }
        } else {
            Err(AmountParseError::InvalidRange)
        }
    }
}

impl From<u64> for I256 {
    fn from(val: u64) -> Self {
        I256::try_from(Uint::from(val))
            .expect("A u64 will always fit in this type")
    }
}

impl TryFrom<Uint> for I256 {
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

impl Neg for I256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.negate())
    }
}

impl PartialOrd for I256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.non_negative(), other.non_negative()) {
            (true, false) => Some(Ordering::Greater),
            (false, true) => Some(Ordering::Less),
            (true, true) => {
                let this = self.abs();
                let that = other.abs();
                this.0.partial_cmp(&that.0)
            }
            (false, false) => {
                let this = self.abs();
                let that = other.abs();
                that.0.partial_cmp(&this.0)
            }
        }
    }
}

impl Ord for I256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Add<I256> for I256 {
    type Output = Self;

    fn add(self, rhs: I256) -> Self::Output {
        match (self.non_negative(), rhs.non_negative()) {
            (true, true) => Self(self.0 + rhs.0),
            (false, false) => -Self(self.abs() + rhs.abs()),
            (true, false) => {
                if self.0 >= rhs.abs() {
                    Self(self.0 - rhs.abs())
                } else {
                    -Self(rhs.abs() - self.0)
                }
            }
            (false, true) => {
                if rhs.0 >= self.abs() {
                    Self(rhs.0 - self.abs())
                } else {
                    -Self(self.abs() - rhs.0)
                }
            }
        }
        .canonical()
    }
}

impl AddAssign for I256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for I256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl SubAssign for I256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

// NOTE: watch the overflow
impl Mul<Uint> for I256 {
    type Output = Self;

    fn mul(self, rhs: Uint) -> Self::Output {
        let is_neg = self.is_negative();
        let prod = self.abs() * rhs;
        if is_neg { -Self(prod) } else { Self(prod) }
    }
}

impl Mul for I256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        if rhs.is_negative() {
            -self * rhs.abs()
        } else {
            self * rhs.abs()
        }
    }
}

impl Div<Uint> for I256 {
    type Output = Self;

    fn div(self, rhs: Uint) -> Self::Output {
        let is_neg = self.is_negative();
        let quot = self
            .abs()
            .fixed_precision_div(&rhs, 0u8)
            .unwrap_or_default();
        if is_neg { -Self(quot) } else { Self(quot) }
    }
}

impl Div<I256> for I256 {
    type Output = Self;

    fn div(self, rhs: I256) -> Self::Output {
        if rhs.is_negative() {
            -(self / rhs.abs())
        } else {
            self / rhs.abs()
        }
    }
}

impl Rem for I256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        if self.is_negative() {
            -(Self(self.abs() % rhs.abs()))
        } else {
            Self(self.abs() % rhs.abs())
        }
    }
}
impl From<i128> for I256 {
    fn from(val: i128) -> Self {
        if val < 0 {
            let abs = Self((-val).into());
            -abs
        } else {
            Self(val.into())
        }
    }
}

impl From<i64> for I256 {
    fn from(val: i64) -> Self {
        Self::from(val as i128)
    }
}

impl From<i32> for I256 {
    fn from(val: i32) -> Self {
        Self::from(val as i128)
    }
}

impl std::iter::Sum for I256 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(I256::zero(), |acc, amt| acc + amt)
    }
}

impl Display for I256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string_native().as_str())
    }
}

impl Debug for I256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl TryFrom<I256> for i128 {
    type Error = std::io::Error;

    fn try_from(value: I256) -> Result<Self, Self::Error> {
        if !value.non_negative() {
            Ok(-(u128::try_from(Amount::from_change(value))? as i128))
        } else {
            Ok(u128::try_from(Amount::from_change(value))? as i128)
        }
    }
}

#[cfg(test)]
mod test_uint {
    use super::*;

    /// Test that dividing two [`Uint`]s with the specified precision
    /// works correctly and performs correct checks.
    #[test]
    fn test_fixed_precision_div() {
        let zero = Uint::zero();
        let two = Uint::from(2);
        let three = Uint::from(3);

        assert_eq!(
            zero.fixed_precision_div(&two, 10).expect("Test failed"),
            zero
        );
        assert!(two.fixed_precision_div(&zero, 3).is_none());
        assert_eq!(
            three.fixed_precision_div(&two, 1).expect("Test failed"),
            Uint::from(15)
        );
        assert_eq!(
            two.fixed_precision_div(&three, 2).expect("Test failed"),
            Uint::from(66)
        );
        assert_eq!(
            two.fixed_precision_div(&three, 3).expect("Satan lives"),
            Uint::from(666)
        );
        assert!(two.fixed_precision_div(&three, 77).is_none());
        assert!(Uint::from(20).fixed_precision_div(&three, 76).is_none());
    }

    /// Test that adding one to the max signed
    /// value gives zero.
    #[test]
    fn test_max_signed_value() {
        let signed = I256::try_from(MAX_SIGNED_VALUE).expect("Test failed");
        let one = I256::try_from(Uint::from(1u64)).expect("Test failed");
        let overflow = signed + one;
        assert_eq!(
            overflow,
            I256::try_from(Uint::zero()).expect("Test failed")
        );
        assert!(signed.checked_add(&one).is_none());
        assert!((-signed).checked_sub(&one).is_none());
    }

    /// Sanity on our constants and that the minus zero representation
    /// is not allowed.
    #[test]
    fn test_minus_zero_not_allowed() {
        let larger = Uint([0, 0, 0, 2u64.pow(63)]);
        let smaller = Uint([u64::MAX, u64::MAX, u64::MAX, 2u64.pow(63) - 1]);
        assert!(larger > smaller);
        assert_eq!(smaller, MAX_SIGNED_VALUE);
        assert_eq!(larger, MINUS_ZERO);
        assert!(I256::try_from(MINUS_ZERO).is_err());
        let zero = Uint::zero();
        assert_eq!(zero, zero.negate());
    }

    /// Test that we correctly reserve the right bit for indicating the
    /// sign.
    #[test]
    fn test_non_negative() {
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        assert!(zero.non_negative());
        assert!((-zero).non_negative());
        let negative = I256(Uint([1u64, 0, 0, 2u64.pow(63)]));
        assert!(!negative.non_negative());
        assert!((-negative).non_negative());
        let positive = I256(MAX_SIGNED_VALUE);
        assert!(positive.non_negative());
        assert!(!(-positive).non_negative());
    }

    /// Test that the absolute value is computed correctly.
    #[test]
    fn test_abs() {
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        let neg_one = I256(Uint::max_value());
        let neg_eight = I256(Uint::max_value() - Uint::from(7));
        let two = I256(Uint::from(2));
        let ten = I256(Uint::from(10));

        assert_eq!(zero.abs(), Uint::zero());
        assert_eq!(neg_one.abs(), Uint::from(1));
        assert_eq!(neg_eight.abs(), Uint::from(8));
        assert_eq!(two.abs(), Uint::from(2));
        assert_eq!(ten.abs(), Uint::from(10));
    }

    /// Test that the string representation is created correctly.
    #[test]
    fn test_to_string_native() {
        let native_scaling = Uint::exp10(6);
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        let neg_one = -I256(native_scaling);
        let neg_eight = -I256(Uint::from(8) * native_scaling);
        let two = I256(Uint::from(2) * native_scaling);
        let ten = I256(Uint::from(10) * native_scaling);

        assert_eq!(zero.to_string_native(), "0.000000");
        assert_eq!(neg_one.to_string_native(), "-1.000000");
        assert_eq!(neg_eight.to_string_native(), "-8.000000");
        assert_eq!(two.to_string_native(), "2.000000");
        assert_eq!(ten.to_string_native(), "10.000000");
    }

    /// Test that we correctly handle arithmetic with two's complement
    #[test]
    fn test_arithmetic() {
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        let neg_one = I256(Uint::max_value());
        let neg_eight = I256(Uint::max_value() - Uint::from(7));
        let two = I256(Uint::from(2));
        let ten = I256(Uint::from(10));

        assert_eq!(zero + neg_one, neg_one);
        assert_eq!(neg_one - zero, neg_one);
        assert_eq!(zero - neg_one, I256(Uint::one()));
        assert_eq!(two - neg_eight, ten);
        assert_eq!(two + ten, I256(Uint::from(12)));
        assert_eq!(ten - two, -neg_eight);
        assert_eq!(two - ten, neg_eight);
        assert_eq!(neg_eight + neg_one, -I256(Uint::from(9)));
        assert_eq!(neg_one - neg_eight, I256(Uint::from(7)));
        assert_eq!(neg_eight - neg_one, -I256(Uint::from(7)));
        assert_eq!(neg_eight - two, -ten);
        assert!((two - two).is_zero());
    }

    /// Test that ordering is correctly implemented
    #[test]
    fn test_ord() {
        let this = Amount::from_uint(1, 0).unwrap().change();
        let that = Amount::native_whole(1000).change();
        assert!(this <= that);
        assert!(-this <= that);
        assert!(-this >= -that);
        assert!(this >= -that);
        assert!(that >= this);
        assert!(that >= -this);
        assert!(-that <= -this);
        assert!(-that <= this);
    }
}
