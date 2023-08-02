#![allow(clippy::assign_op_pattern)]
//! An unsigned 256 integer type. Used for, among other things,
//! the backing type of token amounts.
use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::ops::{Add, AddAssign, BitAnd, Div, Mul, Neg, Not, Rem, Shr, Sub, SubAssign};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use impl_num_traits::impl_uint_num_traits;
use num_integer::Integer;
use num_traits::{Bounded, CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg, CheckedRem, CheckedSub, Num, One, Signed as SignedTrait, Zero};
use uint::construct_uint;

use crate::types::token;
use crate::types::token::{AmountParseError, MaspDenom};

/// The value zero.
pub const ZERO: Uint = Uint::from_u64(0);

/// The value one.
pub const ONE: Uint = Uint::from_u64(1);

impl Uint {
    /// Convert a [`u64`] to a [`Uint`].
    pub const fn from_u64(x: u64) -> Uint {
        Uint([x.to_le(), 0, 0, 0])
    }
}

construct_uint! {
    /// Namada native type to replace for unsigned 256 bit
    /// integers.
    #[derive(
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
    )]

    pub struct Uint(4);
}

impl serde::Serialize for Uint {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let amount_string = self.to_string();
        serde::Serialize::serialize(&amount_string, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Uint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as serdeError;
        let amount_string: String =
            serde::Deserialize::deserialize(deserializer)?;

        let digits = amount_string
            .chars()
            .filter_map(|c| {
                if c.is_ascii_digit() {
                    c.to_digit(10).map(Uint::from)
                } else {
                    None
                }
            })
            .rev()
            .collect::<Vec<_>>();
        if digits.len() != amount_string.len() {
            return Err(D::Error::custom(AmountParseError::FromString));
        }
        if digits.len() > 77 {
            return Err(D::Error::custom(AmountParseError::ScaleTooLarge(
                digits.len() as u32,
                77,
            )));
        }
        let mut value = Uint::default();
        let ten = Uint::from(10);
        for (pow, digit) in digits.into_iter().enumerate() {
            value = ten
                .checked_pow(Uint::from(pow))
                .and_then(|scaling| scaling.checked_mul(digit))
                .and_then(|scaled| value.checked_add(scaled))
                .ok_or(AmountParseError::PrecisionOverflow)
                .map_err(D::Error::custom)?;
        }
        Ok(value)
    }
}

impl_uint_num_traits!(Uint, 4);

impl Integer for Uint {
    fn div_floor(&self, other: &Self) -> Self {
        self.div(other)
    }

    fn mod_floor(&self, other: &Self) -> Self {
        let (_, rem) = self.div_mod(*other);
        rem
    }

    fn gcd(&self, other: &Self) -> Self {
        if self.is_zero() {
            return *self;
        }
        if other.is_zero() {
            return *other;
        }

        let shift = (*self | *other).trailing_zeros();
        let mut u = *self;
        let mut v = *other;
        u >>= shift;
        v >>= shift;
        u >>= u.trailing_zeros();

        loop {
            v >>= v.trailing_zeros();
            if u > v {
                std::mem::swap(&mut u, &mut v);
            }
            v -= u; // here v >= u
            if v.is_zero() {
                break;
            }
        }
        u << shift
    }

    fn lcm(&self, other: &Self) -> Self {
        (*self * *other).div(self.gcd(other))
    }

    fn divides(&self, other: &Self) -> bool {
        other.rem(self).is_zero()
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        self.divides(other)
    }

    fn is_even(&self) -> bool {
        self.bitand(Self::one()) != Self::one()
    }

    fn is_odd(&self) -> bool {
        !self.is_even()
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        self.div_mod(*other)
    }
}

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
}

/// The maximum absolute value a [`I256`] may have.
/// Note the the last digit is 2^63 - 1. We add this cap so
/// we can use two's complement.
pub const MAX_SIGNED_VALUE: Uint =
    Uint([u64::MAX, u64::MAX, u64::MAX, 9223372036854775807]);

pub type I256 = Signed<Uint>;

/// A signed 256 big integer.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct Signed<U>(pub U) where U: BorshSerialize + BorshDeserialize + PartialEq + Eq;

impl<U> fmt::Display for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Display + Zero + One + Not<Output = U> + PartialEq + Eq + PartialOrd + CheckedAdd + Sub<Output = U> + CheckedMul + Num + Shr<Output = U> + CheckedDiv + Rem + Copy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::min_value() {
            write!(f, "-{}", self.0)
        } else if self.is_negative() {
            write!(f, "-{}", (-*self).0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl<U> Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + PartialEq + Eq + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    pub fn from_uint(value: U) -> Option<Self> {
        let res = Self(value);
        (!res.is_negative()).then_some(res)
    }
}

impl<U> SignedTrait for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    /// Get the absolute value
    fn abs(&self) -> Self {
        if self.is_negative() {
            -*self
        } else {
            *self
        }
    }

    fn signum(&self) -> Self {
        if self.is_negative() {
            -Self::one()
        } else if self.is_positive() {
            Self::one()
        } else {
            Self::zero()
        }
    }

    fn abs_sub(&self, other: &Self) -> Self {
        if self <= other {
            Self::zero()
        } else {
            self.checked_sub(other).expect("subtraction overflow")
        }
    }
    
    /// Check if the amount is negative (less than zero)
    fn is_negative(&self) -> bool {
        self.0
            .as_ref()
            .last()
            .expect("signed type must be backed by integer type with positive bitwidth")
            .leading_zeros() == 0
    }

    /// Check if the amount is positive (greater than zero)
    fn is_positive(&self) -> bool {
        !self.is_negative() && self.0.as_ref().iter().any(|x| *x != 0)
    }
}

impl Signed<Uint> {
    /// Get a string representation of `self` as a
    /// native token amount.
    pub fn to_string_native(&self) -> String {
        let mut sign = if self.is_negative() {
            String::from("-")
        } else {
            String::new()
        };
        sign.push_str(&token::Amount::from(*self).to_string_native());
        sign
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
                Ok(-Self(result))
            } else {
                Ok(Self(result))
            }
        } else {
            Err(AmountParseError::InvalidRange)
        }
    }
}

impl<U> CheckedNeg for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + PartialEq + Eq + Copy {
    /// Compute the two's complement of a number.
    fn checked_neg(&self) -> Option<Self> {
        let res = !self.0;
        if res.as_ref().iter().all(|x| *x == u64::MAX) {
            Some(Self(U::zero()))
        } else {
            let res = res + U::one();
            (res != self.0).then_some(Self(res))
        }
    }
}

impl<U> Zero for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    /// Check if this value is zero
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Gives the zero value of an I256
    fn zero() -> Self {
        Self(U::zero())
    }
}

impl<U> One for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + One + PartialEq + Eq + Sub<Output = U> + CheckedAdd + Not<Output = U> + Zero + CheckedMul + PartialOrd + Num + CheckedDiv + Rem + Copy {
    /// Check if this value is zero
    fn is_one(&self) -> bool {
        self.0.is_one()
    }

    /// Gives the zero value of an I256
    fn one() -> Self {
        Self(U::one())
    }
}

impl<U> CheckedAdd for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    /// Adds two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    fn checked_add(&self, other: &Self) -> Option<Self> {
        match (self.is_negative(), other.is_negative()) {
            (false, false) => self.0.checked_add(&other.0).and_then(Self::from_uint),
            (true, true) => (!self.abs().0).checked_add(&other.abs().0).map(U::not).and_then(Self::from_uint),
            (true, false) if (!self.0) >= other.0 => Some(Self(!((!self.0) - other.0))),
            (true, false) => Some(Self(other.0 - (-*self).0)),
            (false, true) if (!other.0) >= self.0 => Some(Self(!((!other.0) - self.0))),
            (false, true) => Some(Self(self.0 - (-*other).0)),
            
        }
    }
}

impl<U> CheckedSub for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    /// Subtracts two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.checked_add(&Self(!other.0)).and_then(|x| x.checked_add(&Self::one()))
    }
}

impl<U> Bounded for Signed<U> where U: BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + Shr<Output = U> + PartialEq + Eq {
    /// the maximum I256 value
    fn max_value() -> Self {
        Self((!U::zero()) >> One::one())
    }

    fn min_value() -> Self {
        Self(!((!U::zero()) >> One::one()))
    }
}

impl<U> From<u64> for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + From<u64> + PartialEq + Eq + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + CheckedMul + PartialOrd + Num + CheckedDiv + Rem + Copy {
    fn from(val: u64) -> Self {
        let res = Self(U::from(val));
        if res.is_negative() {
            panic!("u64 exceeds i64::MAX")
        } else {
            res
        }
    }
}

impl<U> Neg for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + PartialEq + Eq {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let res = !self.0;
        if res.as_ref().iter().all(|x| *x == u64::MAX) {
            Self(U::zero())
        } else {
            Self(res + U::one())
        }
    }
}

impl<U> PartialOrd for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + CheckedMul + PartialOrd + Num + CheckedDiv + Rem + Copy {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.is_negative(), other.is_negative()) {
            (false, true) => Some(Ordering::Greater),
            (true, false) => Some(Ordering::Less),
            (false, false) => self.0.partial_cmp(&other.0),
            (true, true) => (!other.0).partial_cmp(&!self.0),
        }
    }
}

impl<U> Ord for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + CheckedMul + PartialOrd + Num + CheckedDiv + Rem + Copy {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).expect("signed integers should be comparable")
    }
}

impl<U> Add for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs).expect("addition overflowed")
    }
}

impl<U> Sub for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(&rhs).expect("subtraction overflowed")
    }
}

impl<U> AddAssign for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<U> SubAssign for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<U> Num for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    type FromStrRadixErr = Option<<U as Num>::FromStrRadixErr>;
    fn from_str_radix(
        str: &str,
        radix: u32
    ) -> Result<Self, Self::FromStrRadixErr> {
        if let Some(suffix) = str.strip_prefix('-') {
            Self(U::from_str_radix(suffix, radix).map_err(Some)?).checked_neg().ok_or(None)
        } else if let Some(suffix) = str.strip_prefix('+') {
            Ok(Self(U::from_str_radix(suffix, radix).map_err(Some)?))
        } else {
            Ok(Self(U::from_str_radix(str, radix).map_err(Some)?))
        }
    }
}

impl<U> CheckedMul for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        if self.is_negative() && !rhs.is_negative() {
            (!self.0)
                .checked_mul(&rhs.0)
                .map(Self)
                .as_ref()
                .and_then(Self::checked_neg)
                .and_then(|x| x.checked_sub(rhs))
        } else if !self.is_negative() && !rhs.is_negative() {
            self.0.checked_mul(&rhs.0).map(Self)
        } else if !self.is_negative() && rhs.is_negative() {
            (!rhs.0)
                .checked_mul(&self.0)
                .map(Self)
                .as_ref()
                .and_then(Self::checked_neg)
                .and_then(|x| x.checked_sub(self))
        } else {
            self.checked_neg().and_then(|x| rhs.checked_neg().and_then(|y| x.0.checked_mul(&y.0))).map(Self)
        } 
    }
}

impl<U> Mul for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs).expect("multiplication overflowed")
    }
}

impl<U> CheckedDiv for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        self.abs().0.checked_div(&rhs.abs().0).map(Self).and_then(|x| {
            if self.is_negative() == rhs.is_negative() {
                (!x.is_negative()).then_some(x)
            } else {
                Some(-x)
            }
        })
    }
}

impl<U> Div<Signed<U>> for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.checked_div(&rhs).expect("division overflow")
    }
}

impl<U> CheckedRem for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    fn checked_rem(&self, rhs: &Self) -> Option<Self> {
        if rhs.is_zero() {
            None
        } else {
            let magnitude = Self(self.abs().0 % rhs.abs().0);
            Some(if !self.is_negative() {
                magnitude
            } else {
                -magnitude
            })
        }
    }
}

impl<U> Rem for Signed<U> where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem + Copy {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        self.checked_rem(&rhs).expect("remainder overflow")
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

impl<U> TryFrom<Signed<U>> for i128 where U: AsRef<[u64]> + BorshSerialize + BorshDeserialize + Zero + One + Not<Output = U> + CheckedAdd + Sub<Output = U> + PartialEq + Eq + PartialOrd + CheckedMul + Num + CheckedDiv + Rem, u64: TryFrom<U, Error = &'static str>, u128: TryFrom<U, Error = <u64 as TryFrom<U>>::Error>, i128: TryFrom<U, Error = <u64 as TryFrom<U>>::Error> {
    type Error = <u64 as TryFrom<U>>::Error;

    fn try_from(value: Signed<U>) -> Result<Self, Self::Error> {
        let words = value.0.as_ref();
        if words.len() == 0 {
            panic!("signed integer cannot have a 0 bitwidth")
        } else if words.len() == 1 {
            u64::try_from(value.0).map(|x| (x as i64).into())
        } else if words.len() == 2 {
            u128::try_from(value.0).map(|x| x as i128)
        } else if words[2..].iter().all(|x| *x == 0) {
            i128::try_from(value.0)
                .and_then(|x| if x < 0 { Err("overflow") } else { Ok(x) })
        } else if words[2..].iter().all(|x| *x == u64::MAX) {
            i128::try_from((-value).0)
                .and_then(|x| if x < 0 { Err("overflow") } else { Ok(-x) })
        } else {
            Err("integer overflow when casting to i128")
        }
    }
}

#[cfg(test)]
mod test_uint {
    use super::*;
    use crate::types::token::Amount;

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
        let signed = I256::from_uint(MAX_SIGNED_VALUE).expect("Test failed");
        let one = I256::from_uint(Uint::from(1u64)).expect("Test failed");
        let overflow = signed + one;
        assert_eq!(
            overflow,
            I256::from_uint(Uint::zero()).expect("Test failed")
        );
        assert!(signed.checked_add(&one).is_none());
        assert!((-signed).checked_sub(&one).is_none());
    }

    /// Test that we correctly reserve the right bit for indicating the
    /// sign.
    #[test]
    fn test_non_negative() {
        let zero = I256::from_uint(Uint::zero()).expect("Test failed");
        assert!(!zero.is_negative());
        assert!(!(-zero).is_negative());
        let negative = Signed(Uint([1u64, 0, 0, 2u64.pow(63)]));
        assert!(negative.is_negative());
        assert!(!(-negative).is_negative());
        let positive = Signed(MAX_SIGNED_VALUE);
        assert!(!positive.is_negative());
        assert!((-positive).is_negative());
    }

    /// Test that the absolute value is computed correctly.
    #[test]
    fn test_abs() {
        let zero = I256::from_uint(Uint::zero()).expect("Test failed");
        let neg_one = Signed(Uint::max_value());
        let neg_eight = Signed(Uint::max_value() - Uint::from(7));
        let two = Signed(Uint::from(2));
        let ten = Signed(Uint::from(10));

        assert_eq!(zero.abs().0, Uint::zero());
        assert_eq!(neg_one.abs().0, Uint::from(1));
        assert_eq!(neg_eight.abs().0, Uint::from(8));
        assert_eq!(two.abs().0, Uint::from(2));
        assert_eq!(ten.abs().0, Uint::from(10));
    }

    /// Test that the string representation is created correctly.
    #[test]
    fn test_to_string_native() {
        let native_scaling = Uint::exp10(6);
        let zero = I256::from_uint(Uint::zero()).expect("Test failed");
        let neg_one = -Signed(native_scaling);
        let neg_eight = -Signed(Uint::from(8) * native_scaling);
        let two = Signed(Uint::from(2) * native_scaling);
        let ten = Signed(Uint::from(10) * native_scaling);

        assert_eq!(zero.to_string_native(), "0.000000");
        assert_eq!(neg_one.to_string_native(), "-1.000000");
        assert_eq!(neg_eight.to_string_native(), "-8.000000");
        assert_eq!(two.to_string_native(), "2.000000");
        assert_eq!(ten.to_string_native(), "10.000000");
    }

    /// Test that we correctly handle arithmetic with two's complement
    #[test]
    fn test_arithmetic() {
        let zero = I256::from_uint(Uint::zero()).expect("Test failed");
        let neg_one = Signed(Uint::max_value());
        let neg_eight = Signed(Uint::max_value() - Uint::from(7));
        let two = Signed(Uint::from(2));
        let ten = Signed(Uint::from(10));

        assert_eq!(zero + neg_one, neg_one);
        assert_eq!(neg_one - zero, neg_one);
        assert_eq!(zero - neg_one, Signed(Uint::one()));
        assert_eq!(two - neg_eight, ten);
        assert_eq!(two + ten, Signed(Uint::from(12)));
        assert_eq!(ten - two, -neg_eight);
        assert_eq!(two - ten, neg_eight);
        assert_eq!(neg_eight + neg_one, -Signed(Uint::from(9)));
        assert_eq!(neg_one - neg_eight, Signed(Uint::from(7)));
        assert_eq!(neg_eight - neg_one, -Signed(Uint::from(7)));
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

    #[test]
    fn test_serialization_roundtrip() {
        let amount: Uint = serde_json::from_str(r#""1000000000""#).unwrap();
        assert_eq!(amount, Uint::from(1000000000));
        let serialized = serde_json::to_string(&amount).unwrap();
        assert_eq!(serialized, r#""1000000000""#);

        let amount: Result<Uint, _> = serde_json::from_str(r#""1000000000.2""#);
        assert!(amount.is_err());
    }
}
