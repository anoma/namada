#![allow(clippy::assign_op_pattern)]
//! An unsigned 256 integer type. Used for, among other things,
//! the backing type of token amounts.
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, AddAssign, BitAnd, Div, Mul, Neg, Rem, Sub, SubAssign};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use impl_num_traits::impl_uint_num_traits;
use num_integer::Integer;
use num_traits::{CheckedAdd, CheckedMul, CheckedSub};
use uint::construct_uint;

use super::dec::{Dec, POS_DECIMAL_PRECISION};
use crate::token;
use crate::token::{Amount, AmountParseError, MaspDigitPos};

/// The value zero.
pub const ZERO: Uint = Uint::from_u64(0);

/// The value one.
pub const ONE: Uint = Uint::from_u64(1);

impl Uint {
    const N_WORDS: usize = 4;

    /// Convert a [`u64`] to a [`Uint`].
    pub const fn from_u64(x: u64) -> Uint {
        Uint([x.to_le(), 0, 0, 0])
    }

    /// Return the least number of bits needed to represent the number
    #[inline]
    pub fn bits_512(arr: &[u64; 2 * Self::N_WORDS]) -> usize {
        for i in 1..arr.len() {
            if arr[arr.len() - i] > 0 {
                return (0x40 * (arr.len() - i + 1))
                    - arr[arr.len() - i].leading_zeros() as usize;
            }
        }
        0x40 - arr[0].leading_zeros() as usize
    }

    fn div_mod_small_512(
        mut slf: [u64; 2 * Self::N_WORDS],
        other: u64,
    ) -> ([u64; 2 * Self::N_WORDS], Self) {
        let mut rem = 0u64;
        slf.iter_mut().rev().for_each(|d| {
            let (q, r) = Self::div_mod_word(rem, *d, other);
            *d = q;
            rem = r;
        });
        (slf, rem.into())
    }

    fn shr_512(
        original: [u64; 2 * Self::N_WORDS],
        shift: u32,
    ) -> [u64; 2 * Self::N_WORDS] {
        let shift = shift as usize;
        let mut ret = [0u64; 2 * Self::N_WORDS];
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        // shift
        for i in word_shift..original.len() {
            ret[i - word_shift] = original[i] >> bit_shift;
        }

        // Carry
        if bit_shift > 0 {
            for i in word_shift + 1..original.len() {
                ret[i - word_shift - 1] += original[i] << (64 - bit_shift);
            }
        }

        ret
    }

    fn full_shl_512(
        slf: [u64; 2 * Self::N_WORDS],
        shift: u32,
    ) -> [u64; 2 * Self::N_WORDS + 1] {
        debug_assert!(shift < Self::WORD_BITS as u32);
        let mut u = [0u64; 2 * Self::N_WORDS + 1];
        let u_lo = slf[0] << shift;
        let u_hi = Self::shr_512(slf, Self::WORD_BITS as u32 - shift);
        u[0] = u_lo;
        u[1..].copy_from_slice(&u_hi[..]);
        u
    }

    fn full_shr_512(
        u: [u64; 2 * Self::N_WORDS + 1],
        shift: u32,
    ) -> [u64; 2 * Self::N_WORDS] {
        debug_assert!(shift < Self::WORD_BITS as u32);
        let mut res = [0; 2 * Self::N_WORDS];
        for i in 0..res.len() {
            res[i] = u[i] >> shift;
        }
        // carry
        if shift > 0 {
            for i in 1..=res.len() {
                res[i - 1] |= u[i] << (Self::WORD_BITS as u32 - shift);
            }
        }
        res
    }

    // See Knuth, TAOCP, Volume 2, section 4.3.1, Algorithm D.
    fn div_mod_knuth_512(
        slf: [u64; 2 * Self::N_WORDS],
        mut v: Self,
        n: usize,
        m: usize,
    ) -> ([u64; 2 * Self::N_WORDS], Self) {
        debug_assert!(Self::bits_512(&slf) >= v.bits() && !v.fits_word());
        debug_assert!(n + m <= slf.len());
        // D1.
        // Make sure 64th bit in v's highest word is set.
        // If we shift both self and v, it won't affect the quotient
        // and the remainder will only need to be shifted back.
        let shift = v.0[n - 1].leading_zeros();
        v <<= shift;
        // u will store the remainder (shifted)
        let mut u = Self::full_shl_512(slf, shift);

        // quotient
        let mut q = [0; 2 * Self::N_WORDS];
        let v_n_1 = v.0[n - 1];
        let v_n_2 = v.0[n - 2];

        // D2. D7.
        // iterate from m downto 0
        for j in (0..=m).rev() {
            let u_jn = u[j + n];

            // D3.
            // q_hat is our guess for the j-th quotient digit
            // q_hat = min(b - 1, (u_{j+n} * b + u_{j+n-1}) / v_{n-1})
            // b = 1 << WORD_BITS
            // Theorem B: q_hat >= q_j >= q_hat - 2
            let mut q_hat = if u_jn < v_n_1 {
                let (mut q_hat, mut r_hat) =
                    Self::div_mod_word(u_jn, u[j + n - 1], v_n_1);
                // this loop takes at most 2 iterations
                loop {
                    // check if q_hat * v_{n-2} > b * r_hat + u_{j+n-2}
                    let (hi, lo) =
                        Self::split_u128(u128::from(q_hat) * u128::from(v_n_2));
                    if (hi, lo) <= (r_hat, u[j + n - 2]) {
                        break;
                    }
                    // then iterate till it doesn't hold
                    q_hat -= 1;
                    let (new_r_hat, overflow) = r_hat.overflowing_add(v_n_1);
                    r_hat = new_r_hat;
                    // if r_hat overflowed, we're done
                    if overflow {
                        break;
                    }
                }
                q_hat
            } else {
                // here q_hat >= q_j >= q_hat - 1
                u64::max_value()
            };

            // ex. 20:
            // since q_hat * v_{n-2} <= b * r_hat + u_{j+n-2},
            // either q_hat == q_j, or q_hat == q_j + 1

            // D4.
            // let's assume optimistically q_hat == q_j
            // subtract (q_hat * v) from u[j..]
            let q_hat_v = v.full_mul_u64(q_hat);
            // u[j..] -= q_hat_v;
            let c = Self::sub_slice(&mut u[j..], &q_hat_v[..n + 1]);

            // D6.
            // actually, q_hat == q_j + 1 and u[j..] has overflowed
            // highly unlikely ~ (1 / 2^63)
            if c {
                q_hat -= 1;
                // add v to u[j..]
                let c = Self::add_slice(&mut u[j..], &v.0[..n]);
                u[j + n] = u[j + n].wrapping_add(u64::from(c));
            }

            // D5.
            q[j] = q_hat;
        }

        // D8.
        let remainder = Self::full_shr_512(u, shift);
        // The remainder should never exceed the capacity of Self
        debug_assert!(
            Self::bits_512(&remainder) <= Self::N_WORDS * Self::WORD_BITS
        );
        (q, Self(remainder[..Self::N_WORDS].try_into().unwrap()))
    }

    /// Returns a pair `(self / other, self % other)`.
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    pub fn div_mod_512(
        slf: [u64; 2 * Self::N_WORDS],
        other: Self,
    ) -> ([u64; 2 * Self::N_WORDS], Self) {
        let my_bits = Self::bits_512(&slf);
        let your_bits = other.bits();

        assert!(your_bits != 0, "division by zero");

        // Early return in case we are dividing by a larger number than us
        if my_bits < your_bits {
            return (
                [0; 2 * Self::N_WORDS],
                Self(slf[..Self::N_WORDS].try_into().unwrap()),
            );
        }

        if your_bits <= Self::WORD_BITS {
            return Self::div_mod_small_512(slf, other.low_u64());
        }

        let (n, m) = {
            let my_words = Self::words(my_bits);
            let your_words = Self::words(your_bits);
            (your_words, my_words - your_words)
        };

        Self::div_mod_knuth_512(slf, other, n, m)
    }

    /// Returns a pair `(Some((self * num) / denom), (self * num) % denom)` if
    /// the quotient fits into Self. Otherwise `(None, (self * num) % denom)` is
    /// returned.
    ///
    /// # Panics
    ///
    /// Panics if `denom` is zero.
    pub fn checked_mul_div(
        &self,
        num: Self,
        denom: Self,
    ) -> Option<(Self, Self)> {
        if denom.is_zero() {
            None
        } else {
            let prod = uint::uint_full_mul_reg!(Uint, 4, self, num);
            let (quotient, remainder) = Self::div_mod_512(prod, denom);
            // The compiler WILL NOT inline this if you remove this annotation.
            #[inline(always)]
            fn any_nonzero(arr: &[u64]) -> bool {
                use uint::unroll;
                unroll! {
                    for i in 0..4 {
                        if arr[i] != 0 {
                            return true;
                        }
                    }
                }

                false
            }
            if any_nonzero(&quotient[Self::N_WORDS..]) {
                None
            } else {
                Some((
                    Self(quotient[0..Self::N_WORDS].try_into().unwrap()),
                    remainder,
                ))
            }
        }
    }

    /// Returns a pair `((self * num) / denom, (self * num) % denom)`.
    ///
    /// # Panics
    ///
    /// Panics if `denom` is zero.
    pub fn mul_div(&self, num: Self, denom: Self) -> (Self, Self) {
        let prod = uint::uint_full_mul_reg!(Uint, 4, self, num);
        let (quotient, remainder) = Self::div_mod_512(prod, denom);
        (
            Self(quotient[0..Self::N_WORDS].try_into().unwrap()),
            remainder,
        )
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
        Uint::from(10)
            .checked_pow(Uint::from(denom))
            .and_then(|res| res.checked_mul_div(*self, *rhs))
            .map(|x| x.0)
    }

    /// Compute the two's complement of a number.
    fn negate(&self) -> Self {
        let mut output = self.0;
        for byte in output.iter_mut() {
            *byte ^= u64::MAX;
        }
        Self(output).overflowing_add(Uint::from(1u64)).0.canonical()
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

impl fmt::Debug for I256 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl fmt::Display for I256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_negative() {
            write!(f, "-")?;
        }
        write!(f, "{}", self.abs())
    }
}

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

    /// Gives the one value of an I256
    pub fn one() -> I256 {
        Self(Uint::one())
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
        denom: MaspDigitPos,
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

    /// Multiply by a decimal [`Dec`] with the result rounded up.
    #[must_use]
    pub fn mul_ceil(&self, dec: Dec) -> Self {
        let is_res_negative = self.is_negative() ^ dec.is_negative();
        let tot = self.abs() * dec.0.abs();
        let denom = Uint::from(10u64.pow(POS_DECIMAL_PRECISION as u32));
        let floor_div = tot / denom;
        let rem = tot % denom;
        let abs_res = Self(if !rem.is_zero() && !is_res_negative {
            floor_div + Uint::from(1_u64)
        } else {
            floor_div
        });
        if is_res_negative { -abs_res } else { abs_res }
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
        Some(self.cmp(other))
    }
}

impl Ord for I256 {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.non_negative(), other.non_negative()) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (true, true) => {
                let this = self.abs();
                let that = other.abs();
                this.cmp(&that)
            }
            (false, false) => {
                let this = self.abs();
                let that = other.abs();
                that.cmp(&this)
            }
        }
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

impl CheckedAdd for I256 {
    /// Adds two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    fn checked_add(&self, other: &Self) -> Option<Self> {
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
}

impl CheckedSub for I256 {
    /// Subtracts two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.checked_add(&other.neg())
    }
}

impl CheckedMul for I256 {
    fn checked_mul(&self, v: &Self) -> Option<Self> {
        let is_negative = self.is_negative() != v.is_negative();
        let unsigned_res =
            I256::try_from(self.abs().checked_mul(v.abs())?).ok()?;
        Some(if is_negative {
            -unsigned_res
        } else {
            unsigned_res
        })
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
    use std::str::FromStr;

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
        assert_eq!(
            two.fixed_precision_div(&three, 77).expect("Test failed"),
            Uint::from_str("9363ff047551e60c314a09cf62a269d471bafcf44a8c6aaaaaaaaaaaaaaaaaaa").unwrap()
        );
        assert_eq!(
            Uint::from(20).fixed_precision_div(&three, 76).expect("Test failed"),
            Uint::from_str("9363ff047551e60c314a09cf62a269d471bafcf44a8c6aaaaaaaaaaaaaaaaaaa").unwrap()
        );
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

    #[test]
    fn test_serialization_roundtrip() {
        let amount: Uint = serde_json::from_str(r#""1000000000""#).unwrap();
        assert_eq!(amount, Uint::from(1000000000));
        let serialized = serde_json::to_string(&amount).unwrap();
        assert_eq!(serialized, r#""1000000000""#);

        let amount: Result<Uint, _> = serde_json::from_str(r#""1000000000.2""#);
        assert!(amount.is_err());
    }

    #[test]
    fn test_i256_mul_ceil() {
        let one = I256::from(1);
        let two = I256::from(2);
        let dec = Dec::from_str("0.25").unwrap();
        assert_eq!(one.mul_ceil(dec), one);
        assert_eq!(two.mul_ceil(dec), one);
        assert_eq!(I256::from(4).mul_ceil(dec), one);
        assert_eq!(I256::from(5).mul_ceil(dec), two);

        assert_eq!((-one).mul_ceil(-dec), one);

        assert_eq!((-one).mul_ceil(dec), I256::zero());
        assert_eq!(one.mul_ceil(-dec), I256::zero());
    }

    #[test]
    fn test_mul_div() {
        use std::str::FromStr;
        let a: Uint = Uint::from_str(
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ).unwrap();
        let b: Uint = Uint::from_str(
            "0x8000000000000000000000000000000000000000000000000000000000000000",
        ).unwrap();
        let c: Uint = Uint::from_str(
            "0x4000000000000000000000000000000000000000000000000000000000000000",
        ).unwrap();
        let d: Uint = Uint::from_str(
            "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ).unwrap();
        let e: Uint = Uint::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        ).unwrap();
        let f: Uint = Uint::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ).unwrap();
        assert_eq!(a.mul_div(a, a), (a, Uint::zero()));
        assert_eq!(b.mul_div(c, b), (c, Uint::zero()));
        assert_eq!(a.mul_div(c, b), (d, c));
        assert_eq!(a.mul_div(e, e), (a, Uint::zero()));
        assert_eq!(e.mul_div(c, b), (Uint::zero(), c));
        assert_eq!(f.mul_div(a, e), (Uint::zero(), Uint::zero()));
        assert_eq!(a.checked_mul_div(a, a), Some((a, Uint::zero())));
        assert_eq!(b.checked_mul_div(c, b), Some((c, Uint::zero())));
        assert_eq!(a.checked_mul_div(c, b), Some((d, c)));
        assert_eq!(a.checked_mul_div(e, e), Some((a, Uint::zero())));
        assert_eq!(e.checked_mul_div(c, b), Some((Uint::zero(), c)));
        assert_eq!(d.checked_mul_div(a, e), None);
    }
}
