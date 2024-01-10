//! A non-negative fixed precision decimal type for computation primarily in the
//! PoS module. For rounding, any computation that exceeds the specified
//! precision is truncated down to the closest value with the specified
//! precision.

use std::fmt::{Debug, Display, Formatter};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, Mul, Neg, Sub};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::eyre;
use num_traits::CheckedMul;
use serde::{Deserialize, Serialize};

use super::token::NATIVE_MAX_DECIMAL_PLACES;
use crate::types::token::{Amount, Change};
use crate::types::uint::{Uint, I256};

/// The number of Dec places for PoS rational calculations
pub const POS_DECIMAL_PRECISION: u8 = 12;

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error [`Dec`] operations can return
pub struct Error(#[from] eyre::Error);

/// Generic result type for fallible [`Dec`] operations
pub type Result<T> = std::result::Result<T, Error>;

/// A 256 bit number with [`POS_DECIMAL_PRECISION`] number of Dec places.
///
/// To be precise, an instance X of this type should be interpreted as the Dec
/// X * 10 ^ (-[`POS_DECIMAL_PRECISION`])
#[derive(
    Clone,
    Copy,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Serialize,
    Deserialize,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct Dec(pub I256);

impl Dec {
    /// Performs division with truncation.
    ///
    /// This method divides `self` by `rhs` (right-hand side) and truncates the
    /// result to [`POS_DECIMAL_PRECISION`] decimal places. Truncation here
    /// means that any fractional part of the result that exceeds
    /// [`POS_DECIMAL_PRECISION`] is discarded.
    ///
    /// The division is performed in the following way:
    /// 1. The absolute values of the numerator and denominator are used for the
    /// division. 2. The result is calculated to a fixed precision defined
    /// by [`POS_DECIMAL_PRECISION`]. 3. If either the numerator or
    /// denominator (but not both) is negative, the result is negated. 4. If
    /// the division is impossible (e.g., division by zero or overflow), `None`
    /// is returned.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// let x = Dec::new(3, 1).unwrap(); // Represents 0.3
    /// let y = Dec::new(2, 1).unwrap(); // Represents 0.2
    /// let result = x.trunc_div(&y).unwrap();
    /// assert_eq!(result, Dec::new(15, 1).unwrap()); // Result is 1.5 truncated to 1 decimal place
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rhs`: The right-hand side `Dec` value for the division.
    ///
    /// # Returns
    ///
    /// An `Option<Dec>` which is `Some` with the result if the division is
    /// successful, or `None` if the division cannot be performed.
    pub fn trunc_div(&self, rhs: &Self) -> Option<Self> {
        let is_neg = self.0.is_negative() ^ rhs.0.is_negative();
        let inner_uint = self.0.abs();
        let inner_rhs_uint = rhs.0.abs();
        match inner_uint
            .fixed_precision_div(&inner_rhs_uint, POS_DECIMAL_PRECISION)
        {
            Some(res) => {
                let res = I256::try_from(res).ok()?;
                if is_neg {
                    Some(Self(-res))
                } else {
                    Some(Self(res))
                }
            }
            None => None,
        }
    }

    /// The representation of 0
    pub fn zero() -> Self {
        Self(I256::zero())
    }

    /// Check if value is zero
    pub fn is_zero(&self) -> bool {
        *self == Self::zero()
    }

    /// The representation of 1
    pub fn one() -> Self {
        Self(I256(
            Uint::one() * Uint::exp10(POS_DECIMAL_PRECISION as usize),
        ))
    }

    /// The representation of 2
    pub fn two() -> Self {
        Self::one() + Self::one()
    }

    /// Create a new [`Dec`] using a mantissa and a scale.
    pub fn new(mantissa: i128, scale: u8) -> Option<Self> {
        if scale > POS_DECIMAL_PRECISION {
            None
        } else {
            let abs = u64::try_from(mantissa.abs()).ok()?;
            match Uint::exp10((POS_DECIMAL_PRECISION - scale) as usize)
                .checked_mul(Uint::from(abs))
            {
                Some(res) => {
                    if mantissa.is_negative() {
                        Some(Self(-I256(res)))
                    } else {
                        Some(Self(I256(res)))
                    }
                }
                None => None,
            }
        }
    }

    /// Get the non-negative difference between two [`Dec`]s.
    pub fn abs_diff(&self, other: &Self) -> Self {
        if self > other {
            *self - *other
        } else {
            *other - *self
        }
    }

    /// Get the absolute value of self as integer
    pub fn abs(&self) -> Uint {
        self.0.abs()
    }

    /// Convert the Dec type into a I256 with truncation
    pub fn to_i256(&self) -> I256 {
        self.0 / Uint::exp10(POS_DECIMAL_PRECISION as usize)
    }

    /// Convert the Dec type into a Uint with truncation
    pub fn to_uint(&self) -> Option<Uint> {
        if self.is_negative() {
            None
        } else {
            Some(self.0.abs() / Uint::exp10(POS_DECIMAL_PRECISION as usize))
        }
    }

    /// Do subtraction of two [`Dec`]s If and only if the value is
    /// greater
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self > other {
            Some(*self - *other)
        } else {
            None
        }
    }

    /// Do addition of two [`Dec`]s
    pub fn add(&self, other: &Self) -> Self {
        Dec(self.0 + other.0)
    }

    /// Do multiply two [`Dec`]s. Return `None` if overflow.
    /// This methods will overflow incorrectly if both arguments are greater
    /// than 128bit.
    pub fn checked_mul(&self, other: &Self) -> Option<Self> {
        let result = self.0.checked_mul(&other.0)?;
        Some(Dec(result / Uint::exp10(POS_DECIMAL_PRECISION as usize)))
    }

    /// Return if the [`Dec`] is negative
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    /// Return the integer value of a [`Dec`] by rounding up.
    pub fn ceil(&self) -> I256 {
        if self.0.is_negative() {
            self.to_i256()
        } else {
            let floor = self.to_i256();
            if (*self - Dec(floor)).is_zero() {
                floor
            } else {
                floor + I256::one()
            }
        }
    }
}

impl FromStr for Dec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let ((large, small), is_neg) = if let Some(strip) = s.strip_prefix('-')
        {
            (strip.split_once('.').unwrap_or((strip, "0")), true)
        } else {
            (s.split_once('.').unwrap_or((s, "0")), false)
        };

        let num_large = Uint::from_str_radix(large, 10).map_err(|e| {
            eyre!("Could not parse {} as an integer: {}", large, e)
        })?;

        // In theory we could allow this, but it is aesthetically offensive.
        // Thus we don't.
        if small.is_empty() {
            return Err(eyre!(
                "Failed to parse Dec from string as there were no numbers \
                 following the decimal point."
            )
            .into());
        }

        let trimmed = small
            .trim_end_matches('0')
            .chars()
            .take(POS_DECIMAL_PRECISION as usize)
            .collect::<String>();
        let decimal_part = if trimmed.is_empty() {
            Uint::zero()
        } else {
            Uint::from_str_radix(&trimmed, 10).map_err(|e| {
                eyre!("Could not parse .{} as decimals: {}", small, e)
            })? * Uint::exp10(POS_DECIMAL_PRECISION as usize - trimmed.len())
        };
        let int_part = Uint::exp10(POS_DECIMAL_PRECISION as usize)
            .checked_mul(num_large)
            .ok_or_else(|| {
                eyre!(
                    "The number {} is too large to fit in the Dec type.",
                    num_large
                )
            })?;
        let inner = I256::try_from(int_part + decimal_part)
            .map_err(|e| eyre!("Could not convert Uint to I256: {}", e))?;
        if is_neg {
            Ok(Dec(-inner))
        } else {
            Ok(Dec(inner))
        }
    }
}

impl TryFrom<String> for Dec {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::from_str(&value)
    }
}

impl From<Amount> for Dec {
    fn from(amt: Amount) -> Self {
        match I256::try_from(amt.raw_amount()).ok() {
            Some(raw) => Self(
                raw * Uint::exp10(
                    (POS_DECIMAL_PRECISION - NATIVE_MAX_DECIMAL_PLACES)
                        as usize,
                ),
            ),
            None => Self::zero(),
        }
    }
}

impl TryFrom<Uint> for Dec {
    type Error = Error;

    fn try_from(value: Uint) -> std::result::Result<Self, Self::Error> {
        let i256 = I256::try_from(value)
            .map_err(|e| eyre!("Could not convert Uint to I256: {}", e))?;
        Ok(Self(i256 * Uint::exp10(POS_DECIMAL_PRECISION as usize)))
    }
}

impl From<u64> for Dec {
    fn from(num: u64) -> Self {
        Self(I256::from(num) * Uint::exp10(POS_DECIMAL_PRECISION as usize))
    }
}

impl From<usize> for Dec {
    fn from(num: usize) -> Self {
        Self::from(num as u64)
    }
}

impl From<i128> for Dec {
    fn from(num: i128) -> Self {
        Self(I256::from(num) * Uint::exp10(POS_DECIMAL_PRECISION as usize))
    }
}

impl From<i32> for Dec {
    fn from(num: i32) -> Self {
        Self::from(num as i128)
    }
}

impl TryFrom<u128> for Dec {
    type Error = Box<dyn 'static + std::error::Error>;

    fn try_from(num: u128) -> std::result::Result<Self, Self::Error> {
        Ok(Self(
            I256::try_from(Uint::from(num))?
                * Uint::exp10(POS_DECIMAL_PRECISION as usize),
        ))
    }
}

impl TryFrom<Dec> for i128 {
    type Error = std::io::Error;

    fn try_from(value: Dec) -> std::result::Result<Self, Self::Error> {
        value.0.try_into()
    }
}

// Is error handling needed for this?
impl From<I256> for Dec {
    fn from(num: I256) -> Self {
        Self(num * Uint::exp10(POS_DECIMAL_PRECISION as usize))
    }
}

impl From<Dec> for String {
    fn from(value: Dec) -> String {
        value.to_string()
    }
}

impl Add<Dec> for Dec {
    type Output = Self;

    fn add(self, rhs: Dec) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<u64> for Dec {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + I256::from(rhs))
    }
}

impl AddAssign<Dec> for Dec {
    fn add_assign(&mut self, rhs: Dec) {
        *self = *self + rhs;
    }
}

impl Sum for Dec {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Dec::default(), |acc, next| acc + next)
    }
}

impl Sub<Dec> for Dec {
    type Output = Self;

    fn sub(self, rhs: Dec) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul<u64> for Dec {
    type Output = Dec;

    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0 * Uint::from(rhs))
    }
}

impl Mul<u128> for Dec {
    type Output = Dec;

    fn mul(self, rhs: u128) -> Self::Output {
        Self(self.0 * Uint::from(rhs))
    }
}

impl Mul<Amount> for Dec {
    type Output = Amount;

    fn mul(self, rhs: Amount) -> Self::Output {
        if !self.is_negative() {
            (rhs * self.0.abs()) / 10u64.pow(POS_DECIMAL_PRECISION as u32)
        } else {
            panic!("aaa");
        }
    }
}

impl Mul<Change> for Dec {
    type Output = Change;

    fn mul(self, rhs: Change) -> Self::Output {
        let tot = rhs * self.0;
        let denom = Uint::from(10u64.pow(POS_DECIMAL_PRECISION as u32));
        tot / denom
    }
}

// TODO: is some checked arithmetic needed here to prevent overflows?
impl Mul<Dec> for Dec {
    type Output = Self;

    fn mul(self, rhs: Dec) -> Self::Output {
        let prod = self.0 * rhs.0;
        Self(prod / Uint::exp10(POS_DECIMAL_PRECISION as usize))
    }
}

impl Div<Dec> for Dec {
    type Output = Self;

    /// Unchecked fixed precision division.
    ///
    /// # Panics:
    ///
    ///   * Denominator is zero
    ///   * Scaling the left hand side by 10^([`POS_DECIMAL_PRECISION`])
    ///     overflows 256 bits
    fn div(self, rhs: Dec) -> Self::Output {
        self.trunc_div(&rhs).unwrap()
    }
}

impl Div<u64> for Dec {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / Uint::from(rhs))
    }
}

impl Neg for Dec {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Display for Dec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let is_neg = self.is_negative();
        let mut string = self.0.abs().to_string();
        if string.len() > POS_DECIMAL_PRECISION as usize {
            let idx = string.len() - POS_DECIMAL_PRECISION as usize;
            string.insert(idx, '.');
        } else {
            let mut str_pre = "0.".to_string();
            for _ in 0..(POS_DECIMAL_PRECISION as usize - string.len()) {
                str_pre.push('0');
            }
            str_pre.push_str(string.as_str());
            string = str_pre;
        };
        let stripped_string = string.trim_end_matches('0');
        let stripped_string = stripped_string.trim_end_matches('.');
        if stripped_string.is_empty() {
            f.write_str("0")
        } else if is_neg {
            let stripped_string = format!("-{}", stripped_string);
            f.write_str(stripped_string.as_str())
        } else {
            f.write_str(stripped_string)
        }
    }
}

impl Debug for Dec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}

/// Helpers for testing.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;

    use super::*;

    /// Generate an arbitrary non-negative `Dec`
    pub fn arb_non_negative_dec() -> impl Strategy<Value = Dec> {
        (any::<u64>(), 0_u8..POS_DECIMAL_PRECISION).prop_map(
            |(mantissa, scale)| Dec::new(mantissa.into(), scale).unwrap(),
        )
    }

    prop_compose! {
        /// Generate an arbitrary uint
        pub fn arb_uint()(value: [u64; 4]) -> Uint {
            Uint(value)
        }
    }

    prop_compose! {
        /// Generate an arbitrary signed 256-bit integer
        pub fn arb_i256()(value in arb_uint()) -> I256 {
            I256(value)
        }
    }

    prop_compose! {
        /// Generate an arbitrary decimal wih the native denomination
        pub fn arb_dec()(value in arb_i256()) -> Dec {
            Dec(value)
        }
    }
}

#[cfg(test)]
mod test_dec {
    use super::*;
    use crate::types::token::{Amount, Change};

    #[derive(Debug, Serialize, Deserialize)]
    struct SerializerTest {
        dec: Dec,
    }

    #[test]
    fn dump_toml() {
        let serializer = SerializerTest {
            dec: Dec::new(3, 0).unwrap(),
        };
        println!("{:?}", toml::to_string(&serializer));
    }

    /// Fill in tests later
    #[test]
    fn test_dec_basics() {
        assert_eq!(
            Dec::one() + Dec::new(3, 0).unwrap() / Dec::new(5, 0).unwrap(),
            Dec::new(16, 1).unwrap()
        );
        assert_eq!(Dec::new(1, 0).expect("Test failed"), Dec::one());
        assert_eq!(Dec::new(2, 0).expect("Test failed"), Dec::two());
        assert_eq!(
            Dec(I256(Uint::from(1653))),
            Dec::new(1653, POS_DECIMAL_PRECISION).expect("Test failed")
        );
        assert_eq!(
            Dec(I256::from(-48756)),
            Dec::new(-48756, POS_DECIMAL_PRECISION).expect("Test failed")
        );
        assert_eq!(
            Dec::new(123456789, 4)
                .expect("Test failed")
                .to_uint()
                .unwrap(),
            Uint::from(12345)
        );
        assert_eq!(
            Dec::new(-123456789, 4).expect("Test failed").to_i256(),
            I256::from(-12345)
        );
        assert_eq!(
            Dec::new(123, 4).expect("Test failed").to_uint().unwrap(),
            Uint::zero()
        );
        assert_eq!(
            Dec::new(123, 4).expect("Test failed").to_i256(),
            I256::zero()
        );
        assert_eq!(
            Dec::from_str("4876.3855")
                .expect("Test failed")
                .to_uint()
                .unwrap(),
            Uint::from(4876)
        );
        assert_eq!(
            Dec::from_str("4876.3855").expect("Test failed").to_i256(),
            I256::from(4876)
        );

        // Fixed precision division is more thoroughly tested for the `Uint`
        // type. These are sanity checks that the precision is correct.
        assert_eq!(
            Dec::new(1, POS_DECIMAL_PRECISION).expect("Test failed")
                / Dec::new(1, POS_DECIMAL_PRECISION).expect("Test failed"),
            Dec::one(),
        );
        assert_eq!(
            Dec::new(1, POS_DECIMAL_PRECISION).expect("Test failed")
                / (Dec::new(1, 0).expect("Test failed") + Dec::one()),
            Dec::zero(),
        );
        assert_eq!(
            Dec::new(1, POS_DECIMAL_PRECISION).expect("Test failed")
                / Dec::two(),
            Dec::zero(),
        );

        // Test Dec * Dec multiplication
        assert!(Dec::new(32353, POS_DECIMAL_PRECISION + 1u8).is_none());
        let dec1 = Dec::new(12345654321, 12).expect("Test failed");
        let dec2 = Dec::new(9876789, 12).expect("Test failed");
        let exp_prod = Dec::new(121935, 12).expect("Test failed");
        let exp_quot = Dec::new(1249966393025101, 12).expect("Test failed");
        assert_eq!(dec1 * dec2, exp_prod);
        assert_eq!(dec1 / dec2, exp_quot);
    }

    /// Test the `Dec` and `Amount` interplay
    #[test]
    fn test_dec_and_amount() {
        let amt = Amount::from(1018u64);
        let dec = Dec::from_str("2.76").unwrap();

        debug_assert_eq!(
            Dec::from(amt),
            Dec::new(1018, 6).expect("Test failed")
        );
        debug_assert_eq!(dec * amt, Amount::from(2809u64));

        let chg = -amt.change();
        debug_assert_eq!(dec * chg, Change::from(-2809i64));
    }

    #[test]
    fn test_into() {
        assert_eq!(
            Dec::from(u64::MAX),
            Dec::from_str("18446744073709551615.000000000000")
                .expect("only 104 bits")
        )
    }

    /// Test that parsing from string is correct.
    #[test]
    fn test_dec_from_string() {
        // Fewer than six decimal places and non-zero integer part
        assert_eq!(
            Dec::from_str("3.14").expect("Test failed"),
            Dec::new(314, 2).expect("Test failed"),
        );

        // more than 12 decimal places and zero integer part
        assert_eq!(
            Dec::from_str("0.1234567654321").expect("Test failed"),
            Dec::new(123456765432, 12).expect("Test failed"),
        );

        // No zero before the decimal
        assert_eq!(
            Dec::from_str(".333333").expect("Test failed"),
            Dec::new(333333, 6).expect("Test failed"),
        );

        // No decimal places
        assert_eq!(
            Dec::from_str("50").expect("Test failed"),
            Dec::new(50, 0).expect("Test failed"),
        );

        // Test zero representations
        assert_eq!(Dec::from_str("0").expect("Test failed"), Dec::zero());
        assert_eq!(Dec::from_str("0.0").expect("Test failed"), Dec::zero());
        assert_eq!(Dec::from_str(".0").expect("Test failed"), Dec::zero());

        // Error conditions

        // Test that a decimal point must be followed by numbers
        assert!(Dec::from_str("0.").is_err());
        // Test that multiple decimal points get caught
        assert!(Dec::from_str("1.2.3").is_err());
        // Test that non-numerics are caught
        assert!(Dec::from_str("DEADBEEF.12").is_err());
        assert!(Dec::from_str("23.DEADBEEF").is_err());
        // Test that we catch strings overflowing 256 bits
        let mut yuge = String::from("1");
        for _ in 0..80 {
            yuge.push('0');
        }
        assert!(Dec::from_str(&yuge).is_err());
    }

    /// Test that parsing from string is correct.
    #[test]
    fn test_dec_from_serde() {
        assert_eq!(
            serde_json::from_str::<Dec>(r#""0.667""#).expect("all good"),
            Dec::from_str("0.667").expect("should work")
        );

        let dec = Dec::from_str("0.667").unwrap();
        assert_eq!(
            dec,
            serde_json::from_str::<Dec>(&serde_json::to_string(&dec).unwrap())
                .unwrap()
        );
    }

    /// Test that ordering of [`Dec`] values using more than 64 bits works.
    #[test]
    fn test_ordering() {
        let smaller = Dec::from_str("6483947304.195066085701").unwrap();
        let larger = Dec::from_str("32418116583.390243854642").unwrap();
        assert!(smaller < larger);
    }

    /// Test that taking the ceiling of a [`Dec`] works.
    #[test]
    fn test_ceiling() {
        let neg = Dec::from_str("-2.4").expect("Test failed");
        assert_eq!(
            neg.ceil(),
            Dec::from_str("-2").expect("Test failed").to_i256()
        );
        let pos = Dec::from_str("2.4").expect("Test failed");
        assert_eq!(
            pos.ceil(),
            Dec::from_str("3").expect("Test failed").to_i256()
        );
    }

    #[test]
    fn test_dec_display() {
        let num = Dec::from_str("14000.0000").unwrap();
        let s = format!("{}", num);
        assert_eq!(s, String::from("14000"));
    }
}
