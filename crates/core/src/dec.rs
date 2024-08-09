//! A non-negative fixed precision decimal type for computation primarily in the
//! PoS module. For rounding, any computation that exceeds the specified
//! precision is truncated down to the closest value with the specified
//! precision.

use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::eyre;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::token::NATIVE_MAX_DECIMAL_PLACES;
use crate::arith::{self, checked};
use crate::token;
use crate::uint::{Uint, I256};

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
/// To be precise, an instance MaspLocalTaskEnv of this type should be
/// interpreted as the Dec MaspLocalTaskEnv * 10 ^ (-[`POS_DECIMAL_PRECISION`])
#[derive(
    Clone,
    Copy,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
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
    /// ## Breakdown of the algorithm
    ///
    /// The division is performed in the following way:
    ///
    /// 1. The absolute values of the numerator and denominator are used for the
    /// division.
    /// 2. The result is calculated to a fixed precision defined
    /// by [`POS_DECIMAL_PRECISION`].
    /// 3. If either the numerator or
    /// denominator (but not both) is negative, the result is negated.
    /// 4. If the division is impossible (e.g., division by zero or overflow),
    ///    `None` is returned.
    ///
    /// ## Example
    ///
    /// ```
    /// use namada_core::dec::Dec;
    ///
    /// let x = Dec::new(3, 1).unwrap(); // Represents 0.3
    /// let y = Dec::new(2, 1).unwrap(); // Represents 0.2
    /// let result = x.trunc_div(&y).unwrap();
    /// assert_eq!(result, Dec::new(15, 1).unwrap()); // Result is 1.5 truncated to 1 decimal place
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `rhs`: The right-hand side `Dec` value for the division.
    ///
    /// ## Returns
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
                    Some(Self(res.checked_neg()?))
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
            Uint::one()
                .checked_mul(Uint::exp10(usize::from(POS_DECIMAL_PRECISION)))
                .expect("Cannot overflow"),
        ))
    }

    /// The representation of 2
    pub fn two() -> Self {
        Self::one()
            .checked_add(Self::one())
            .expect("Cannot overflow")
    }

    /// The representation of 1 / 3
    pub fn one_third() -> Self {
        Self::one().checked_div(3).expect("Cannot fail")
    }

    /// The representation of 2 / 3
    pub fn two_thirds() -> Self {
        Self::two().checked_div(3).expect("Cannot fail")
    }

    /// Create a new [`Dec`] using a mantissa and a scale.
    pub fn new(mantissa: i128, scale: u8) -> Option<Self> {
        if scale > POS_DECIMAL_PRECISION {
            None
        } else {
            let abs = u64::try_from(mantissa.abs()).ok()?;
            // Cannot underflow
            #[allow(clippy::arithmetic_side_effects)]
            let scale_diff = POS_DECIMAL_PRECISION - scale;
            match Uint::exp10((scale_diff) as usize)
                .checked_mul(Uint::from(abs))
            {
                Some(res) => {
                    if mantissa.is_negative() {
                        Some(Self(I256(res).checked_neg()?))
                    } else {
                        Some(Self(I256(res)))
                    }
                }
                None => None,
            }
        }
    }

    /// Get the non-negative difference between two [`Dec`]s.
    pub fn abs_diff(
        &self,
        other: Self,
    ) -> std::result::Result<Self, arith::Error> {
        if self > &other {
            checked!(self - other)
        } else {
            checked!(other - *self)
        }
    }

    /// Get the absolute value of self as integer
    pub fn abs(&self) -> Uint {
        self.0.abs()
    }

    /// Convert the Dec type into a I256 with truncation
    pub fn to_i256(&self) -> I256 {
        self.0
            .checked_div(I256(Uint::exp10(usize::from(POS_DECIMAL_PRECISION))))
            .expect("Cannot panic as rhs > 0")
    }

    /// Convert the Dec type into a Uint with truncation
    pub fn to_uint(&self) -> Option<Uint> {
        if self.is_negative() {
            None
        } else {
            Some(
                self.0.abs().checked_div(Uint::exp10(usize::from(
                    POS_DECIMAL_PRECISION,
                )))?,
            )
        }
    }

    /// Do subtraction of two [`Dec`]s
    pub fn checked_sub(&self, rhs: Self) -> Option<Self> {
        Some(Self(self.0.checked_sub(rhs.0)?))
    }

    /// Do addition of two [`Dec`]s
    pub fn checked_add(&self, other: Self) -> Option<Self> {
        Some(Dec(self.0.checked_add(other.0)?))
    }

    /// Checked multiplication. Return `None` if overflow.
    /// This methods will overflow incorrectly if both arguments are greater
    /// than 128bit.
    pub fn checked_mul(&self, other: impl Into<Self>) -> Option<Self> {
        let other: Self = other.into();
        let result = self.0.checked_mul(other.0)?;
        let inner = result.checked_div(I256(Uint::exp10(usize::from(
            POS_DECIMAL_PRECISION,
        ))))?;
        Some(Dec(inner))
    }

    /// Checked division
    pub fn checked_div(self, rhs: impl Into<Self>) -> Option<Self> {
        let rhs: Self = rhs.into();
        self.trunc_div(&rhs)
    }

    /// Checked negation
    pub fn checked_neg(&self) -> Option<Self> {
        Some(Self(self.0.checked_neg()?))
    }

    /// Return if the [`Dec`] is negative
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    /// Return the integer value of a [`Dec`] by rounding up.
    pub fn ceil(&self) -> Option<I256> {
        if self.0.is_negative() {
            Some(self.to_i256())
        } else {
            let floor = self.to_i256();
            if self
                .checked_sub(Dec(floor))
                .as_ref()
                .map(Dec::is_zero)
                .unwrap_or_default()
            {
                Some(floor)
            } else {
                floor.checked_add(I256::one())
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
            .take(usize::from(POS_DECIMAL_PRECISION))
            .collect::<String>();
        let decimal_part = if trimmed.is_empty() {
            Uint::zero()
        } else {
            // `trimmed.len` <= `POS_DECIMAL_PRECISION`
            #[allow(clippy::arithmetic_side_effects)]
            let len_diff = usize::from(POS_DECIMAL_PRECISION) - trimmed.len();
            Uint::from_str_radix(&trimmed, 10)
                .map_err(|e| {
                    eyre!("Could not parse .{} as decimals: {}", small, e)
                })?
                .checked_mul(Uint::exp10(len_diff))
                .ok_or_else(|| eyre!("Decimal part overflow"))?
        };
        let int_part = Uint::exp10(usize::from(POS_DECIMAL_PRECISION))
            .checked_mul(num_large)
            .ok_or_else(|| {
                eyre!(
                    "The number {} is too large to fit in the Dec type.",
                    num_large
                )
            })?;
        let inner =
            I256::try_from(int_part.checked_add(decimal_part).ok_or_else(
                || eyre!("Failed to add integral and decimal part"),
            )?)
            .map_err(|e| eyre!("Could not convert Uint to I256: {}", e))?;
        if is_neg {
            Ok(Dec(inner
                .checked_neg()
                .ok_or_else(|| eyre!("Failed to negate"))?))
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

impl TryFrom<token::Amount> for Dec {
    type Error = Error;

    fn try_from(amt: token::Amount) -> std::result::Result<Self, Self::Error> {
        let raw = I256::try_from(amt.raw_amount())
            .map_err(|e| eyre!("Invalid raw amount: {e}"))?;
        let denom = I256(Uint::exp10(
            (POS_DECIMAL_PRECISION - NATIVE_MAX_DECIMAL_PLACES) as usize,
        ));
        let inner = checked!(raw * denom).map_err(|e| eyre!("Arith: {e}"))?;

        Ok(Self(inner))
    }
}

impl TryFrom<Uint> for Dec {
    type Error = Error;

    fn try_from(value: Uint) -> std::result::Result<Self, Self::Error> {
        let i256 = I256::try_from(value)
            .map_err(|e| eyre!("Could not convert Uint to I256: {e}"))?;
        let inner = i256
            .checked_mul(I256(Uint::exp10(usize::from(POS_DECIMAL_PRECISION))))
            .ok_or_else(|| eyre!("Overflow"))?;
        Ok(Self(inner))
    }
}

impl From<u64> for Dec {
    fn from(num: u64) -> Self {
        Self(
            I256::from(num)
                .checked_mul(I256(Uint::exp10(usize::from(
                    POS_DECIMAL_PRECISION,
                ))))
                .expect("Cannot overflow as the value is in `u64` range"),
        )
    }
}

impl From<usize> for Dec {
    fn from(num: usize) -> Self {
        Self::from(num as u64)
    }
}

impl From<i128> for Dec {
    fn from(num: i128) -> Self {
        Self(
            I256::from(num)
                .checked_mul(I256(Uint::exp10(usize::from(
                    POS_DECIMAL_PRECISION,
                ))))
                .expect("Cannot overflow as the value is in `i128` range"),
        )
    }
}

impl From<i32> for Dec {
    fn from(num: i32) -> Self {
        Self::from(i128::from(num))
    }
}

impl TryFrom<u128> for Dec {
    type Error = arith::Error;

    fn try_from(num: u128) -> std::result::Result<Self, Self::Error> {
        let denom = I256(Uint::exp10(usize::from(POS_DECIMAL_PRECISION)));
        let num =
            I256::try_from(Uint::from(num)).expect("u128 must fit in a Dec");
        let inner = checked!(num * denom)?;
        Ok(Self(inner))
    }
}

impl TryFrom<Dec> for i128 {
    type Error = std::io::Error;

    fn try_from(value: Dec) -> std::result::Result<Self, Self::Error> {
        value.0.try_into()
    }
}

impl TryFrom<I256> for Dec {
    type Error = arith::Error;

    fn try_from(num: I256) -> std::result::Result<Self, Self::Error> {
        let denom = I256(Uint::exp10(usize::from(POS_DECIMAL_PRECISION)));
        let inner = checked!(num * denom)?;
        Ok(Self(inner))
    }
}

impl From<Dec> for String {
    fn from(value: Dec) -> String {
        value.to_string()
    }
}

impl Display for Dec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let is_neg = self.is_negative();
        let mut string = self.0.abs().to_string();
        if string.len() > usize::from(POS_DECIMAL_PRECISION) {
            // Cannot underflow as we checked above
            #[allow(clippy::arithmetic_side_effects)]
            let idx = string.len() - usize::from(POS_DECIMAL_PRECISION);
            string.insert(idx, '.');
        } else {
            let mut str_pre = "0.".to_string();
            // Cannot underflow as we checked above
            #[allow(clippy::arithmetic_side_effects)]
            let end = usize::from(POS_DECIMAL_PRECISION) - string.len();
            for _ in 0..end {
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
#[allow(clippy::arithmetic_side_effects, clippy::cast_lossless)]
pub mod testing {
    use proptest::prelude::*;

    use super::*;

    impl std::ops::Add<Dec> for Dec {
        type Output = Dec;

        fn add(self, rhs: Dec) -> Self::Output {
            self.checked_add(rhs).unwrap()
        }
    }

    impl std::ops::AddAssign for Dec {
        fn add_assign(&mut self, rhs: Self) {
            *self = self.checked_add(rhs).unwrap();
        }
    }

    impl std::ops::Sub<Dec> for Dec {
        type Output = Dec;

        fn sub(self, rhs: Dec) -> Self::Output {
            self.checked_sub(rhs).unwrap()
        }
    }

    impl<T> std::ops::Mul<T> for Dec
    where
        T: Into<Self>,
    {
        type Output = Dec;

        fn mul(self, rhs: T) -> Self::Output {
            self.checked_mul(rhs.into()).unwrap()
        }
    }

    impl<T> std::ops::Div<T> for Dec
    where
        T: Into<Self>,
    {
        type Output = Self;

        fn div(self, rhs: T) -> Self::Output {
            self.trunc_div(&rhs.into()).unwrap()
        }
    }

    impl std::ops::Mul<token::Amount> for Dec {
        type Output = token::Amount;

        fn mul(self, rhs: token::Amount) -> Self::Output {
            if !self.is_negative() {
                (rhs * self.0.abs()) / 10u64.pow(POS_DECIMAL_PRECISION as u32)
            } else {
                panic!(
                    "Dec is negative and cannot produce a valid Amount output"
                );
            }
        }
    }

    impl std::ops::Mul<token::Change> for Dec {
        type Output = token::Change;

        fn mul(self, rhs: token::Change) -> Self::Output {
            let tot = rhs * self.0;
            let denom = Uint::from(10u64.pow(POS_DECIMAL_PRECISION as u32));
            tot.checked_div(I256(denom)).unwrap()
        }
    }

    impl std::iter::Sum for Dec {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(Dec::zero(), |a, b| a + b)
        }
    }

    impl std::ops::Neg for Dec {
        type Output = Dec;

        fn neg(self) -> Self::Output {
            self.checked_neg().unwrap()
        }
    }

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

        Dec::one_third(); // must not panic
        Dec::two_thirds(); // must not panic
    }

    /// Test the `Dec` and `token::Amount` interplay
    #[test]
    fn test_dec_and_amount() {
        let amt = token::Amount::from(1018u64);
        let dec = Dec::from_str("2.76").unwrap();

        debug_assert_eq!(
            Dec::try_from(amt).unwrap(),
            Dec::new(1018, 6).expect("Test failed")
        );
        debug_assert_eq!(dec * amt, token::Amount::from(2809u64));

        let chg = -amt.change();
        debug_assert_eq!(dec * chg, token::Change::from(-2809i64));
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
            neg.ceil().unwrap(),
            Dec::from_str("-2").expect("Test failed").to_i256()
        );
        let pos = Dec::from_str("2.4").expect("Test failed");
        assert_eq!(
            pos.ceil().unwrap(),
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
