//! A non-negative fixed precision decimal type for computation primarily in the
//! PoS module. For rounding, any computation that exceeds the specified
//! precision is truncated down to the closest value with the specified
//! precision.

use std::fmt::{Debug, Display, Formatter};
use std::ops::{Add, AddAssign, Div, Mul, Sub};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::eyre;
use serde::{Deserialize, Serialize};

use super::token::NATIVE_MAX_DECIMAL_PLACES;
use crate::types::token::{Amount, Change};
use crate::types::uint::Uint;

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
/// To be precise, an instance X of this type should be interpeted as the Dec
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
    Debug,
    Hash,
)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct Dec(pub Uint);

impl std::ops::Deref for Dec {
    type Target = Uint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Dec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Dec {
    /// Division with truncation (TODO: better description)
    pub fn trunc_div(&self, rhs: &Self) -> Option<Self> {
        self.0
            .fixed_precision_div(rhs, POS_DECIMAL_PRECISION)
            .map(Self)
    }

    /// The representation of 0
    pub fn zero() -> Self {
        Self(Uint::zero())
    }

    /// The representation of 1
    pub fn one() -> Self {
        Self(Uint::one() * Uint::exp10(POS_DECIMAL_PRECISION as usize))
    }

    /// The representation of 2
    pub fn two() -> Self {
        Self(
            (Uint::one() + Uint::one())
                * Uint::exp10(POS_DECIMAL_PRECISION as usize),
        )
    }

    /// Create a new [`Dec`] using a mantissa and a scale.
    pub fn new(mantissa: u64, scale: u8) -> Option<Self> {
        if scale > POS_DECIMAL_PRECISION {
            None
        } else {
            Uint::exp10((POS_DECIMAL_PRECISION - scale) as usize)
                .checked_mul(Uint::from(mantissa))
                .map(Self)
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

    /// Convert the Dec type into a Uint with truncation
    pub fn to_uint(&self) -> Uint {
        self.0 / Uint::exp10(POS_DECIMAL_PRECISION as usize)
    }
}

impl FromStr for Dec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.starts_with('-') {
            return Err(eyre!("Dec cannot be negative").into());
        }

        let (large, small) = s.split_once('.').unwrap_or((s, "0"));
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
        Ok(Dec(int_part + decimal_part))
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
        Self(
            amt.raw_amount()
                * Uint::exp10(
                    (POS_DECIMAL_PRECISION - NATIVE_MAX_DECIMAL_PLACES)
                        as usize,
                ),
        )
    }
}

impl From<u64> for Dec {
    fn from(num: u64) -> Self {
        Self(Uint::from(num * 10u64.pow(POS_DECIMAL_PRECISION as u32)))
    }
}

// Is error handling needed for this?
impl From<Uint> for Dec {
    fn from(num: Uint) -> Self {
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
        Self(self.0 + Uint::from(rhs))
    }
}

impl AddAssign<Dec> for Dec {
    fn add_assign(&mut self, rhs: Dec) {
        *self = *self + rhs;
    }
}

impl Sub<Dec> for Dec {
    type Output = Self;

    fn sub(self, rhs: Dec) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul<Uint> for Dec {
    type Output = Uint;

    fn mul(self, rhs: Uint) -> Self::Output {
        self.0 * rhs / Uint::exp10(POS_DECIMAL_PRECISION as usize)
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
        (rhs * self.0) / 10u64.pow(POS_DECIMAL_PRECISION as u32)
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

impl Display for Dec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut string = self.0.to_string();
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
        f.write_str(&string)
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
            Dec(Uint::from(1653)),
            Dec::new(1653, POS_DECIMAL_PRECISION).expect("Test failed")
        );
        assert_eq!(
            Dec::new(123456789, 4).expect("Test failed").to_uint(),
            Uint::from(12345)
        );
        assert_eq!(
            Dec::new(123, 4).expect("Test failed").to_uint(),
            Uint::zero()
        );
        assert_eq!(
            Dec::from_str("4876.3855").expect("Test failed").to_uint(),
            Uint::from(4876)
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
        // Test that negative numbers are rejected
        assert!(Dec::from_str("-1").is_err());
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
}
