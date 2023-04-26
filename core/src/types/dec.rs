//! A non-negative fixed precision decimal type for computation primarily in the
//! PoS module.
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Add, AddAssign, Div, Mul, Sub};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::eyre;
use serde::{Deserialize, Serialize};

use crate::types::token::{Amount, Change};
use crate::types::uint::Uint;

/// The number of Dec places for PoS rational calculations
pub const POS_DECIMAL_PRECISION: u8 = 6;

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
    Serialize,
    Deserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
)]
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
        Self(Uint::one())
    }

    /// The representation of 2
    pub fn two() -> Self {
        Self(Uint::one() + Uint::one())
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

impl From<Amount> for Dec {
    fn from(amt: Amount) -> Self {
        Self(amt.into())
    }
}

impl From<u64> for Dec {
    fn from(num: u64) -> Self {
        Self(Uint::from(num * 10u64.pow(POS_DECIMAL_PRECISION as u32)))
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
        self.0 * rhs
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

impl Mul<Dec> for Dec {
    type Output = Self;

    fn mul(self, rhs: Dec) -> Self::Output {
        Self(self.0 * rhs.0)
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

impl Display for Dec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = self.0.to_string();
        f.write_str(&string)
    }
}

#[cfg(test)]
mod test_dec {
    use super::*;

    /// Fill in tests later
    #[test]
    fn test_basic() {
        assert_eq!(
            Dec::new(1, 0).unwrap()
                + Dec::new(3, 0).unwrap() / Dec::new(5, 0).unwrap(),
            Dec::new(16, 1).unwrap()
        );
    }

    /// Test that parsing from string is correct.
    #[test]
    fn test_from_string() {
        // Fewer than six decimal places and non-zero integer part
        assert_eq!(
            Dec::from_str("3.14").expect("Test failed"),
            Dec::new(314, 2).expect("Test failed"),
        );

        // more than six decimal places and zero integer part
        assert_eq!(
            Dec::from_str("0.1234567").expect("Test failed"),
            Dec::new(123456, 6).expect("Test failed"),
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
}
