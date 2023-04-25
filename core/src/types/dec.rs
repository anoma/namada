//! A non-negative fixed precision decimal type for computation primarily in the
//! PoS module.
use core::fmt::{Debug, Formatter};
use std::fmt::Display;
use std::ops::{Add, AddAssign, Div, Mul, Sub};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::token::{Amount, Change};
use crate::types::uint::Uint;

/// The number of Dec places for PoS rational calculations
pub const POS_DECIMAL_PRECISION: u8 = 6;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("{error}")]
    First { error: String },
}

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
    /// Division with truncation (TDO: better description)
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

// TODO: improve (actualyl do) error handling!
impl FromStr for Dec {
    type Err = self::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with('-') {
            return Err(self::Error::First {
                error: "Dec cannot be negative".to_string(),
            });
        }
        if let Some((large, mut small)) = s.split_once('.') {
            let num_large =
                u64::from_str(large).map_err(|_| self::Error::First {
                    error: "Error".to_string(),
                })?;
            let mut num_small =
                u64::from_str(small).map_err(|_| self::Error::First {
                    error: "Error".to_string(),
                })?;

            if num_small == 0u64 {
                return Ok(Dec(Uint::from(num_large)));
            }

            small = small.trim_end_matches('0');
            let mut num_dec_places = small.len();
            if num_dec_places > POS_DECIMAL_PRECISION as usize {
                // truncate to the first `POS_DECIMAL_PRECISION` places
                num_dec_places = POS_DECIMAL_PRECISION as usize;
                small = &small[..POS_DECIMAL_PRECISION as usize];
                num_small =
                    u64::from_str(small).map_err(|_| self::Error::First {
                        error: "Error".to_string(),
                    })?;
            }
            if num_large == 0u64 {
                return Ok(Dec::new(num_small, num_dec_places as u8)
                    .expect("Dec creation failed"));
            }
            let tot_num = format!("{}{}", num_large, num_small);
            let tot_num = u64::from_str(tot_num.as_str()).map_err(|_| {
                self::Error::First {
                    error: "Error".to_string(),
                }
            })?;
            Ok(Dec::new(tot_num, num_dec_places as u8)
                .expect("Dec creation failed"))
        } else {
            Err(self::Error::First {
                error: "Error".to_string(),
            })
        }
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

    fn div(self, rhs: Dec) -> Self::Output {
        Self(self.0 / rhs.0)
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
            Dec::one() + Dec::new(3, 0).unwrap() / Dec::new(5, 0).unwrap(),
            Dec::new(16, 1).unwrap()
        );
    }
}
