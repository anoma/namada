#![allow(clippy::assign_op_pattern)]
//! An unsigned 256 integer type. Used for, among other things,
//! the backing type of token amounts.
use std::cmp::Ordering;
use std::ops::{BitXor, Neg};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use impl_num_traits::impl_uint_num_traits;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use uint::construct_uint;

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

impl Uint {
    /// Compute the two's complement of a number.
    fn negate(&self) -> Option<Self> {
        Self(
            self.0
                .into_iter()
                .map(|byte| byte.bitxor(u64::MAX))
                .try_collect()
                .expect("This cannot fail"),
        )
        .checked_add(Uint::from(1u64))
    }
}

/// The maximum absolute value a [`SignedUint`] may have.
/// Note the the last digit is 2^63 - 1. We add this cap so
/// we can use two's complement.
pub const MAX_VALUE: Uint =
    Uint([u64::MAX, u64::MAX, u64::MAX, 9223372036854775807]);

/// A signed 256 big integer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
}

impl TryFrom<Uint> for SignedUint {
    type Error = Box<dyn 'static + std::error::Error>;

    fn try_from(value: Uint) -> Result<Self, Self::Error> {
        if value.0 <= MAX_VALUE.0 {
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
        Self(
            self.0
                .into_iter()
                .map(|byte| byte.bitxor(u64::MAX))
                .try_collect()
                .expect("This cannot fail")
                .0
                .checked_add(Uint::from(1u64))
                .unwrap(),
        )
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
