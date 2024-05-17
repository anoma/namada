//! Arithmetics helpers

pub use masp_primitives::num_traits::ops::checked::{
    CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg, CheckedRem, CheckedSub,
};
pub use masp_primitives::num_traits::ops::overflowing::OverflowingAdd;
pub use smooth_operator::{checked, Error};
