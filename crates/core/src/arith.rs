//! Arithmetics helpers

pub use smooth_operator::{checked, Error};

/// Performs addition that returns `None` instead of wrapping around on
/// overflow.
pub trait CheckedAdd: Sized + Copy {
    /// Adds two numbers, checking for overflow. If overflow happens, `None` is
    /// returned.
    fn checked_add(&self, rhs: Self) -> Option<Self>;
}

/// Helpers for testing.
#[cfg(feature = "testing")]
pub mod testing {
    use super::*;

    impl CheckedAdd for u64 {
        fn checked_add(&self, rhs: Self) -> Option<Self> {
            u64::checked_add(*self, rhs)
        }
    }
}
