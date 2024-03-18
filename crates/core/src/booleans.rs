//! Boolean related functionality.

/// Extend [`bool`] values with the possibility to create
/// [`Result`] values of unit and some error type.
pub trait BoolResultUnitExt<E> {
    /// Return `Ok(())` if true, or `error` if false.
    fn ok_or(self, error: E) -> Result<(), E>;

    /// Return `Ok(())` if true, or the value returned by
    /// `handle_err` if false.
    fn ok_or_else<F>(self, handle_err: F) -> Result<(), E>
    where
        F: FnOnce() -> E;
}

impl<E> BoolResultUnitExt<E> for bool {
    #[inline]
    fn ok_or(self, error: E) -> Result<(), E> {
        self.ok_or_else(|| error)
    }

    #[inline]
    fn ok_or_else<F>(self, handle_err: F) -> Result<(), E>
    where
        F: FnOnce() -> E,
    {
        if self { Ok(()) } else { Err(handle_err()) }
    }
}
