//! Compiler hints, to improve the performance of certain operations.

/// A function that is seldom called.
#[inline]
#[cold]
pub fn cold() {}

/// A likely path to be taken in an if-expression.
///
/// # Example
///
/// ```ignore
/// if likely(frequent_condition()) {
///     // most common path to take
/// } else {
///     // ...
/// }
/// ```
#[inline]
pub fn likely(b: bool) -> bool {
    if !b {
        cold()
    }
    b
}

/// An unlikely path to be taken in an if-expression.
///
/// # Example
///
/// ```ignore
/// if unlikely(rare_condition()) {
///     // ...
/// } else {
///     // most common path to take
/// }
/// ```
#[inline]
pub fn unlikely(b: bool) -> bool {
    if b {
        cold()
    }
    b
}
