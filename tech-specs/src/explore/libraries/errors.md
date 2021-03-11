# Error handling

To make the code robust, we should avoid using code that may panic for errors that recoverable and handle all possible errors explicitly. Two exceptions to this rule are:
- prototyping, where it's fine to use `unwrap`, `expect`, etc.
- in code paths with conditional compilation **only** for development build, where it's preferable to use `expect` in place of `unwrap` to help with debugging

In case of panics, we should provide an error trace that is helpful for trouble-shooting and debugging.

The current preference is to use `thiserror` for library and library-like code and `eyre` for application code.

The considered DBs:
- thiserror
- anyhow
- eyre

## Thiserror

- <https://crates.io/crates/thiserror>

Macros for user-derived error types. Commonly used for library code.

## Anyhow

- <https://crates.io/crates/anyhow>

Easy error handling helpers. Commonly used for application code.

## Eyre

- <https://crates.io/crates/eyre>

Fork of `anyhow` with custom error reporting.
