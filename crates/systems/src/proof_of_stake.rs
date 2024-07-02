//! Proof-of-Stake abstract interfaces

use namada_core::address::Address;
use namada_core::storage;
pub use namada_storage::Result;

/// Abstract PoS storage read interface
pub trait Read<S> {
    /// Check if the provided address is a validator address
    fn is_validator(storage: &S, address: &Address) -> Result<bool>;

    /// Check if the provided address is a delegator address, optionally at a
    /// particular epoch. Returns `false` if the address is a validator.
    fn is_delegator(
        storage: &S,
        address: &Address,
        epoch: Option<storage::Epoch>,
    ) -> Result<bool>;

    /// Read PoS pipeline length parameter
    fn pipeline_len(storage: &S) -> Result<u64>;
}
