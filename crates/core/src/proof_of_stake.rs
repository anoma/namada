//! Proof-of-Stake abstract interfaces

use crate::address::Address;
use crate::storage;

/// Abstract PoS storage read interface
pub trait Read<S> {
    /// Storage error
    type Err;

    /// Check if the provided address is a validator address
    fn is_validator(storage: &S, address: &Address) -> Result<bool, Self::Err>;

    /// Check if the provided address is a delegator address, optionally at a
    /// particular epoch. Returns `false` if the address is a validator.
    fn is_delegator(
        storage: &S,
        address: &Address,
        epoch: Option<storage::Epoch>,
    ) -> Result<bool, Self::Err>;

    /// Read PoS pipeline length parameter
    fn pipeline_len(storage: &S) -> Result<u64, Self::Err>;
}
