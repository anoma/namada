//! Proof-of-Stake abstract interfaces

use crate::address::Address;
use crate::storage::Epoch;
use crate::{storage, token};

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
}

/// Abstract PoS storage write interface
pub trait Write<S>: Read<S> {
    /// Self-bond tokens to a validator when `source` is `None` or equal to
    /// the `validator` address, or delegate tokens from the `source` to the
    /// `validator`.
    fn bond_tokens(
        storage: &mut S,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
        current_epoch: Epoch,
        offset_opt: Option<u64>,
    ) -> Result<(), Self::Err>;
}
