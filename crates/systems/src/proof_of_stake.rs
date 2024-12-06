//! Proof-of-Stake abstract interfaces

use namada_core::address::Address;
use namada_core::chain::Epoch;
use namada_core::token;
pub use namada_storage::Result;

use crate::governance;

/// Abstract PoS storage read interface
pub trait Read<S> {
    /// Check if the provided address is a validator address
    fn is_validator(storage: &S, address: &Address) -> Result<bool>;

    /// Check if the provided address is a delegator address, optionally at a
    /// particular epoch. Returns `false` if the address is a validator.
    fn is_delegator(
        storage: &S,
        address: &Address,
        epoch: Option<Epoch>,
    ) -> Result<bool>;

    /// Read PoS pipeline length parameter
    fn pipeline_len(storage: &S) -> Result<u64>;

    /// Get the epoch offset from which an unbonded bond can withdrawn
    fn withdrawable_epoch_offset(storage: &S) -> Result<u64>;

    /// Read total active stake
    fn total_active_stake<Gov>(
        storage: &S,
        epoch: Epoch,
    ) -> Result<token::Amount>
    where
        Gov: governance::Read<S>;

    /// Returns `Ok(true)` if the given address is a validator and it's not
    /// jailed or inactive
    fn is_active_validator<Gov>(
        storage: &S,
        validator: &Address,
        epoch: Epoch,
    ) -> Result<bool>
    where
        Gov: governance::Read<S>;

    /// Read PoS validator's stake.
    /// For non-validators and validators with `0` stake, this returns the
    /// default - `token::Amount::zero()`.
    fn read_validator_stake<Gov>(
        storage: &S,
        validator: &Address,
        epoch: Epoch,
    ) -> Result<token::Amount>
    where
        Gov: governance::Read<S>;

    /// Get the total bond amount, including slashes, for a given bond ID and
    /// epoch. Returns the bond amount after slashing. For future epochs,
    /// the value is subject to change.
    fn bond_amount<Gov>(
        storage: &S,
        validator: &Address,
        delegator: &Address,
        epoch: Epoch,
    ) -> Result<token::Amount>
    where
        Gov: governance::Read<S>;
}
