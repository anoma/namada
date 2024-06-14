//! Governance abstract interfaces

/// Abstract governance storage read interface
pub trait Read<S> {
    /// Storage error
    type Err;

    /// Check if an accepted proposal is being executed
    fn is_proposal_accepted(
        storage: &S,
        tx_data: &[u8],
    ) -> Result<bool, Self::Err>;
}
