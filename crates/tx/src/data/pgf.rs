use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::collections::HashMap;
use namada_core::dec::Dec;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum PgfError {
    #[error("Invalid pgf update commission transaction.")]
    InvalidPgfCommission,
}

/// A tx data type to hold proposal data
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSchema,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Serialize,
    Deserialize,
)]
pub struct UpdateStewardCommission {
    /// The pgf steward address
    pub steward: Address,
    /// The new commission distribution
    pub commission: HashMap<Address, Dec>,
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for PGF
pub mod tests {
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::dec::testing::arb_dec;
    use proptest::{collection, prop_compose};

    use super::UpdateStewardCommission;

    prop_compose! {
        /// Generate an arbitraary steward commission update
        pub fn arb_update_steward_commission()(
            steward in arb_non_internal_address(),
            commission in collection::hash_map(arb_non_internal_address(), arb_dec(), 0..10),
        ) -> UpdateStewardCommission {
            UpdateStewardCommission {
                steward,
                commission: commission.into_iter().collect(),
            }
        }
    }
}
