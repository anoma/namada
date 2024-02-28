use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::hash::Hash;
use namada_core::key::common;
use serde::{Deserialize, Serialize};

/// A tx data type to initialize a new established account
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct InitAccount {
    /// Public keys to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub public_keys: Vec<common::PublicKey>,
    /// The VP code hash
    pub vp_code_hash: Hash,
    /// The account signature threshold
    pub threshold: u8,
}

/// A tx data type to update an account's validity predicate
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct UpdateAccount {
    /// An address of the account
    pub addr: Address,
    /// The new VP code hash
    pub vp_code_hash: Option<Hash>,
    /// Public keys to be written into the account's storage. This can be used
    /// for signature verification of transactions for the newly created
    /// account.
    pub public_keys: Vec<common::PublicKey>,
    /// The account signature threshold
    pub threshold: Option<u8>,
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for accounts
pub mod tests {
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::hash::testing::arb_hash;
    use namada_core::key::testing::arb_common_pk;
    use proptest::prelude::Just;
    use proptest::{collection, option, prop_compose};

    use super::*;

    prop_compose! {
        /// Generate an account initialization
        pub fn arb_init_account()(
            public_keys in collection::vec(arb_common_pk(), 0..10),
        )(
            threshold in 0..=public_keys.len() as u8,
            public_keys in Just(public_keys),
            vp_code_hash in arb_hash(),
        ) -> InitAccount {
            InitAccount {
                public_keys,
                vp_code_hash,
                threshold,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary account update
        pub fn arb_update_account()(
            public_keys in collection::vec(arb_common_pk(), 0..10),
        )(
            addr in arb_non_internal_address(),
            vp_code_hash in option::of(arb_hash()),
            threshold in option::of(0..=public_keys.len() as u8),
            public_keys in Just(public_keys),
        ) -> UpdateAccount {
            UpdateAccount {
                addr,
                vp_code_hash,
                public_keys,
                threshold,
            }
        }
    }
}
