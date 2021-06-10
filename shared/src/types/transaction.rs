//! Types that are used in transactions.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::key::ed25519::{Keypair, SignedTxData};

/// A tx data type to update an account's validity predicate
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct UpdateVp {
    /// An address of the account
    pub addr: Address,
    /// The new VP code
    pub vp_code: Vec<u8>,
}

impl UpdateVp {
    /// Sign data for transaction with a given keypair.
    pub fn sign(
        self,
        tx_code: impl AsRef<[u8]>,
        keypair: &Keypair,
    ) -> SignedTxData {
        let bytes = self.try_to_vec().expect(
            "Encoding transfer data to update a validity predicate shouldn't \
             fail",
        );
        SignedTxData::new(keypair, bytes, tx_code)
    }
}
