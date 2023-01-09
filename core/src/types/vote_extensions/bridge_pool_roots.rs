//! Vote extension types for adding a signature
//! of the bridge pool merkle root to be added
//! to storage. This will be used to generate
//! bridge pool inclusion proofs for Ethereum.
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

use crate::proto::Signed;
use crate::types::address::Address;
use crate::types::key::common;
use crate::types::key::common::Signature;
use crate::types::storage::BlockHeight;

/// A vote extension containing a validator's signature
/// of the current root and nonce of the
/// Ethereum bridge pool.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct BridgePoolRootVext {
    /// The validator sending the vote extension
    pub validator_addr: Address,
    /// The block height at which the vote extensions was
    /// sent.
    ///
    /// This can be used as replay protection as well
    /// as allowing validators to  query the epoch with
    /// the appropriate validator set to verify signatures
    pub block_height: BlockHeight,
    /// The actual signature being submitted.
    /// This is a signature over KeccakHash(root || nonce).
    pub sig: Signature,
}

/// Alias for [`BridgePoolRootVext`].
pub type Vext = BridgePoolRootVext;

/// A signed [`BridgePoolRootVext`].
/// Note that this is serialized with Ethereum's
/// ABI encoding schema.
pub type SignedVext = Signed<BridgePoolRootVext>;

impl Vext {
    /// Creates a new signed [`Vext`].
    #[inline]
    pub fn sign(&self, sk: &common::SecretKey) -> SignedVext {
        SignedVext::new(sk, self.clone())
    }
}
