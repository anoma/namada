//! Vote extension types for adding a signature
//! of the bridge pool merkle root to be added
//! to storage. This will be used to generate
//! bridge pool inclusion proofs for Ethereum.
use std::ops::{Deref, DerefMut};

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::chain::BlockHeight;
use namada_core::collections::HashSet;
use namada_core::key::common;
use namada_core::key::common::Signature;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use namada_tx::Signed;

/// A vote extension containing a validator's signature
/// of the current root and nonce of the
/// Ethereum bridge pool.
#[derive(
    Debug,
    Clone,
    PartialEq,
    PartialOrd,
    Ord,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct BridgePoolRootVext {
    /// The address of the validator who submitted the vote extension.
    // NOTE: The validator's established address was included as a workaround
    // for `namada#200`, which prevented us from mapping a CometBFT validator
    // address to a Namada address. Since then, we have committed to keeping
    // this `validator_addr` field.
    pub validator_addr: Address,
    /// The block height at which the vote extensions was
    /// sent.
    ///
    /// This can be used as replay protection as well
    /// as allowing validators to  query the epoch with
    /// the appropriate validator set to verify signatures
    pub block_height: BlockHeight,
    /// The actual signature being submitted.
    /// This is a signature over `keccak(eth_header || keccak(root || nonce))`.
    pub sig: Signature,
}

/// Alias for [`BridgePoolRootVext`].
pub type Vext = BridgePoolRootVext;

/// A signed [`BridgePoolRootVext`].
///
/// Note that this is serialized with Ethereum's
/// ABI encoding schema.
#[derive(
    Clone,
    Debug,
    BorshSerialize,
    BorshSchema,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
pub struct SignedVext(pub Signed<BridgePoolRootVext>);

impl Deref for SignedVext {
    type Target = Signed<BridgePoolRootVext>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Signed<BridgePoolRootVext>> for SignedVext {
    fn from(value: Signed<BridgePoolRootVext>) -> Self {
        Self(value)
    }
}

impl Vext {
    /// Creates a new signed [`Vext`].
    #[inline]
    pub fn sign(&self, sk: &common::SecretKey) -> SignedVext {
        SignedVext(Signed::new(sk, self.clone()))
    }
}

/// A collection of validator signatures over the
/// Ethereum bridge pool Merkle root and nonce.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct MultiSignedVext(pub HashSet<SignedVext>);

impl Deref for MultiSignedVext {
    type Target = HashSet<SignedVext>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MultiSignedVext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for MultiSignedVext {
    type IntoIter = namada_core::collections::hash_set::IntoIter<SignedVext>;
    type Item = SignedVext;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<SignedVext> for MultiSignedVext {
    fn from(vext: SignedVext) -> Self {
        Self(HashSet::from([vext]))
    }
}
