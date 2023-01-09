//! Proofs over some arbitrarily signed data.

use std::collections::BTreeMap;

use crate::core::ledger::storage::{self, Storage};
use crate::proto::{SerializeWithBorsh, SignedSerialize};
use crate::types::address::Address;
use crate::types::key::common;
use crate::types::storage::BlockHeight;

/// Some [`Proof`] was constructed with signatures derived from
/// Ethereum secp keys.
pub enum ForEthereum {}

/// Some [`Proof`] was constructed with signatures derived from
/// Namada validator keys.
pub enum ForNamada {}

/// Proofs contain the signatures of validators reflecting
/// more than 2/3 of the staked NAM over some data to be signed.
pub struct Proof<F, T> {
    /// The signatures contained in the proof.
    pub signatures: HashMap<(Address, BlockHeight), Signature>,
    /// The data to be signed.
    pub data: T,
    /// The type of the underlying nodes whose keys were
    /// used to sign `data`.
    ///
    /// A [`Proof`] will either be constructed with
    /// signatures derived from Ethereum or Namada
    /// hot keys.
    _for_whom: PhantomData<*const F>,
}

impl<T, S: SignedSerialize> Proof<T, ForEthereum, S> {
    /// Verify a [`Proof`] constructed with Ethereum hot keys.
    pub fn eth_verify(&self, storage: &Storage<D, H>) -> bool
    where
        D: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: storage::StorageHasher,
    {
    }
}
