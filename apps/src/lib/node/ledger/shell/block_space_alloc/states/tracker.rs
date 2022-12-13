//! Utilities to track the state of a [`BlockSpaceAllocator`].

use std::any::TypeId;
use std::marker::PhantomData;

use super::super::BlockSpaceAllocator;
use super::{
    BuildingDecryptedTxBatch, BuildingEncryptedTxBatch,
    BuildingProtocolTxBatch, FillingRemainingSpace, TryAlloc, WithEncryptedTxs,
    WithoutEncryptedTxs,
};

/// A tracker for the state of a decrypted txs allocator.
#[allow(dead_code)]
pub const DECRYPTED: Tracker<BuildingDecryptedTxBatch> = Tracker::new();

/// A tracker for the state of a protocol txs allocator.
#[allow(dead_code)]
pub const PROTOCOL: Tracker<BuildingProtocolTxBatch> = Tracker::new();

/// A tracker for the state of an allocator with encrypted txs.
///
/// Encrypted txs can be allocated in a block.
#[allow(dead_code)]
pub const WITH_ENCRYPTED: Tracker<BuildingEncryptedTxBatch<WithEncryptedTxs>> =
    Tracker::new();

/// A tracker for the state of an allocator without encrypted txs.
///
/// No encrypted txs will be allowed in a block.
#[allow(dead_code)]
pub const WITHOUT_ENCRYPTED: Tracker<
    BuildingEncryptedTxBatch<WithoutEncryptedTxs>,
> = Tracker::new();

/// A tracker for the state of a remaining txs allocator.
#[allow(dead_code)]
pub const REMAINING: Tracker<FillingRemainingSpace> = Tracker::new();

/// Utility to dynamically track the state of a [`BlockSpaceAllocator`].
#[derive(Debug, Copy, Clone, Hash)]
pub struct Tracker<S> {
    _marker: PhantomData<*const S>,
}

impl<S> Tracker<S>
where
    S: 'static,
    BlockSpaceAllocator<S>: TryAlloc,
{
    /// Return a new [`Tracker`] for a state `S`.
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<A, B> PartialEq<Tracker<B>> for Tracker<A>
where
    A: 'static,
    B: 'static,
    BlockSpaceAllocator<A>: TryAlloc,
    BlockSpaceAllocator<B>: TryAlloc,
{
    #[inline]
    fn eq(&self, _: &Tracker<B>) -> bool {
        TypeId::of::<A>() == TypeId::of::<B>()
    }
}

impl<S> Eq for Tracker<S>
where
    S: 'static,
    BlockSpaceAllocator<S>: TryAlloc,
{
}

/// Current state tracker for a [`BlockSpaceAllocator`].
pub trait CurrentState: TryAlloc {
    type State;

    /// Retrieve the current state of a [`BlockSpaceAllocator`].
    ///
    /// The returned [`Tracker`] can be compared against a
    /// [`Tracker`] for another state.
    fn current_state(&self) -> Tracker<Self::State>;
}

impl<S> CurrentState for BlockSpaceAllocator<S>
where
    S: 'static,
    BlockSpaceAllocator<S>: TryAlloc,
{
    type State = S;

    #[inline]
    fn current_state(&self) -> Tracker<S> {
        Tracker::new()
    }
}
