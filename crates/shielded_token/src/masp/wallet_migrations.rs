//! Tools for migrating shielded wallets .
//!
//! Since users store a serialized version of  [`ShieldedWallet`] locally,
//! changes to this type breaks backwards compatability if migrations are not
//! present.

use namada_core::borsh::{BorshDeserialize, BorshSerialize};

use crate::ShieldedWallet;
use crate::masp::ShieldedUtils;

/// An enum that adds version info to the [`ShieldedWallet`]
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum VersionedWallet<U: ShieldedUtils> {
    /// Version 0
    VO(ShieldedWallet<U>),
}

impl<U: ShieldedUtils> VersionedWallet<U> {
    /// Try to migrate this wallet to the latest version and return
    /// it if successful.
    pub fn migrate(self) -> eyre::Result<ShieldedWallet<U>> {
        match self {
            VersionedWallet::VO(w) => Ok(w),
        }
    }
}

/// A borrowed version of [`VersionedWallet`]
#[derive(BorshSerialize, Debug)]
pub enum VersionedWalletRef<'w, U: ShieldedUtils> {
    /// Version 0
    V0(&'w ShieldedWallet<U>),
}
