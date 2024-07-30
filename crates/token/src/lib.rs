//! Namada transparent and shielded token types, storage keys and storage
//! fns.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_macros::BorshDeserializer;
pub use namada_shielded_token::*;
pub use namada_trans_token::*;

/// Validity predicates
pub mod vp {
    pub use namada_shielded_token::vp::{
        Error as MaspError, MaspVp, Result as MaspResult,
    };
    pub use namada_trans_token::vp::{
        Error as MultitokenError, MultitokenVp, Result as MultitokenResult,
    };
}
use serde::{Deserialize, Serialize};

/// Token storage keys
pub mod storage_key {
    pub use namada_shielded_token::storage_key::*;
    pub use namada_trans_token::storage_key::*;
}

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::masp::TxId;
use namada_events::EmitEvents;
use namada_storage::{Result, StorageRead, StorageWrite};

/// Initialize parameters for the token in storage during the genesis block.
pub fn write_params<S>(
    params: &Option<ShieldedParams>,
    storage: &mut S,
    address: &Address,
    denom: &Denomination,
) -> Result<()>
where
    S: StorageRead + StorageWrite,
{
    namada_trans_token::write_params(storage, address)?;
    if let Some(params) = params {
        namada_shielded_token::write_params(params, storage, address, denom)?;
    }
    Ok(())
}

/// Apply token logic for finalizing block (i.e. shielded token rewards)
pub fn finalize_block<S>(
    storage: &mut S,
    _events: &mut impl EmitEvents,
    is_new_masp_epoch: bool,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
{
    if is_new_masp_epoch {
        conversion::update_allowed_conversions(storage)?;
    }
    Ok(())
}

/// Accounts can send or receive funds in a transparent token transfer
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Hash,
    Eq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Account {
    /// Owner of the account
    pub owner: Address,
    /// Token handled by the account
    pub token: Address,
}

/// Arguments for a multi-party token transfer
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Default,
    Hash,
    Eq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Transfer {
    /// Sources of this transfer
    pub sources: BTreeMap<Account, DenominatedAmount>,
    /// Targets of this transfer
    pub targets: BTreeMap<Account, DenominatedAmount>,
    /// Hash of tx section that contains the MASP transaction
    pub shielded_section_hash: Option<TxId>,
}

impl Transfer {
    /// Create a MASP transaction
    pub fn masp(hash: TxId) -> Self {
        Self {
            shielded_section_hash: Some(hash),
            ..Self::default()
        }
    }

    /// Set the key to the given amount
    fn set<K: Ord>(
        map: &mut BTreeMap<K, DenominatedAmount>,
        key: K,
        val: DenominatedAmount,
    ) {
        if val.is_zero() {
            // Zero entries do not need to be present
            map.remove(&key);
        } else {
            map.insert(key, val);
        }
    }

    /// Debit the given account
    pub fn debit(
        mut self,
        owner: Address,
        token: Address,
        amount: DenominatedAmount,
    ) -> Option<Self> {
        let account = Account { owner, token };
        let zero = DenominatedAmount::new(Amount::zero(), amount.denom());
        let source_amount = *self.sources.get(&account).unwrap_or(&zero);
        let target_amount = *self.targets.get(&account).unwrap_or(&zero);
        // If this account is already a target, then reduce the target
        if amount < target_amount {
            // Account still gets net increase
            Self::set(
                &mut self.targets,
                account,
                target_amount.checked_sub(amount)?,
            );
        } else {
            // Account now actually gets a net decrease
            self.targets.remove(&account);
            let new_amt = source_amount
                .checked_add(amount.checked_sub(target_amount)?)?;
            Self::set(&mut self.sources, account, new_amt);
        }
        Some(self)
    }

    /// Credit the given account
    pub fn credit(
        mut self,
        owner: Address,
        token: Address,
        amount: DenominatedAmount,
    ) -> Option<Self> {
        let account = Account { owner, token };
        let zero = DenominatedAmount::new(Amount::zero(), amount.denom());
        let source_amount = *self.sources.get(&account).unwrap_or(&zero);
        let target_amount = *self.targets.get(&account).unwrap_or(&zero);
        // If this account is already a source, then reduce the source
        if amount < source_amount {
            // Account still gets net decrease
            Self::set(
                &mut self.sources,
                account,
                source_amount.checked_sub(amount)?,
            );
        } else {
            // Account now actually gets a net increase
            self.sources.remove(&account);
            let new_amt = target_amount
                .checked_add(amount.checked_sub(source_amount)?)?;
            Self::set(&mut self.targets, account, new_amt);
        }
        Some(self)
    }

    /// Transfer assets between accounts
    pub fn transfer(
        self,
        source: Address,
        target: Address,
        token: Address,
        amount: DenominatedAmount,
    ) -> Option<Self> {
        self.debit(source, token.clone(), amount)?
            .credit(target, token, amount)
    }
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and strategies for tokens
pub mod testing {
    use namada_core::address::testing::{
        arb_established_address, arb_non_internal_address,
    };
    use namada_core::address::Address;
    pub use namada_core::token::*;
    pub use namada_trans_token::testing::*;
    use proptest::prelude::*;
    use proptest::sample::SizeRange;

    use super::Transfer;

    prop_compose! {
        /// Generate a transparent transfer
        fn arb_single_transparent_transfer()(
            source in arb_non_internal_address(),
            target in arb_non_internal_address(),
            token in arb_established_address().prop_map(Address::Established),
            amount in arb_denominated_amount(),
        ) -> (Address, Address, Address, DenominatedAmount) {
            (
                source,
                target,
                token,
                amount,
            )
        }
    }

    /// Generate a vectorized transparent transfer
    pub fn arb_transparent_transfer(
        number_of_txs: impl Into<SizeRange>,
    ) -> impl Strategy<Value = Transfer> {
        proptest::collection::vec(
            arb_single_transparent_transfer(),
            number_of_txs,
        )
        .prop_filter_map("Transfers must not overflow", |data| {
            data.into_iter().try_fold(
                Transfer::default(),
                |acc, (source, target, token, amount)| {
                    acc.transfer(source, target, token, amount)
                },
            )
        })
    }
}
