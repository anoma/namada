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

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_events::EmitEvents;
use namada_macros::BorshDeserializer;
pub use namada_shielded_token::*;
use namada_systems::parameters;
pub use namada_trans_token::*;

/// Validity predicates
pub mod vp {
    pub use namada_shielded_token::vp::MaspVp;
    // The error and result type are the same as in `namada_trans_token` -
    // a native VP
    pub use namada_shielded_token::{Error, Result};
    pub use namada_trans_token::vp::MultitokenVp;
}
use serde::{Deserialize, Serialize};

/// Token storage keys
pub mod storage_key {
    use namada_core::address::Address;
    use namada_core::storage;
    use namada_shielded_token::storage_key as shielded;
    pub use namada_shielded_token::storage_key::{
        is_masp_commitment_anchor_key, is_masp_key, is_masp_nullifier_key,
        is_masp_token_map_key, is_masp_transfer_key, masp_assets_hash_key,
        masp_commitment_anchor_key, masp_commitment_tree_key,
        masp_convert_anchor_key, masp_nullifier_key, masp_token_map_key,
        masp_total_rewards,
    };
    pub use namada_trans_token::storage_key::*;

    type TransToken = namada_trans_token::Store<()>;

    /// Obtain the nominal proportional key for the given token
    pub fn masp_kp_gain_key(token_addr: &Address) -> storage::Key {
        shielded::masp_kp_gain_key::<TransToken>(token_addr)
    }

    /// Obtain the nominal derivative key for the given token
    pub fn masp_kd_gain_key(token_addr: &Address) -> storage::Key {
        shielded::masp_kd_gain_key::<TransToken>(token_addr)
    }

    /// The max reward rate key for the given token
    pub fn masp_max_reward_rate_key(token_addr: &Address) -> storage::Key {
        shielded::masp_max_reward_rate_key::<TransToken>(token_addr)
    }

    /// Obtain the locked target amount key for the given token
    pub fn masp_locked_amount_target_key(token_addr: &Address) -> storage::Key {
        shielded::masp_locked_amount_target_key::<TransToken>(token_addr)
    }

    /// Obtain the storage key for the last locked amount of a token
    pub fn masp_last_locked_amount_key(token_addr: &Address) -> storage::Key {
        shielded::masp_last_locked_amount_key::<TransToken>(token_addr)
    }

    /// Obtain the storage key for the last inflation of a token
    pub fn masp_last_inflation_key(token_addr: &Address) -> storage::Key {
        shielded::masp_last_inflation_key::<TransToken>(token_addr)
    }
}

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
        namada_shielded_token::write_params::<S, namada_trans_token::Store<()>>(
            params, storage, address, denom,
        )?;
    }
    Ok(())
}

/// Apply token logic for finalizing block (i.e. shielded token rewards)
pub fn finalize_block<S, Params>(
    storage: &mut S,
    _events: &mut impl EmitEvents,
    is_new_masp_epoch: bool,
) -> Result<()>
where
    S: StorageWrite + StorageRead + WithConversionState,
    Params: parameters::Read<S>,
{
    if is_new_masp_epoch {
        conversion::update_allowed_conversions::<S, Params, Store<S>>(storage)?;
    }
    Ok(())
}

/// Accounts can send or receive funds in a transparent token transfer
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
    pub shielded_section_hash: Option<MaspTxId>,
}

impl Transfer {
    /// Create a MASP transaction
    pub fn masp(hash: MaspTxId) -> Self {
        Self {
            shielded_section_hash: Some(hash),
            ..Self::default()
        }
    }

    /// Set the key to the given amount
    fn set(
        map: &mut BTreeMap<Account, DenominatedAmount>,
        key: Account,
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

#[cfg(test)]
mod test_token_transfer_actions {
    use namada_core::address::testing::{established_address_1, nam};

    use super::*;

    #[test]
    fn test_set_to_zero() {
        let account = Account {
            owner: established_address_1(),
            token: nam(),
        };

        let mut transfer = Transfer::default();

        let zero = Amount::zero().native_denominated();
        Transfer::set(&mut transfer.sources, account.clone(), zero);
        assert_eq!(transfer, Transfer::default());

        let one = Amount::from(1).native_denominated();
        Transfer::set(&mut transfer.sources, account.clone(), one);
        assert_eq!(
            transfer,
            Transfer {
                sources: BTreeMap::from([(account, one)]),
                ..Transfer::default()
            }
        );
    }

    #[test]
    fn test_debit_credit() {
        // test debit
        test_debit_credit_aux(
            Transfer::debit,
            Transfer::credit,
            |sources| Transfer {
                sources,
                ..Transfer::default()
            },
            |targets| Transfer {
                targets,
                ..Transfer::default()
            },
        );

        // test credit
        test_debit_credit_aux(
            Transfer::credit,
            Transfer::debit,
            |targets| Transfer {
                targets,
                ..Transfer::default()
            },
            |sources| Transfer {
                sources,
                ..Transfer::default()
            },
        );
    }

    fn test_debit_credit_aux(
        op1: fn(
            Transfer,
            Address,
            Address,
            DenominatedAmount,
        ) -> Option<Transfer>,
        op2: fn(
            Transfer,
            Address,
            Address,
            DenominatedAmount,
        ) -> Option<Transfer>,
        transfer1: fn(BTreeMap<Account, DenominatedAmount>) -> Transfer,
        transfer2: fn(BTreeMap<Account, DenominatedAmount>) -> Transfer,
    ) {
        let account = Account {
            owner: established_address_1(),
            token: nam(),
        };

        let amount_100 = Amount::native_whole(100).native_denominated();
        let amount_90 = Amount::native_whole(90).native_denominated();
        let amount_80 = Amount::native_whole(80).native_denominated();
        let amount_10 = Amount::native_whole(10).native_denominated();

        let transfer = Transfer::default();

        let transfer = op1(
            transfer,
            account.owner.clone(),
            account.token.clone(),
            amount_10,
        )
        .unwrap();

        assert_eq!(
            transfer,
            transfer1(BTreeMap::from([(account.clone(), amount_10)])),
        );

        let transfer = op2(
            transfer,
            account.owner.clone(),
            account.token.clone(),
            amount_100,
        )
        .unwrap();

        assert_eq!(
            transfer,
            transfer2(BTreeMap::from([(account.clone(), amount_90)])),
        );

        let transfer = op1(
            transfer,
            account.owner.clone(),
            account.token.clone(),
            amount_10,
        )
        .unwrap();

        assert_eq!(
            transfer,
            transfer2(BTreeMap::from([(account.clone(), amount_80)])),
        );
    }
}
