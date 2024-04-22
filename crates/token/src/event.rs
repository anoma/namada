//! Token transaction events.

use std::borrow::Cow;

use namada_core::address::Address;
use namada_core::uint::{Uint, I256};
use namada_events::extend::EventAttributeEntry;
use namada_events::{Event, EventLevel, EventToEmit};

pub mod types {
    //! Token event types.

    use namada_events::{event_type, EventType};

    use super::TokenEvent;

    /// Balance change event.
    pub const BALANCE_CHANGE: EventType =
        event_type!(TokenEvent, "balance-change");
}

/// Namada token event.
pub enum TokenEvent {
    /// Balance change event.
    BalanceChange {
        /// Describes the reason of the balance change.
        descriptor: Cow<'static, str>,
        /// The address of the token whose balance was updated.
        token: Address,
        /// Account whose balance has changed.
        ///
        /// If the account is `None`, then the balance
        /// change refers to the minted supply of tokens.
        account: Option<Address>,
        /// The diff between the pre and post balance
        /// (`pre_balance` + `diff` = `post_balance`).
        diff: I256,
        /// The balance that `account` ended up with.
        post_balance: Uint,
    },
}

impl EventToEmit for TokenEvent {
    const DOMAIN: &'static str = "token";
}

impl From<TokenEvent> for Event {
    fn from(token_event: TokenEvent) -> Self {
        match token_event {
            TokenEvent::BalanceChange {
                descriptor,
                token,
                account,
                diff,
                post_balance,
            } => {
                let mut event =
                    Self::new(types::BALANCE_CHANGE, EventLevel::Tx);

                event
                    .extend(BalanceChangeKind(&descriptor))
                    .extend(TokenAddress(token))
                    .extend(BalanceDiff(&diff))
                    .extend(PostBalance(&post_balance));

                if let Some(account) = account {
                    event.extend(AccountAddress(account));
                }

                event
            }
        }
    }
}

/// Extend an [`Event`] with balance change kind data.
pub struct BalanceChangeKind<'k>(pub &'k str);

impl<'k> EventAttributeEntry<'k> for BalanceChangeKind<'k> {
    type Value = &'k str;
    type ValueOwned = String;

    const KEY: &'static str = "balance-change-kind";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with token address data.
pub struct TokenAddress(pub Address);

impl EventAttributeEntry<'static> for TokenAddress {
    type Value = Address;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "token-address";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with account address data.
pub struct AccountAddress(pub Address);

impl EventAttributeEntry<'static> for AccountAddress {
    type Value = Address;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "account-address";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with balance change diff data.
pub struct BalanceDiff<'bal>(pub &'bal I256);

impl<'bal> EventAttributeEntry<'bal> for BalanceDiff<'bal> {
    type Value = &'bal I256;
    type ValueOwned = I256;

    const KEY: &'static str = "diff";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with post balance data.
pub struct PostBalance<'bal>(pub &'bal Uint);

impl<'bal> EventAttributeEntry<'bal> for PostBalance<'bal> {
    type Value = &'bal Uint;
    type ValueOwned = Uint;

    const KEY: &'static str = "post-balance";

    fn into_value(self) -> Self::Value {
        self.0
    }
}
