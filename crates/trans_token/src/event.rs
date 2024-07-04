//! Token transaction events.

use std::borrow::Cow;
use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::uint::Uint;
use namada_events::extend::{
    ComposeEvent, EventAttributeEntry, EventValue, UserAccount,
};
use namada_events::{Event, EventLevel, EventToEmit, EventType};

pub mod types {
    //! Token event types.

    use namada_events::{event_type, EventType};

    use super::TokenEvent;

    /// Mint token event.
    pub const MINT: EventType = event_type!(TokenEvent, "mint");

    /// Burn token event.
    pub const BURN: EventType = event_type!(TokenEvent, "burn");

    /// Transfer token event.
    pub const TRANSFER: EventType = event_type!(TokenEvent, "transfer");
}

/// Token event kind.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TokenEventKind {
    /// Token mint operation.
    Mint,
    /// Token burn operation.
    Burn,
    /// Token transfer operation.
    Transfer,
}

impl From<&TokenEventKind> for EventType {
    fn from(token_event_kind: &TokenEventKind) -> Self {
        match token_event_kind {
            TokenEventKind::Mint => types::MINT,
            TokenEventKind::Burn => types::BURN,
            TokenEventKind::Transfer => types::TRANSFER,
        }
    }
}

impl From<TokenEventKind> for EventType {
    fn from(token_event_kind: TokenEventKind) -> Self {
        (&token_event_kind).into()
    }
}

/// Namada token event.
#[derive(Debug)]
pub struct TokenEvent {
    /// The event level.
    pub level: EventLevel,
    /// The operation that took place.
    pub operation: TokenOperation,
    /// Additional description of the token event.
    pub descriptor: Cow<'static, str>,
}

/// Namada token operation.
#[derive(Debug)]
pub enum TokenOperation {
    /// Token mint event.
    Mint {
        /// The target account whose balance was changed.
        target_account: UserAccount,
        /// The affected token address.
        token: Address,
        /// The amount of minted tokens.
        amount: Uint,
        /// The balance that `target_account` ended up with.
        post_balance: Uint,
    },
    /// Token burn event.
    Burn {
        /// The target account whose balance was changed.
        target_account: UserAccount,
        /// The affected token address.
        token: Address,
        /// The amount of minted tokens.
        amount: Uint,
        /// The balance that `target_account` ended up with.
        post_balance: Uint,
    },
    /// Token transfer event.
    Transfer {
        /// The source of the token transfer.
        sources: BTreeMap<(UserAccount, Address), Uint>,
        /// The target of the token transfer.
        targets: BTreeMap<(UserAccount, Address), Uint>,
        /// The balance that `sources` and `targets` ended up with.
        post_balances: BTreeMap<(UserAccount, Address), Uint>,
    },
}

impl TokenOperation {
    /// The token event kind associated with this operation.
    pub fn kind(&self) -> TokenEventKind {
        match self {
            Self::Mint { .. } => TokenEventKind::Mint,
            Self::Burn { .. } => TokenEventKind::Burn,
            Self::Transfer { .. } => TokenEventKind::Transfer,
        }
    }

    /// Construct a simple transfer operation
    pub fn transfer(
        source: UserAccount,
        target: UserAccount,
        token: Address,
        amount: Uint,
        source_post_balance: Uint,
        target_post_balance: Option<Uint>,
    ) -> Self {
        let mut sources = BTreeMap::new();
        sources.insert((source.clone(), token.clone()), amount);
        let mut targets = BTreeMap::new();
        targets.insert((target.clone(), token.clone()), amount);
        let mut post_balances = BTreeMap::new();
        post_balances.insert((source, token.clone()), source_post_balance);
        if let Some(target_post_balance) = target_post_balance {
            post_balances.insert((target, token), target_post_balance);
        }
        Self::Transfer {
            sources,
            targets,
            post_balances,
        }
    }
}

impl EventToEmit for TokenEvent {
    const DOMAIN: &'static str = "token";
}

impl From<TokenEvent> for Event {
    fn from(token_event: TokenEvent) -> Self {
        let event =
            Self::new(token_event.operation.kind().into(), token_event.level)
                .with(Descriptor(&token_event.descriptor));

        match token_event.operation {
            TokenOperation::Mint {
                target_account,
                token,
                amount,
                post_balance,
            }
            | TokenOperation::Burn {
                target_account,
                token,
                amount,
                post_balance,
            } => event
                .with(TargetAccount(target_account))
                .with(TokenAddress(token))
                .with(Amount(&amount))
                .with(TargetPostBalance(&post_balance))
                .into(),
            TokenOperation::Transfer {
                sources,
                targets,
                post_balances,
            } => event
                .with(SourceAccounts(
                    sources.into_iter().collect::<Vec<_>>().into(),
                ))
                .with(TargetAccounts(
                    targets.into_iter().collect::<Vec<_>>().into(),
                ))
                .with(PostBalances(
                    post_balances.into_iter().collect::<Vec<_>>().into(),
                ))
                .into(),
        }
    }
}

/// Extend an [`Event`] with token event descriptor data.
pub struct Descriptor<'k>(pub &'k str);

impl<'k> EventAttributeEntry<'k> for Descriptor<'k> {
    type Value = &'k str;
    type ValueOwned = String;

    const KEY: &'static str = "token-event-descriptor";

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

/// Extend an [`Event`] with source account data.
pub struct SourceAccount(pub UserAccount);

impl EventAttributeEntry<'static> for SourceAccount {
    type Value = UserAccount;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "source-account";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with source account data.
pub struct SourceAccounts(pub EventValue<Vec<((UserAccount, Address), Uint)>>);

impl EventAttributeEntry<'static> for SourceAccounts {
    type Value = EventValue<Vec<((UserAccount, Address), Uint)>>;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "source-accounts";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with target account data.
pub struct TargetAccount(pub UserAccount);

impl EventAttributeEntry<'static> for TargetAccount {
    type Value = UserAccount;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "target-account";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with target account data.
pub struct TargetAccounts(pub EventValue<Vec<((UserAccount, Address), Uint)>>);

impl EventAttributeEntry<'static> for TargetAccounts {
    type Value = EventValue<Vec<((UserAccount, Address), Uint)>>;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "target-accounts";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with amount data.
pub struct Amount<'amt>(pub &'amt Uint);

impl<'amt> EventAttributeEntry<'amt> for Amount<'amt> {
    type Value = &'amt Uint;
    type ValueOwned = Uint;

    const KEY: &'static str = "amount";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with source post balance data.
pub struct PostBalances(pub EventValue<Vec<((UserAccount, Address), Uint)>>);

impl EventAttributeEntry<'static> for PostBalances {
    type Value = EventValue<Vec<((UserAccount, Address), Uint)>>;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "post-balances";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with source post balance data.
pub struct SourcePostBalance<'bal>(pub &'bal Uint);

impl<'bal> EventAttributeEntry<'bal> for SourcePostBalance<'bal> {
    type Value = &'bal Uint;
    type ValueOwned = Uint;

    const KEY: &'static str = "source-post-balance";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with target post balance data.
pub struct TargetPostBalance<'bal>(pub &'bal Uint);

impl<'bal> EventAttributeEntry<'bal> for TargetPostBalance<'bal> {
    type Value = &'bal Uint;
    type ValueOwned = Uint;

    const KEY: &'static str = "target-post-balance";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_account_str_roundtrip() {
        let targets = [
            UserAccount::External(
                "cosmos1hkgjfuznl4af5ayzn6gzl6kwwkcu28urxmqejg".to_owned(),
            ),
            UserAccount::Internal(
                Address::decode(
                    "tnam1q82t25z5f9gmnv5sztyr8ht9tqhrw4u875qjhy56",
                )
                .unwrap(),
            ),
        ];

        for target in targets {
            let as_str = target.to_string();
            let decoded: UserAccount = as_str.parse().unwrap();

            assert_eq!(decoded, target);
        }
    }
}
