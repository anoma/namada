//! Token transaction events.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use namada_core::address::Address;
use namada_core::uint::{Uint, I256};
use namada_events::extend::{Closure, ComposeEvent, EventAttributeEntry};
use namada_events::{Event, EventLevel, EventToEmit};

pub mod types {
    //! Token event types.

    use namada_events::{event_type, EventType};

    use super::TokenEvent;

    /// Balance change event.
    pub const BALANCE_CHANGE: EventType =
        event_type!(TokenEvent, "balance-change");
}

/// The target of a balance change.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum BalanceChangeTarget {
    /// The minted supply of tokens.
    MintedSupply,
    /// Internal chain address in Namada.
    Internal(Address),
    /// External chain address.
    External(String),
}

impl fmt::Display for BalanceChangeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MintedSupply => write!(f, "minted-supply"),
            Self::Internal(addr) => write!(f, "internal-address/{addr}"),
            Self::External(addr) => write!(f, "external-address/{addr}"),
        }
    }
}

impl FromStr for BalanceChangeTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            None if s == "minted-supply" => Ok(Self::MintedSupply),
            Some(("internal-address", addr)) => {
                Ok(Self::Internal(Address::decode(addr).map_err(|err| {
                    format!(
                        "Unknown internal address balance change target \
                         {s:?}: {err}"
                    )
                })?))
            }
            Some(("external-address", addr)) => {
                Ok(Self::External(addr.to_owned()))
            }
            _ => Err(format!("Unknown balance change target {s:?}")),
        }
    }
}

/// Namada token event.
#[derive(Debug)]
pub enum TokenEvent {
    /// Balance change event.
    BalanceChange {
        /// Describes the reason of the balance change.
        descriptor: Cow<'static, str>,
        /// The address of the token whose balance was updated.
        token: Address,
        /// The target whose balance was changed.
        target: BalanceChangeTarget,
        /// The diff between the pre and post balance
        /// (`pre_balance` + `diff` = `post_balance`).
        diff: I256,
        /// The balance that `account` ended up with,
        /// if it is known.
        post_balance: Option<Uint>,
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
                target,
                diff,
                post_balance,
            } => Self::new(types::BALANCE_CHANGE, EventLevel::Tx)
                .with(TargetAccount(target))
                .with(BalanceChangeKind(&descriptor))
                .with(TokenAddress(token))
                .with(BalanceDiff(&diff))
                .with(Closure(|event: &mut Event| {
                    if let Some(post_balance) = post_balance {
                        event.extend(PostBalance(&post_balance));
                    }
                }))
                .into(),
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

/// Extend an [`Event`] with target account data.
pub struct TargetAccount(pub BalanceChangeTarget);

impl EventAttributeEntry<'static> for TargetAccount {
    type Value = BalanceChangeTarget;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "target-account";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_change_target_str_roundtrip() {
        let targets = [
            BalanceChangeTarget::MintedSupply,
            BalanceChangeTarget::External(
                "cosmos1hkgjfuznl4af5ayzn6gzl6kwwkcu28urxmqejg".to_owned(),
            ),
            BalanceChangeTarget::Internal(
                Address::decode(
                    "tnam1q82t25z5f9gmnv5sztyr8ht9tqhrw4u875qjhy56",
                )
                .unwrap(),
            ),
        ];

        for target in targets {
            let as_str = target.to_string();
            let decoded: BalanceChangeTarget = as_str.parse().unwrap();

            assert_eq!(decoded, target);
        }
    }
}
