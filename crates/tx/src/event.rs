//! Transaction events.

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_events::extend::{
    ComposeEvent, EventAttributeEntry, Height, Log, TxHash,
};
use namada_events::{Event, EventLevel, EventToEmit};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;

use super::Tx;
use crate::data::{ResultCode, TxResult};
use crate::TxType;

/// Transaction event.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct TxEvent(pub Event);

impl From<TxEvent> for Event {
    #[inline]
    fn from(TxEvent(event): TxEvent) -> Self {
        event
    }
}

impl EventToEmit for TxEvent {
    const DOMAIN: &'static str = "tx";
}

pub mod types {
    //! Transaction event types.

    use namada_events::EventType;

    use super::TxEvent;

    /// Applied transaction.
    pub const APPLIED: EventType =
        namada_events::event_type!(TxEvent, "applied");
}

/// Creates a new event with the hash and height of the transaction
/// already filled in.
pub fn new_tx_event(tx: &Tx, height: u64) -> Event {
    let base_event = match tx.header().tx_type {
        TxType::Wrapper(_) | TxType::Protocol(_) => {
            Event::new(types::APPLIED, EventLevel::Tx)
                .with(TxHash(tx.header_hash()))
        }
        _ => unreachable!(),
    };
    base_event
        .with(Height(height.into()))
        .with(Log(String::new()))
        .into()
}

/// Extend an [`Event`] with result code data.
pub struct Code(pub ResultCode);

impl EventAttributeEntry<'static> for Code {
    type Value = ResultCode;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "code";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with batch data.
pub struct Batch<'result>(pub &'result TxResult<String>);

impl<'result> EventAttributeEntry<'result> for Batch<'result> {
    type Value = &'result TxResult<String>;
    type ValueOwned = TxResult<String>;

    const KEY: &'static str = "batch";

    fn into_value(self) -> Self::Value {
        self.0
    }
}
