//! Transaction events.

use std::fmt::Display;
use std::str::FromStr;

use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::hash::Hash;
use namada_core::ibc::IbcTxDataHash;
use namada_core::masp::MaspTxId;
use namada_events::extend::{
    ComposeEvent, EventAttributeEntry, Height, Log, TxHash,
};
use namada_events::{Event, EventLevel, EventToEmit, EventType};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::Tx;
use crate::data::{ResultCode, TxResult};
use crate::{IndexedTx, TxType};

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

pub mod masp_types {
    //! MASP event types

    use namada_events::EventType;

    use super::MaspEvent;

    /// MASP fee payment event
    pub const FEE_PAYMENT: EventType =
        namada_events::event_type!(MaspEvent, "fee-payment");

    /// General MASP transfer event
    pub const TRANSFER: EventType =
        namada_events::event_type!(MaspEvent, "transfer");

    /// FMD flag ciphertexts event
    pub const FLAG_CIPHERTEXTS: EventType =
        namada_events::event_type!(MaspEvent, "flag");
}

/// The type of a MASP transaction
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
    PartialEq,
    Eq,
    Ord,
    Serialize,
    Deserialize,
    Hash,
)]
pub enum MaspTxKind {
    /// A MASP transaction used for fee payment
    FeePayment,
    /// A general MASP transfer
    #[default]
    Transfer,
}

impl From<MaspTxKind> for EventType {
    fn from(kind: MaspTxKind) -> Self {
        match kind {
            MaspTxKind::FeePayment => masp_types::FEE_PAYMENT,
            MaspTxKind::Transfer => masp_types::TRANSFER,
        }
    }
}

/// Represents a reference to an FMD flag ciphertext.
///
/// Store either in an IBC packet memo, or a Namada tx section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FmdSectionRef {
    /// Reference to a flag ciphertext tx section.
    FmdSection(Hash),
    /// Reference to an IBC tx data section.
    IbcData(IbcTxDataHash),
}

impl Display for FmdSectionRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for FmdSectionRef {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

/// A type representing the possible reference to some MASP data, either a masp
/// section or ibc tx data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaspTxRef {
    /// Reference to a MASP section
    MaspSection(MaspTxId),
    /// Reference to an ibc tx data section
    IbcData(IbcTxDataHash),
}

impl Display for MaspTxRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for MaspTxRef {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

/// MASP transaction event
#[derive(Debug, Clone)]
pub enum MaspEvent {
    /// Emit emitted upon generating a new shielded output
    ShieldedOutput {
        /// The indexed transaction that generated this event
        tx_index: IndexedTx,
        /// A flag signaling the type of the MASP transaction
        kind: MaspTxKind,
        /// The reference to the masp data
        data: MaspTxRef,
    },
    /// Emit emitted after flagging a new shielded output
    ///
    /// Generally follows the creation of [`Self::ShieldedOutput`]
    FlagCiphertexts {
        /// The indexed transaction that generated this event
        tx_index: IndexedTx,
        /// The tx section hash of the FMD flag ciphertext
        section: FmdSectionRef,
    },
}

/// MASP transaction event
#[derive(Debug, Clone)]
pub struct MaspTxEvent {
    /// The indexed transaction that generated this event
    pub tx_index: IndexedTx,
    /// A flag signaling the type of the MASP transaction
    pub kind: MaspTxKind,
    /// The reference to the masp data
    pub data: MaspTxRef,
}

impl From<MaspTxEvent> for MaspEvent {
    fn from(
        MaspTxEvent {
            tx_index,
            kind,
            data,
        }: MaspTxEvent,
    ) -> Self {
        Self::ShieldedOutput {
            tx_index,
            kind,
            data,
        }
    }
}

impl EventToEmit for MaspEvent {
    const DOMAIN: &'static str = "masp";
}

impl From<MaspEvent> for Event {
    fn from(masp_event: MaspEvent) -> Self {
        match masp_event {
            MaspEvent::ShieldedOutput {
                tx_index,
                kind,
                data,
            } => Self::new(kind.into(), EventLevel::Tx)
                .with(data)
                .with(tx_index)
                .into(),
            MaspEvent::FlagCiphertexts { tx_index, section } => {
                Self::new(masp_types::FLAG_CIPHERTEXTS, EventLevel::Tx)
                    .with(section)
                    .with(tx_index)
                    .into()
            }
        }
    }
}

impl EventAttributeEntry<'static> for MaspTxRef {
    type Value = MaspTxRef;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "section";

    fn into_value(self) -> Self::Value {
        self
    }
}

impl EventAttributeEntry<'static> for IndexedTx {
    type Value = IndexedTx;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "indexed-tx";

    fn into_value(self) -> Self::Value {
        self
    }
}

impl EventAttributeEntry<'static> for FmdSectionRef {
    type Value = Self;
    type ValueOwned = Self;

    const KEY: &'static str = "ciphertext";

    fn into_value(self) -> Self::Value {
        self
    }
}
