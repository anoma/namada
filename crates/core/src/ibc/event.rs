//! IBC event related types

use std::cmp::Ordering;
use std::str::FromStr;

use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::IbcShieldedTransfer;
use crate::address::{Address, MASP};
use crate::borsh::*;
use crate::collections::HashMap;
use crate::event::extend::{
    AttributesMap, EventAttributeEntry, ReadFromEventAttributes as _,
};
use crate::event::{Event, EventError, EventToEmit as _};
use crate::ibc::core::channel::types::packet::Packet;
use crate::ibc::core::channel::types::timeout::TimeoutHeight as IbcTimeoutHeight;
use crate::ibc::core::client::types::events::{
    CLIENT_ID_ATTRIBUTE_KEY, CONSENSUS_HEIGHTS_ATTRIBUTE_KEY,
};
use crate::ibc::core::client::types::{Height as IbcHeight, HeightError};
use crate::ibc::core::handler::types::events::IbcEvent as RawIbcEvent;
use crate::ibc::core::host::types::identifiers::{
    ChannelId as IbcChannelId, ClientId as IbcClientId,
    ConnectionId as IbcConnectionId, PortId, Sequence,
};
use crate::ibc::primitives::Timestamp;
use crate::masp::PaymentAddress;
use crate::tendermint::abci::Event as AbciEvent;

pub mod types {
    //! IBC event types.

    use super::IbcEvent;
    use crate::event::EventType;
    use crate::event_type;
    use crate::ibc::core::client::types::events::UPDATE_CLIENT_EVENT;

    /// Update client.
    pub const UPDATE_CLIENT: EventType =
        event_type!(IbcEvent, UPDATE_CLIENT_EVENT);
}

/// Wrapped IbcEvent
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
pub struct IbcEvent {
    /// The IBC event type
    pub event_type: String,
    /// The attributes of the IBC event
    pub attributes: HashMap<String, String>,
}

impl TryFrom<Event> for IbcEvent {
    type Error = EventError;

    fn try_from(namada_event: Event) -> std::result::Result<Self, Self::Error> {
        if namada_event.event_type.domain() != IbcEvent::DOMAIN {
            return Err(EventError::InvalidEventType);
        }

        let event_type = namada_event.event_type.sub_domain();

        if !matches!(
            event_type,
            // TODO: add other ibc event types that we use in namada
            "update_client" | "send_packet" | "write_acknowledgement"
        ) {
            return Err(EventError::InvalidEventType);
        }

        Ok(Self {
            event_type: event_type.to_owned(),
            attributes: namada_event.attributes,
        })
    }
}

impl std::cmp::PartialOrd for IbcEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for IbcEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // should not compare the same event type
        self.event_type.cmp(&other.event_type)
    }
}

impl std::fmt::Display for IbcEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let attributes = self
            .attributes
            .iter()
            .map(|(k, v)| format!("{}: {};", k, v))
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "Event type: {}, Attributes: {}",
            self.event_type, attributes
        )
    }
}

impl TryFrom<RawIbcEvent> for IbcEvent {
    type Error = super::Error;

    fn try_from(e: RawIbcEvent) -> Result<Self, super::Error> {
        let event_type = e.event_type().to_string();
        let abci_event =
            AbciEvent::try_from(e).map_err(super::Error::IbcEvent)?;
        let attributes: HashMap<_, _> = abci_event
            .attributes
            .iter()
            .map(|tag| (tag.key.to_string(), tag.value.to_string()))
            .collect();
        Ok(Self {
            event_type,
            attributes,
        })
    }
}

/// Extend an [`Event`] with packet sequence data.
pub struct PacketSequence(pub Sequence);

impl EventAttributeEntry<'static> for PacketSequence {
    type Value = Sequence;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "packet_sequence";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with packet source port data.
pub struct PacketSrcPort(pub PortId);

impl EventAttributeEntry<'static> for PacketSrcPort {
    type Value = PortId;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "packet_src_port";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with packet source channel data.
pub struct PacketSrcChannel(pub IbcChannelId);

impl EventAttributeEntry<'static> for PacketSrcChannel {
    type Value = IbcChannelId;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "packet_src_channel";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with packet destination port data.
pub struct PacketDstPort(pub PortId);

impl EventAttributeEntry<'static> for PacketDstPort {
    type Value = PortId;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "packet_dst_port";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with packet destination channel data.
pub struct PacketDstChannel(pub IbcChannelId);

impl EventAttributeEntry<'static> for PacketDstChannel {
    type Value = IbcChannelId;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "packet_dst_channel";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with client id data.
pub struct ClientId(pub IbcClientId);

impl EventAttributeEntry<'static> for ClientId {
    type Value = IbcClientId;
    type ValueOwned = Self::Value;

    const KEY: &'static str = CLIENT_ID_ATTRIBUTE_KEY;

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with consensus heights data.
pub struct ConsensusHeights(pub IbcHeight);

impl EventAttributeEntry<'static> for ConsensusHeights {
    type Value = IbcHeight;
    type ValueOwned = Self::Value;

    const KEY: &'static str = CONSENSUS_HEIGHTS_ATTRIBUTE_KEY;

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with connection id data.
pub struct ConnectionId(pub IbcConnectionId);

impl EventAttributeEntry<'static> for ConnectionId {
    type Value = IbcConnectionId;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "connection_id";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with packet data.
pub struct PacketData<'data>(pub &'data str);

impl<'data> EventAttributeEntry<'data> for PacketData<'data> {
    type Value = &'data str;
    type ValueOwned = String;

    const KEY: &'static str = "packet_data";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Represents an IBC timeout height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutHeight(pub IbcTimeoutHeight);

impl FromStr for TimeoutHeight {
    type Err = HeightError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::ibc::core::client::types::Height::from_str(s).map_or_else(
            |err| match err {
                HeightError::ZeroHeight => {
                    Ok(TimeoutHeight(IbcTimeoutHeight::Never))
                }
                err => Err(err),
            },
            |height| Ok(TimeoutHeight(IbcTimeoutHeight::At(height))),
        )
    }
}

impl std::fmt::Display for TimeoutHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            IbcTimeoutHeight::Never => write!(f, "0-0"),
            IbcTimeoutHeight::At(h) => write!(f, "{h}"),
        }
    }
}

/// Extend an [`Event`] with packet timeout height data.
pub struct PacketTimeoutHeight(pub TimeoutHeight);

impl EventAttributeEntry<'static> for PacketTimeoutHeight {
    type Value = TimeoutHeight;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "packet_timeout_height";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with packet timeout timestamp data.
pub struct PacketTimeoutTimestamp(pub Timestamp);

impl EventAttributeEntry<'static> for PacketTimeoutTimestamp {
    type Value = Timestamp;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "packet_timeout_timestamp";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with channel id data.
pub struct ChannelId(pub IbcChannelId);

impl EventAttributeEntry<'static> for ChannelId {
    type Value = IbcChannelId;
    type ValueOwned = Self::Value;

    const KEY: &'static str = "channel_id";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with packet ack data.
pub struct PacketAck<'ack>(pub &'ack str);

impl<'ack> EventAttributeEntry<'ack> for PacketAck<'ack> {
    type Value = &'ack str;
    type ValueOwned = String;

    const KEY: &'static str = "packet_ack";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with shielded receiver data.
pub struct ShieldedReceiver<'addr>(pub &'addr PaymentAddress);

impl<'addr> EventAttributeEntry<'addr> for ShieldedReceiver<'addr> {
    type Value = &'addr PaymentAddress;
    type ValueOwned = PaymentAddress;

    const KEY: &'static str = "receiver";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Receiving end of some IBC transaction.
pub enum IbcReceiver<S, T> {
    /// Shielded account receiver.
    Shielded(S),
    /// Transparent account receiver.
    Transparent(T),
}

/// Owned variant of an [`IbcReceiver`].
pub type OwnedIbcReceiver = IbcReceiver<PaymentAddress, Address>;

/// Borrowed variant of an [`IbcReceiver`].
pub type BorrowedIbcReceiver<'addr> =
    IbcReceiver<&'addr PaymentAddress, &'addr Address>;

impl FromStr for OwnedIbcReceiver {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::decode(s)
            .map(IbcReceiver::Transparent)
            .map_err(|_| ())
            .or_else(|_| {
                PaymentAddress::from_str(s)
                    .map(IbcReceiver::Shielded)
                    .map_err(|_| ())
            })
            .map_err(|()| {
                format!(
                    "IBC receiver address neither transparent nor shielded: \
                     {s:?}"
                )
            })
    }
}

impl OwnedIbcReceiver {
    /// Return a reference to the owned values.
    pub fn as_ref(&self) -> BorrowedIbcReceiver<'_> {
        match self {
            Self::Transparent(addr) => IbcReceiver::Transparent(addr),
            Self::Shielded(addr) => IbcReceiver::Shielded(addr),
        }
    }
}

impl BorrowedIbcReceiver<'_> {
    /// Return a transparent address from this [`IbcReceiver`].
    pub fn transparent_address(&self) -> &Address {
        match self {
            Self::Transparent(addr) => addr,
            Self::Shielded(_) => &MASP,
        }
    }
}

impl<'addr> std::fmt::Display for BorrowedIbcReceiver<'addr> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transparent(addr) => write!(f, "{addr}"),
            Self::Shielded(addr) => write!(f, "{addr}"),
        }
    }
}

impl std::fmt::Display for OwnedIbcReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transparent(addr) => write!(f, "{addr}"),
            Self::Shielded(addr) => write!(f, "{addr}"),
        }
    }
}

/// Extend an [`Event`] with receiver data.
pub struct Receiver<'addr>(pub BorrowedIbcReceiver<'addr>);

impl<'addr> EventAttributeEntry<'addr> for Receiver<'addr> {
    type Value = BorrowedIbcReceiver<'addr>;
    type ValueOwned = OwnedIbcReceiver;

    const KEY: &'static str = "receiver";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with shielded transfer data.
pub struct ShieldedTransfer<'tx>(pub &'tx IbcShieldedTransfer);

impl<'tx> EventAttributeEntry<'tx> for ShieldedTransfer<'tx> {
    type Value = &'tx IbcShieldedTransfer;
    type ValueOwned = IbcShieldedTransfer;

    const KEY: &'static str = "memo";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with trace hash data.
pub struct TraceHash<'hash>(pub &'hash str);

impl<'hash> EventAttributeEntry<'hash> for TraceHash<'hash> {
    type Value = &'hash str;
    type ValueOwned = String;

    const KEY: &'static str = "trace_hash";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Extend an [`Event`] with denomination data.
pub struct Denomination<'denom>(pub &'denom str);

impl<'denom> EventAttributeEntry<'denom> for Denomination<'denom> {
    type Value = &'denom str;
    type ValueOwned = String;

    const KEY: &'static str = "denom";

    fn into_value(self) -> Self::Value {
        self.0
    }
}

/// Attempt to parse an IBC [`Packet`] from a set of event attributes.
pub fn packet_from_event_attributes<A: AttributesMap>(
    attributes: &A,
) -> Result<Packet, EventError> {
    Ok(Packet {
        seq_on_a: PacketSequence::read_from_event_attributes(attributes)?,
        port_id_on_a: PacketSrcPort::read_from_event_attributes(attributes)?,
        chan_id_on_a: PacketSrcChannel::read_from_event_attributes(attributes)?,
        port_id_on_b: PacketDstPort::read_from_event_attributes(attributes)?,
        chan_id_on_b: PacketDstChannel::read_from_event_attributes(attributes)?,
        data: PacketData::read_from_event_attributes(attributes)?.into_bytes(),
        timeout_height_on_b: PacketTimeoutHeight::read_from_event_attributes(
            attributes,
        )?
        .0,
        timeout_timestamp_on_b:
            PacketTimeoutTimestamp::read_from_event_attributes(attributes)?,
    })
}
