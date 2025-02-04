//! IBC event related types

use std::cmp::Ordering;
use std::str::FromStr;

use ibc::core::channel::types::packet::Packet;
use ibc::core::channel::types::timeout::{
    TimeoutHeight as IbcTimeoutHeight, TimeoutTimestamp as IbcTimeoutTimestamp,
};
use ibc::core::client::types::events::{
    CLIENT_ID_ATTRIBUTE_KEY, CONSENSUS_HEIGHTS_ATTRIBUTE_KEY,
};
use ibc::core::client::types::Height as IbcHeight;
use ibc::core::handler::types::events::IbcEvent as RawIbcEvent;
use ibc::core::host::types::error::DecodingError;
use ibc::core::host::types::identifiers::{
    ChannelId as IbcChannelId, ClientId as IbcClientId,
    ConnectionId as IbcConnectionId, PortId, Sequence,
};
use ibc::primitives::{Timestamp, TimestampError};
use namada_core::borsh::*;
use namada_core::collections::HashMap;
use namada_core::tendermint::abci::Event as AbciEvent;
use namada_events::extend::{
    event_domain_of, AttributesMap, EventAttributeEntry,
    ReadFromEventAttributes as _,
};
use namada_events::{
    Event, EventError, EventLevel, EventToEmit, EventTypeBuilder,
};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

/// Describes a token event within IBC.
pub const TOKEN_EVENT_DESCRIPTOR: &str = IbcEvent::DOMAIN;

pub mod types {
    //! IBC event types.

    use ibc::core::client::types::events::UPDATE_CLIENT_EVENT;
    use namada_events::{event_type, EventType};

    use super::IbcEvent;

    /// Update client.
    pub const UPDATE_CLIENT: EventType =
        event_type!(IbcEvent, UPDATE_CLIENT_EVENT);
}

/// IBC event kind.
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[repr(transparent)]
pub struct IbcEventType(pub String);

impl EventToEmit for IbcEvent {
    const DOMAIN: &'static str = "ibc";
}

impl From<IbcEvent> for Event {
    fn from(ibc_event: IbcEvent) -> Self {
        let mut event = Self::new(
            EventTypeBuilder::new_of::<IbcEvent>()
                .with_segment(ibc_event.event_type.0)
                .build(),
            EventLevel::Tx,
        );
        #[allow(deprecated)]
        {
            *event.attributes_mut() =
                ibc_event.attributes.into_iter().collect();
        }
        event.extend(event_domain_of::<IbcEvent>());
        event
    }
}

impl std::fmt::Display for IbcEventType {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for IbcEventType {
    type Err = std::convert::Infallible;

    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IbcEventType(s.to_owned()))
    }
}

impl std::cmp::PartialEq<String> for IbcEventType {
    fn eq(&self, other: &String) -> bool {
        self.0.eq(other)
    }
}

impl std::cmp::PartialEq<str> for IbcEventType {
    fn eq(&self, other: &str) -> bool {
        self.0.eq(other)
    }
}

impl std::cmp::PartialEq<&str> for IbcEventType {
    fn eq(&self, other: &&str) -> bool {
        self.0.eq(other)
    }
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
    pub event_type: IbcEventType,
    /// The attributes of the IBC event
    pub attributes: HashMap<String, String>,
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
        let event_type = IbcEventType(e.event_type().to_string());
        let abci_event =
            AbciEvent::try_from(e).map_err(super::Error::IbcEvent)?;
        let attributes: HashMap<_, _> = abci_event
            .attributes
            .iter()
            .map(|tag| {
                (
                    tag.key_str()
                        .expect("Attribute key is malformed UFT-8")
                        .to_string(),
                    tag.value_str()
                        .expect("Attribute value is malformed UTF-8")
                        .to_string(),
                )
            })
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
    type Err = DecodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "0-0" {
            return Ok(TimeoutHeight(IbcTimeoutHeight::Never));
        }
        IbcHeight::from_str(s)
            .map(|height| TimeoutHeight(IbcTimeoutHeight::At(height)))
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

/// Represents an IBC timeout timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutTimestamp(pub IbcTimeoutTimestamp);

impl FromStr for TimeoutTimestamp {
    type Err = TimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let timestamp = Timestamp::from_str(s)?;
        if timestamp.nanoseconds() == 0 {
            Ok(TimeoutTimestamp(IbcTimeoutTimestamp::Never))
        } else {
            Ok(TimeoutTimestamp(IbcTimeoutTimestamp::At(timestamp)))
        }
    }
}

impl std::fmt::Display for TimeoutTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            IbcTimeoutTimestamp::Never => {
                write!(f, "{}", Timestamp::from_nanoseconds(0))
            }
            IbcTimeoutTimestamp::At(h) => write!(f, "{h}"),
        }
    }
}

/// Extend an [`Event`] with packet timeout timestamp data.
pub struct PacketTimeoutTimestamp(pub TimeoutTimestamp);

impl EventAttributeEntry<'static> for PacketTimeoutTimestamp {
    type Value = TimeoutTimestamp;
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
            PacketTimeoutTimestamp::read_from_event_attributes(attributes)?.0,
    })
}

#[cfg(test)]
mod tests {
    use namada_core::hash::Hash;
    use namada_core::tendermint_proto::abci::Event as AbciEventV037;
    use namada_events::extend::{
        ComposeEvent as _, Domain, Height, Log,
        RawReadFromEventAttributes as _, TxHash,
    };

    use super::*;

    #[test]
    fn test_ibc_domain_encoded_in_abci_event_attrs() {
        const EVENT_TYPE: &str = "update_account";

        let event: Event = IbcEvent {
            event_type: IbcEventType(EVENT_TYPE.into()),
            attributes: Default::default(),
        }
        .into();

        let event: AbciEventV037 = event.into();

        assert_eq!(event.r#type, EVENT_TYPE);
        assert_eq!(
            Some(IbcEvent::DOMAIN),
            Domain::<IbcEvent>::raw_read_opt_from_event_attributes(
                &event.attributes
            )
        );
    }

    #[test]
    fn test_domain_of_composed_ibc_event() {
        let composite_event = IbcEvent {
            event_type: IbcEventType("update_account".into()),
            attributes: Default::default(),
        }
        .with(Log("this is sparta!".to_string()))
        .with(Height(300.into()))
        .with(TxHash(Hash::default()));

        fn event_domain<E: EventToEmit>(_: &E) -> &'static str {
            E::DOMAIN
        }

        assert_eq!(event_domain(&composite_event), IbcEvent::DOMAIN);
    }
}
