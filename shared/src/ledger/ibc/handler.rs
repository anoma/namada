//! Functions to handle IBC modules

use std::str::FromStr;

use borsh::BorshSerialize;
#[cfg(not(feature = "ABCI"))]
use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics02_client::client_consensus::{
    AnyConsensusState, ConsensusState,
};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics02_client::client_state::{AnyClientState, ClientState};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics02_client::client_type::ClientType;
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics02_client::events::{
    Attributes as ClientAttributes, CreateClient, UpdateClient, UpgradeClient,
};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics02_client::header::{AnyHeader, Header};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics02_client::height::Height;
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics03_connection::connection::{
    ConnectionEnd, Counterparty as ConnCounterparty, State as ConnState,
};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics03_connection::events::{
    Attributes as ConnectionAttributes, OpenAck as ConnOpenAck,
    OpenConfirm as ConnOpenConfirm, OpenInit as ConnOpenInit,
    OpenTry as ConnOpenTry,
};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChanCounterparty, State as ChanState,
};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics04_channel::events::{
    AcknowledgePacket, Attributes as ChannelAttributes,
    CloseConfirm as ChanCloseConfirm, CloseInit as ChanCloseInit,
    OpenAck as ChanOpenAck, OpenConfirm as ChanOpenConfirm,
    OpenInit as ChanOpenInit, OpenTry as ChanOpenTry, SendPacket,
    TimeoutOnClosePacket, TimeoutPacket, WriteAcknowledgement,
};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics04_channel::packet::{Packet, Sequence};
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics24_host::error::ValidationError as Ics24Error;
#[cfg(not(feature = "ABCI"))]
use ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortChannelId, PortId,
};
#[cfg(not(feature = "ABCI"))]
use ibc::events::IbcEvent;
#[cfg(not(feature = "ABCI"))]
use ibc::mock::client_state::{MockClientState, MockConsensusState};
#[cfg(feature = "ABCI")]
use ibc_abci::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics02_client::client_consensus::{
    AnyConsensusState, ConsensusState,
};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics02_client::client_state::{AnyClientState, ClientState};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics02_client::client_type::ClientType;
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics02_client::events::{
    Attributes as ClientAttributes, CreateClient, UpdateClient, UpgradeClient,
};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics02_client::header::{AnyHeader, Header};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics02_client::height::Height;
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics03_connection::connection::{
    ConnectionEnd, Counterparty as ConnCounterparty, State as ConnState,
};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics03_connection::events::{
    Attributes as ConnectionAttributes, OpenAck as ConnOpenAck,
    OpenConfirm as ConnOpenConfirm, OpenInit as ConnOpenInit,
    OpenTry as ConnOpenTry,
};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChanCounterparty, State as ChanState,
};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics04_channel::events::{
    AcknowledgePacket, Attributes as ChannelAttributes,
    CloseConfirm as ChanCloseConfirm, CloseInit as ChanCloseInit,
    OpenAck as ChanOpenAck, OpenConfirm as ChanOpenConfirm,
    OpenInit as ChanOpenInit, OpenTry as ChanOpenTry, SendPacket,
    TimeoutPacket, WriteAcknowledgement,
};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics04_channel::packet::{Packet, Sequence};
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics23_commitment::commitment::CommitmentPrefix;
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics24_host::error::ValidationError as Ics24Error;
#[cfg(feature = "ABCI")]
use ibc_abci::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortChannelId, PortId,
};
#[cfg(feature = "ABCI")]
use ibc_abci::events::IbcEvent;
#[cfg(feature = "ABCI")]
use ibc_abci::mock::client_state::{MockClientState, MockConsensusState};
use sha2::Digest;
use thiserror::Error;

use crate::types::address::{Address, InternalAddress};
use crate::types::ibc::data::*;
use crate::types::storage::KeySeg;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid port error: {0}")]
    PortId(Ics24Error),
    #[error("Updating a client error: {0}")]
    ClientUpdate(String),
}

/// for handling IBC modules
pub type Result<T> = std::result::Result<T, Error>;

/// Update a client with the given state and headers
pub fn update_client(
    client_state: AnyClientState,
    headers: Vec<AnyHeader>,
) -> Result<(AnyClientState, AnyConsensusState)> {
    if headers.is_empty() {
        return Err(Error::ClientUpdate("No header is given".to_owned()));
    }
    match client_state {
        AnyClientState::Tendermint(cs) => {
            let mut new_client_state = cs;
            for header in &headers {
                let h = match header {
                    AnyHeader::Tendermint(h) => h,
                    _ => {
                        return Err(Error::ClientUpdate(
                            "The header type is mismatched".to_owned(),
                        ));
                    }
                };
                new_client_state = new_client_state.with_header(h.clone());
            }
            let consensus_state = match headers.last().unwrap() {
                AnyHeader::Tendermint(h) => TmConsensusState::from(h.clone()),
                _ => {
                    return Err(Error::ClientUpdate(
                        "The header type is mismatched".to_owned(),
                    ));
                }
            };
            Ok((new_client_state.wrap_any(), consensus_state.wrap_any()))
        }
        AnyClientState::Mock(_) => match headers.last().unwrap() {
            AnyHeader::Mock(h) => Ok((
                MockClientState(*h).wrap_any(),
                MockConsensusState::new(*h).wrap_any(),
            )),
            _ => Err(Error::ClientUpdate(
                "The header type is mismatched".to_owned(),
            )),
        },
    }
}

/// Returns a new connection ID
pub fn connection_id(counter: u64) -> ConnectionId {
    ConnectionId::new(counter)
}

/// Open the connection
pub fn open_connection(conn: &mut ConnectionEnd) {
    conn.set_state(ConnState::Open);
}

/// Returns a new channel ID
pub fn channel_id(counter: u64) -> ChannelId {
    ChannelId::new(counter)
}

/// Open the channel
pub fn open_channel(channel: &mut ChannelEnd) {
    channel.set_state(ChanState::Open);
}

/// Close the channel
pub fn close_channel(channel: &mut ChannelEnd) {
    channel.set_state(ChanState::Closed);
}

/// Returns a port ID
pub fn port_id(id: &str) -> Result<PortId> {
    PortId::from_str(id).map_err(Error::PortId)
}

/// Returns a pair of port ID and channel ID
pub fn port_channel_id(
    port_id: PortId,
    channel_id: ChannelId,
) -> PortChannelId {
    PortChannelId {
        port_id,
        channel_id,
    }
}

/// Returns a sequence
pub fn sequence(index: u64) -> Sequence {
    Sequence::from(index)
}

/// Returns a commitment from the given packet
pub fn commitment(packet: &Packet) -> String {
    let input = format!(
        "{:?},{:?},{:?}",
        packet.timeout_timestamp, packet.timeout_height, packet.data,
    );
    let r = sha2::Sha256::digest(input.as_bytes());
    format!("{:x}", r)
}

/// Returns a counterparty of a connection
pub fn connection_counterparty(
    client_id: ClientId,
    conn_id: ConnectionId,
) -> ConnCounterparty {
    ConnCounterparty::new(client_id, Some(conn_id), commitment_prefix())
}

/// Returns a counterparty of a channel
pub fn channel_counterparty(
    port_id: PortId,
    channel_id: ChannelId,
) -> ChanCounterparty {
    ChanCounterparty::new(port_id, Some(channel_id))
}

fn commitment_prefix() -> CommitmentPrefix {
    let addr = Address::Internal(InternalAddress::Ibc);
    let bytes = addr
        .raw()
        .try_to_vec()
        .expect("Encoding an address string shouldn't fail");
    CommitmentPrefix::from(bytes)
}

/// Makes CreateClient event
pub fn make_create_client_event(
    client_id: &ClientId,
    data: &ClientCreationData,
) -> IbcEvent {
    let attributes = ClientAttributes {
        client_id: client_id.clone(),
        client_type: data.client_state.client_type(),
        consensus_height: data.client_state.latest_height(),
        ..Default::default()
    };
    IbcEvent::CreateClient(CreateClient::from(attributes))
}

/// Makes UpdateClient event
pub fn make_update_client_event(
    client_id: &ClientId,
    data: &ClientUpdateData,
) -> IbcEvent {
    let (client_type, consensus_height) = match data.headers.last() {
        Some(header) => (header.client_type(), header.height()),
        // set default values
        None => (ClientType::Tendermint, Height::default()),
    };
    let attributes = ClientAttributes {
        client_id: client_id.clone(),
        client_type,
        consensus_height,
        ..Default::default()
    };
    IbcEvent::UpdateClient(UpdateClient::from(attributes))
}

/// Makes UpgradeClient event
pub fn make_upgrade_client_event(
    client_id: &ClientId,
    data: &ClientUpgradeData,
) -> IbcEvent {
    let attributes = ClientAttributes {
        client_id: client_id.clone(),
        client_type: data.client_state.client_type(),
        consensus_height: data.client_state.latest_height(),
        ..Default::default()
    };
    IbcEvent::UpgradeClient(UpgradeClient::from(attributes))
}

/// Makes OpenInitConnection event
pub fn make_open_init_connection_event(
    conn_id: &ConnectionId,
    data: &ConnectionOpenInitData,
) -> IbcEvent {
    let attributes = ConnectionAttributes {
        connection_id: Some(conn_id.clone()),
        client_id: data.client_id.clone(),
        counterparty_connection_id: data.counterparty.connection_id().cloned(),
        counterparty_client_id: data.counterparty.client_id().clone(),
        ..Default::default()
    };
    IbcEvent::OpenInitConnection(ConnOpenInit::from(attributes))
}

/// Makes OpenTryConnection event
pub fn make_open_try_connection_event(
    conn_id: &ConnectionId,
    data: &ConnectionOpenTryData,
) -> IbcEvent {
    let attributes = ConnectionAttributes {
        connection_id: Some(conn_id.clone()),
        client_id: data.client_id.clone(),
        counterparty_connection_id: data.counterparty.connection_id().cloned(),
        counterparty_client_id: data.counterparty.client_id().clone(),
        ..Default::default()
    };
    IbcEvent::OpenTryConnection(ConnOpenTry::from(attributes))
}

/// Makes OpenAckConnection event
pub fn make_open_ack_connection_event(
    data: &ConnectionOpenAckData,
) -> IbcEvent {
    let attributes = ConnectionAttributes {
        connection_id: Some(data.conn_id.clone()),
        counterparty_connection_id: Some(data.counterpart_conn_id.clone()),
        ..Default::default()
    };
    IbcEvent::OpenAckConnection(ConnOpenAck::from(attributes))
}

/// Makes OpenConfirmConnection event
pub fn make_open_confirm_connection_event(
    data: &ConnectionOpenConfirmData,
) -> IbcEvent {
    let attributes = ConnectionAttributes {
        connection_id: Some(data.conn_id.clone()),
        ..Default::default()
    };
    IbcEvent::OpenConfirmConnection(ConnOpenConfirm::from(attributes))
}

/// Makes OpenInitChannel event
pub fn make_open_init_channel_event(
    channel_id: &ChannelId,
    data: &ChannelOpenInitData,
) -> IbcEvent {
    let connection_id = match data.connection_hops.get(0) {
        Some(c) => c.clone(),
        None => ConnectionId::default(),
    };
    let attributes = ChannelAttributes {
        port_id: data.port_id.clone(),
        channel_id: Some(channel_id.clone()),
        connection_id,
        counterparty_port_id: data.counterparty.port_id().clone(),
        counterparty_channel_id: data.counterparty.channel_id().cloned(),
        ..Default::default()
    };
    IbcEvent::OpenInitChannel(ChanOpenInit::from(attributes))
}

/// Makes OpenTryChannel event
pub fn make_open_try_channel_event(
    channel_id: &ChannelId,
    data: &ChannelOpenTryData,
) -> IbcEvent {
    let connection_id = match data.connection_hops.get(0) {
        Some(c) => c.clone(),
        None => ConnectionId::default(),
    };
    let attributes = ChannelAttributes {
        port_id: data.port_id.clone(),
        channel_id: Some(channel_id.clone()),
        connection_id,
        counterparty_port_id: data.counterparty.port_id().clone(),
        counterparty_channel_id: data.counterparty.channel_id().cloned(),
        ..Default::default()
    };
    IbcEvent::OpenTryChannel(ChanOpenTry::from(attributes))
}

/// Makes OpenAckChannel event
pub fn make_open_ack_channel_event(data: &ChannelOpenAckData) -> IbcEvent {
    let attributes = ChannelAttributes {
        port_id: data.port_id.clone(),
        channel_id: Some(data.channel_id.clone()),
        counterparty_channel_id: Some(data.counterpart_channel_id.clone()),
        ..Default::default()
    };
    IbcEvent::OpenAckChannel(ChanOpenAck::from(attributes))
}

/// Makes OpenConfirmChannel event
pub fn make_open_confirm_channel_event(
    data: &ChannelOpenConfirmData,
) -> IbcEvent {
    let attributes = ChannelAttributes {
        port_id: data.port_id.clone(),
        channel_id: Some(data.channel_id.clone()),
        ..Default::default()
    };
    IbcEvent::OpenConfirmChannel(ChanOpenConfirm::from(attributes))
}

/// Makes CloseInitChannel event
pub fn make_close_init_channel_event(data: &ChannelCloseInitData) -> IbcEvent {
    let attributes = ChannelAttributes {
        port_id: data.port_id.clone(),
        channel_id: Some(data.channel_id.clone()),
        ..Default::default()
    };
    IbcEvent::CloseInitChannel(ChanCloseInit::from(attributes))
}

/// Makes CloseConfirmChannel event
pub fn make_close_confirm_channel_event(
    data: &ChannelCloseConfirmData,
) -> IbcEvent {
    let attributes = ChannelAttributes {
        port_id: data.port_id.clone(),
        channel_id: Some(data.channel_id.clone()),
        ..Default::default()
    };
    IbcEvent::CloseConfirmChannel(ChanCloseConfirm::from(attributes))
}

/// Makes SendPacket event
pub fn make_send_packet_event(packet: Packet) -> IbcEvent {
    IbcEvent::SendPacket(SendPacket {
        height: packet.timeout_height,
        packet,
    })
}

/// Makes WriteAcknowledgement event
pub fn make_write_ack_event(packet: Packet, ack: Vec<u8>) -> IbcEvent {
    IbcEvent::WriteAcknowledgement(WriteAcknowledgement {
        // this height is not used
        height: Height::default(),
        packet,
        ack,
    })
}

/// Makes AcknowledgePacket event
pub fn make_ack_event(packet: Packet) -> IbcEvent {
    IbcEvent::AcknowledgePacket(AcknowledgePacket {
        // this height is not used
        height: Height::default(),
        packet,
    })
}

/// Makes TimeoutPacket event
pub fn make_timeout_event(packet: Packet) -> IbcEvent {
    IbcEvent::TimeoutPacket(TimeoutPacket {
        // this height is not used
        height: Height::default(),
        packet,
    })
}
