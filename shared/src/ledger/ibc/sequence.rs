//! IBC validity predicate for sequences

use std::str::FromStr;

use borsh::BorshDeserialize;
use ibc::ics04_channel::channel::{Counterparty, Order};
use ibc::ics04_channel::context::ChannelReader;
use ibc::ics04_channel::handler::verify::{
    verify_packet_acknowledgement_proofs, verify_packet_recv_proofs,
};
use ibc::ics04_channel::packet::Packet;
use ibc::ics24_host::identifier::{ChannelId, PortId};
use ibc::proofs::Proofs;
use ibc::timestamp::Expiry;
use thiserror::Error;

use super::channel::Error as ChannelError;
use super::Ibc;
use crate::ledger::storage::{self, StorageHasher};
use crate::types::ibc::{
    self as types, Error as IbcDataError, PacketAckData, PacketReceiptData,
};
use crate::types::storage::{Key, KeySeg};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Key error: {0}")]
    KeyError(String),
    #[error("Client error: {0}")]
    ClientError(String),
    #[error("Channel error: {0}")]
    ChannelError(String),
    #[error("Port error: {0}")]
    PortError(String),
    #[error("Sequence error: {0}")]
    SequenceError(String),
    #[error("Proof verification error: {0}")]
    ProofVerificationError(String),
    #[error("Decoding TX data error: {0}")]
    DecodingTxDataError(std::io::Error),
    #[error("IBC data error: {0}")]
    IbcDataError(IbcDataError),
}

/// IBC packet functions result
pub type Result<T> = std::result::Result<T, Error>;

enum Phase {
    Send,
    Recv,
    Ack,
}

impl<'a, DB, H> Ibc<'a, DB, H>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    pub(super) fn validate_sequence_send(
        &self,
        key: &Key,
        tx_data: &[u8],
    ) -> Result<bool> {
        let port_channel_id = Self::get_port_channel_id(key)?;
        let packet = types::decode_packet(tx_data)?;
        let next_seq_pre = self.get_next_sequence_send_pre(&port_channel_id)?;
        let next_seq = match self.get_next_sequence_send(&port_channel_id) {
            Some(s) => s,
            None => {
                return Err(Error::SequenceError(
                    "The nextSequenceSend doesn't exit".to_owned(),
                ));
            }
        };
        if u64::from(next_seq_pre) + 1 != u64::from(next_seq)
            || packet.sequence != next_seq
        {
            return Ok(false);
        }

        self.validate_send_packet(&port_channel_id, &packet)
    }

    pub(super) fn validate_sequence_recv(
        &self,
        key: &Key,
        tx_data: &[u8],
    ) -> Result<bool> {
        let port_channel_id = Self::get_port_channel_id(key)?;
        let data = PacketReceiptData::try_from_slice(tx_data)?;
        let packet = data.packet()?;
        let next_seq_pre = self.get_next_sequence_recv_pre(&port_channel_id)?;
        let next_seq = match self.get_next_sequence_recv(&port_channel_id) {
            Some(s) => s,
            None => {
                return Err(Error::SequenceError(
                    "The nextSequenceRecv doesn't exist".to_owned(),
                ));
            }
        };
        if u64::from(next_seq_pre) + 1 != u64::from(next_seq) {
            return Ok(false);
        }
        // when the ordered channel, the sequence number should be equal to
        // nextSequenceRecv
        if self.is_ordered_channel(&port_channel_id)?
            && packet.sequence != next_seq
        {
            return Ok(false);
        }

        if !self.validate_recv_packet(&port_channel_id, &packet)? {
            return Ok(false);
        }

        self.verify_recv_proof(&port_channel_id, &packet, &data.proofs()?)
    }

    pub(super) fn validate_sequence_ack(
        &self,
        key: &Key,
        tx_data: &[u8],
    ) -> Result<bool> {
        let port_channel_id = Self::get_port_channel_id(key)?;
        let data = PacketAckData::try_from_slice(tx_data)?;
        let packet = data.packet()?;
        let next_seq_pre = self.get_next_sequence_ack_pre(&port_channel_id)?;
        let next_seq = match self.get_next_sequence_ack(&port_channel_id) {
            Some(s) => s,
            None => {
                return Err(Error::SequenceError(
                    "The nextSequenceAck doesn't exist".to_owned(),
                ));
            }
        };
        if u64::from(next_seq_pre) + 1 != u64::from(next_seq) {
            return Err(Error::SequenceError(
                "The sequence number is invalid".to_owned(),
            ));
        }
        // when the ordered channel, the sequence number should be equal to
        // nextSequenceAck
        if self.is_ordered_channel(&port_channel_id)?
            && packet.sequence != next_seq
        {
            return Ok(false);
        }

        if !self.validate_ack_packet(&port_channel_id, &packet)? {
            return Ok(false);
        }

        self.verify_ack_proof(
            &port_channel_id,
            &packet,
            data.ack(),
            &data.proofs()?,
        )
    }

    fn validate_send_packet(
        &self,
        port_channel_id: &(PortId, ChannelId),
        packet: &Packet,
    ) -> Result<bool> {
        if !self.validate_packet(&packet, Phase::Send)? {
            return Ok(false);
        }

        let key = (
            port_channel_id.0.clone(),
            port_channel_id.1.clone(),
            packet.sequence,
        );
        if self.get_packet_commitment(&key).is_none() {
            return Ok(false);
        }

        Ok(true)
    }

    fn validate_recv_packet(
        &self,
        port_channel_id: &(PortId, ChannelId),
        packet: &Packet,
    ) -> Result<bool> {
        if !self.validate_packet(&packet, Phase::Recv)? {
            return Ok(false);
        }

        let key = (
            port_channel_id.0.clone(),
            port_channel_id.1.clone(),
            packet.sequence,
        );
        if self.get_packet_receipt(&key).is_none() {
            return Ok(false);
        }
        if self.get_packet_acknowledgement(&key).is_none() {
            return Ok(false);
        }

        Ok(true)
    }

    fn validate_ack_packet(
        &self,
        port_channel_id: &(PortId, ChannelId),
        packet: &Packet,
    ) -> Result<bool> {
        if !self.validate_packet(&packet, Phase::Ack)? {
            return Ok(false);
        }

        let key = (
            port_channel_id.0.clone(),
            port_channel_id.1.clone(),
            packet.sequence,
        );
        let prev_commitment = self.get_packet_commitment_pre(&key)?;
        let input = format!(
            "{:?},{:?},{:?}",
            packet.timeout_timestamp, packet.timeout_height, packet.data,
        );
        if prev_commitment != self.hash(input) {
            return Ok(false);
        }
        if self.get_packet_commitment(&key).is_some() {
            // the commitment should be already deleted
            return Ok(false);
        }

        Ok(true)
    }

    fn verify_recv_proof(
        &self,
        port_channel_id: &(PortId, ChannelId),
        packet: &Packet,
        proofs: &Proofs,
    ) -> Result<bool> {
        let channel = match self.channel_end(&port_channel_id) {
            Some(c) => c,
            None => {
                return Err(Error::ChannelError(format!(
                    "The channel doesn't exist: Port {}, Channel {}",
                    port_channel_id.0, port_channel_id.1,
                )));
            }
        };
        let connection = self.connection_from_channel(&channel)?;
        let client_id = connection.client_id().clone();

        match verify_packet_recv_proofs(self, packet, client_id, proofs) {
            Ok(_) => Ok(true),
            Err(e) => Err(Error::ProofVerificationError(e.to_string())),
        }
    }

    fn verify_ack_proof(
        &self,
        port_channel_id: &(PortId, ChannelId),
        packet: &Packet,
        ack: Vec<u8>,
        proofs: &Proofs,
    ) -> Result<bool> {
        let channel = match self.channel_end(&port_channel_id) {
            Some(c) => c,
            None => {
                return Err(Error::ChannelError(format!(
                    "The channel doesn't exist: Port {}, Channel {}",
                    port_channel_id.0, port_channel_id.1,
                )));
            }
        };
        let connection = self.connection_from_channel(&channel)?;
        let client_id = connection.client_id().clone();

        match verify_packet_acknowledgement_proofs(
            self, packet, ack, client_id, proofs,
        ) {
            Ok(_) => Ok(true),
            Err(e) => Err(Error::ProofVerificationError(e.to_string())),
        }
    }

    fn get_port_channel_id(key: &Key) -> Result<(PortId, ChannelId)> {
        let port_id = match key.segments.get(3) {
            Some(id) => PortId::from_str(&id.raw())
                .map_err(|e| Error::KeyError(e.to_string()))?,
            None => {
                return Err(Error::KeyError(format!(
                    "The key doesn't have a port ID: {}",
                    key
                )));
            }
        };
        let channel_id = match key.segments.get(5) {
            Some(id) => ChannelId::from_str(&id.raw())
                .map_err(|e| Error::KeyError(e.to_string()))?,
            None => {
                return Err(Error::KeyError(format!(
                    "The key doesn't have a channel ID: {}",
                    key
                )));
            }
        };
        Ok((port_id, channel_id))
    }

    fn is_ordered_channel(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<bool> {
        let channel = match self.channel_end(&port_channel_id) {
            Some(c) => c,
            None => {
                return Err(Error::ChannelError(format!(
                    "The channel doesn't exist: Port {}, Channel {}",
                    port_channel_id.0, port_channel_id.1
                )));
            }
        };
        Ok(channel.order_matches(&Order::Ordered))
    }

    fn validate_packet(&self, packet: &Packet, phase: Phase) -> Result<bool> {
        let port_channel_id = match phase {
            Phase::Send | Phase::Ack => {
                (packet.source_port.clone(), packet.source_channel.clone())
            }
            Phase::Recv => (
                packet.destination_port.clone(),
                packet.destination_channel.clone(),
            ),
        };

        // port authentication
        self.authenticated_capability(&port_channel_id.0)
            .map_err(|e| {
                Error::PortError(format!(
                    "The port is not owned: Port {}, {}",
                    port_channel_id.0, e
                ))
            })?;

        let channel = match self.channel_end(&port_channel_id) {
            Some(c) => c,
            None => {
                return Err(Error::ChannelError(format!(
                    "The channel doesn't exist: Port {}, Channel {}",
                    port_channel_id.0, port_channel_id.1,
                )));
            }
        };
        if !channel.is_open() {
            return Ok(false);
        }

        let connection = self.connection_from_channel(&channel)?;
        if !connection.is_open() {
            return Ok(false);
        }

        // counterparty consistency
        let counterparty = match phase {
            Phase::Send | Phase::Ack => Counterparty::new(
                packet.destination_port.clone(),
                Some(packet.destination_channel.clone()),
            ),
            Phase::Recv => Counterparty::new(
                packet.source_port.clone(),
                Some(packet.source_channel.clone()),
            ),
        };
        if !channel.counterparty_matches(&counterparty) {
            return Ok(false);
        }

        // check timeout
        match phase {
            Phase::Send => {
                // check timeout height
                let client_id = connection.client_id();
                let height = match self.client_state(client_id) {
                    Some(s) => {
                        if packet.timeout_height <= s.latest_height() {
                            return Ok(false);
                        }
                        s.latest_height()
                    }
                    None => {
                        return Ok(false);
                    }
                };
                // check timeout timestamp
                match self.client_consensus_state(&client_id, height) {
                    Some(s) => {
                        if s.timestamp().check_expiry(&packet.timeout_timestamp)
                            != Expiry::NotExpired
                        {
                            return Ok(false);
                        }
                    }
                    None => {
                        return Err(Error::ClientError(format!(
                            "The consensus state doesn't exist: ID {}, Height \
                             {}",
                            client_id, height
                        )));
                    }
                }
            }
            Phase::Recv => {
                // check timeout height
                if packet.timeout_height <= self.host_height() {
                    return Ok(false);
                }
                // check timeout timestamp
                if self
                    .host_timestamp()
                    .check_expiry(&packet.timeout_timestamp)
                    != Expiry::NotExpired
                {
                    return Ok(false);
                }
            }
            Phase::Ack => (),
        }

        Ok(true)
    }
}

impl From<ChannelError> for Error {
    fn from(err: ChannelError) -> Self {
        Self::SequenceError(err.to_string())
    }
}

impl From<IbcDataError> for Error {
    fn from(err: IbcDataError) -> Self {
        Self::IbcDataError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::DecodingTxDataError(err)
    }
}
