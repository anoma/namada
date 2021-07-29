//! IBC validity predicate for channel module

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use ibc::ics02_client::client_consensus::{AnyConsensusState, ConsensusState};
use ibc::ics02_client::client_state::AnyClientState;
use ibc::ics02_client::context::ClientReader;
use ibc::ics02_client::height::Height;
use ibc::ics03_connection::connection::ConnectionEnd;
use ibc::ics03_connection::context::ConnectionReader;
use ibc::ics04_channel::channel::ChannelEnd;
use ibc::ics04_channel::context::ChannelReader;
use ibc::ics04_channel::error::{Error as Ics4Error, Kind as Ics4Kind};
use ibc::ics04_channel::packet::{Receipt, Sequence};
use ibc::ics05_port::capabilities::Capability;
use ibc::ics05_port::context::PortReader;
use ibc::ics07_tendermint::consensus_state::ConsensusState as TendermintConsensusState;
use ibc::ics23_commitment::commitment::CommitmentPrefix;
use ibc::ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId};
use ibc::ics24_host::Path;
use ibc::proofs::Proofs;
use ibc::timestamp::Timestamp;
use sha2::Digest;
use tendermint_proto::Protobuf;

use super::{Error, Ibc, Result, StateChange};
use crate::ledger::storage::{self, StorageHasher};
use crate::types::address::{Address, InternalAddress};
use crate::types::ibc::{
    ConnectionOpenAckData, ConnectionOpenConfirmData, ConnectionOpenTryData,
};
use crate::types::storage::{Key, KeySeg};

impl<'a, DB, H> Ibc<'a, DB, H>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    pub(super) fn validate_channel(
        &self,
        key: &Key,
        tx_data: &[u8],
    ) -> Result<bool> {
        let port_id = Self::get_port_id(key)?;
        let channel_id = Self::get_channel_id(key)?;
    }

    /// Returns the channel ID after #IBC/channelEnds/ports/{port_id}/channels
    fn get_channel_id(key: &Key) -> Result<ChannelId> {
        match key.segments.get(5) {
            Some(id) => ChannelId::from_str(&id.raw())
                .map_err(|e| Error::KeyError(e.to_string())),
            None => Err(Error::KeyError(format!(
                "The key doesn't have a channel ID: {}",
                key
            ))),
        }
    }

    fn get_sequence(&self, path: Path) -> Option<Sequence> {
        let key = Key::ibc_key(path.to_string())
            .expect("Creating akey for a sequence shouldn't fail");
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => {
                let index: u64 =
                    match crate::ledger::storage::types::decode(value) {
                        Ok(i) => i,
                        Err(e) => {
                            tracing::error!("Decoding a sequece index failed");
                            return None;
                        }
                    };
                Some(Sequence::from(index))
            }
            // returns None even if DB read fails
            _ => None,
        }
    }

    fn get_packet_info(&self, path: Path) -> Option<String> {
        let key = Key::ibc_key(path.to_string())
            .expect("Creating akey for a packet info shouldn't fail");
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => match String::from_utf8(value.to_vec()) {
                Ok(s) => Some(s),
                Err(_) => None,
            },
            // returns None even if DB read fails
            _ => None,
        }
    }
}

impl<'a, DB, H> ChannelReader for Ibc<'a, DB, H>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn channel_end(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Option<ChannelEnd> {
        let path =
            Path::ChannelEnds(port_channel_id.0, port_channel_id.1).to_string();
        let key =
            Key::ibc_key(path).expect("Creating a key for a channel failed");
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => ChannelEnd::decode_vec(&value).ok(),
            // returns None even if DB read fails
            _ => None,
        }
    }

    fn connection_end(&self, conn_id: &ConnectionId) -> Option<ConnectionEnd> {
        ConnectionReader::connection_end(self, conn_id)
    }

    fn connection_channels(
        &self,
        _conn_id: &ConnectionId,
    ) -> Option<Vec<(PortId, ChannelId)>> {
        // TODO I'm not sure why this is required
        None
    }

    fn client_state(&self, client_id: &ClientId) -> Option<AnyClientState> {
        ClientReader::client_state(self, client_id)
    }

    fn client_consensus_state(
        &self,
        client_id: &ClientId,
        height: Height,
    ) -> Option<AnyConsensusState> {
        ClientReader::consensus_state(self, client_id, height)
    }

    fn authenticated_capability(
        &self,
        port_id: &PortId,
    ) -> std::result::Result<Capability, Ics4Error> {
        let cap = PortReader::lookup_module_by_port(self, port_id);
        match cap {
            Some(c) => {
                if !PortReader::authenticate(self, &c, port_id) {
                    Err(Ics4Kind::InvalidPortCapability.into())
                } else {
                    Ok(c)
                }
            }
            None => Err(Ics4Kind::NoPortCapability(port_id.clone()).into()),
        }
    }

    fn get_next_sequence_send(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Option<Sequence> {
        let path = Path::SeqSends(port_channel_id.0, port_channel_id.1);
        self.get_sequence(path)
    }

    fn get_next_sequence_recv(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Option<Sequence> {
        let path = Path::SeqRecvs(port_channel_id.0, port_channel_id.1);
        self.get_sequence(path)
    }

    fn get_next_sequence_ack(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Option<Sequence> {
        let path = Path::SeqAcks(port_channel_id.0, port_channel_id.1);
        self.get_sequence(path)
    }

    fn get_packet_commitment(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Option<String> {
        let path = Path::Commitments {
            port_id: key.0.clone(),
            channel_id: key.1.clone(),
            sequence: key.2.clone(),
        };
        self.get_packet_info(path)
    }

    fn get_packet_receipt(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Option<Receipt> {
        let path = Path::Receipts {
            port_id: key.0.clone(),
            channel_id: key.1.clone(),
            sequence: key.2.clone(),
        };
        let key = Key::ibc_key(path.to_string())
            .expect("Creating akey for a packet info shouldn't fail");
        match self.ctx.read_post(&key) {
            Ok(Some(value)) => Some(Receipt::Ok),
            // returns None even if DB read fails
            _ => None,
        }
    }

    fn get_packet_acknowledgement(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Option<String> {
        let path = Path::Acks {
            port_id: key.0.clone(),
            channel_id: key.1.clone(),
            sequence: key.2.clone(),
        };
        self.get_packet_info(path)
    }

    fn hash(&self, value: String) -> String {
        let r = sha2::Sha256::digest(value.as_bytes());
        format!("{:x}", r)
    }

    fn host_height(&self) -> Height {
        self.host_current_height()
    }

    fn host_timestamp(&self) -> Timestamp {
        match self.ctx.storage.get_block_header().0 {
            Some(h) => Timestamp {
                time: Some(h.time.into()),
            },
            None => Timestamp { time: None },
        }
    }

    fn channel_counter(&self) -> u64 {
        let key = Key::ibc_channel_counter();
        self.read_counter(&key)
    }
}
