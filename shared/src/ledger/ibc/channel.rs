//! IBC validity predicate for channel module

use std::str::FromStr;

use borsh::BorshDeserialize;
use ibc::ics02_client::client_consensus::AnyConsensusState;
use ibc::ics02_client::client_state::AnyClientState;
use ibc::ics02_client::context::ClientReader;
use ibc::ics02_client::height::Height;
use ibc::ics03_connection::connection::ConnectionEnd;
use ibc::ics03_connection::context::ConnectionReader;
use ibc::ics04_channel::channel::{ChannelEnd, Counterparty, State};
use ibc::ics04_channel::context::ChannelReader;
use ibc::ics04_channel::error::{Error as Ics4Error, Kind as Ics4Kind};
use ibc::ics04_channel::handler::verify::verify_channel_proofs;
use ibc::ics04_channel::packet::{Receipt, Sequence};
use ibc::ics05_port::capabilities::Capability;
use ibc::ics05_port::context::PortReader;
use ibc::ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId};
use ibc::ics24_host::Path;
use ibc::proofs::Proofs;
use ibc::timestamp::Timestamp;
use sha2::Digest;
use tendermint_proto::Protobuf;

use super::{Error, Ibc, Result, StateChange};
use crate::ledger::storage::{self, StorageHasher};
use crate::types::ibc::{
    ChannelCloseConfirmData, ChannelCloseInitData, ChannelOpenAckData,
    ChannelOpenConfirmData, ChannelOpenTryData,
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

        if self.authenticated_capability(&port_id).is_err() {
            tracing::info!("the port is not authenticated");
            return Ok(false);
        }

        let port_channel_id = (port_id, channel_id);
        let channel = match self.channel_end(&port_channel_id) {
            Some(c) => c,
            None => {
                tracing::info!(
                    "the channel doesn't exist: Port {}, Channel {}",
                    port_channel_id.0,
                    port_channel_id.1
                );
                return Ok(false);
            }
        };
        // check the number of hops and empty version in the channel end
        if channel.validate_basic().is_err() {
            tracing::info!("the channel end is invalid");
            return Ok(false);
        }

        if !self.has_valid_version(&channel) {
            return Ok(false);
        }

        match self.get_channel_state_change(port_channel_id.clone())? {
            StateChange::Created => match channel.state() {
                State::Init => Ok(true),
                State::TryOpen => self.verify_channel_try_proof(
                    port_channel_id.clone(),
                    &channel,
                    tx_data,
                ),
                _ => {
                    tracing::info!(
                        "the channel state is invalid: Port {}, Channel {}",
                        port_channel_id.0,
                        port_channel_id.1
                    );
                    Ok(false)
                }
            },
            StateChange::Updated => self.validate_updated_channel(
                port_channel_id.clone(),
                &channel,
                tx_data,
            ),
            _ => {
                tracing::info!(
                    "unexpected state change for an IBC channel: {}",
                    key
                );
                Ok(false)
            }
        }
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

    fn get_channel_state_change(
        &self,
        port_channel_id: (PortId, ChannelId),
    ) -> Result<StateChange> {
        let path =
            Path::ChannelEnds(port_channel_id.0, port_channel_id.1).to_string();
        let key =
            Key::ibc_key(path).expect("Creating a key for a channel failed");
        self.get_state_change(&key)
    }

    fn has_valid_version(&self, channel: &ChannelEnd) -> bool {
        let conn = match self.connection_from_channel(channel) {
            Ok(c) => c,
            Err(e) => {
                tracing::info!("{}", e);
                return false;
            }
        };

        let versions = conn.versions();
        let version = match versions.as_slice() {
            [version] => version,
            _ => {
                tracing::info!("multiple versions are specified or no version");
                return false;
            }
        };

        let feature = channel.ordering().to_string();
        if !version.is_supported_feature(feature.clone()) {
            tracing::info!("the feature isn't supported: {}", feature);
            return false;
        }

        true
    }

    fn validate_updated_channel(
        &self,
        port_channel_id: (PortId, ChannelId),
        channel: &ChannelEnd,
        tx_data: &[u8],
    ) -> Result<bool> {
        let prev_channel = match self.channel_end_pre(port_channel_id.clone()) {
            Some(c) => c,
            None => {
                tracing::info!("the previous channel doesn't exist");
                return Ok(false);
            }
        };
        match channel.state() {
            State::Open => match prev_channel.state() {
                State::Init => self.verify_channel_ack_proof(
                    port_channel_id,
                    channel,
                    tx_data,
                ),
                State::TryOpen => self.verify_channel_confirm_proof(
                    port_channel_id,
                    channel,
                    tx_data,
                ),
                _ => {
                    tracing::info!(
                        "the state change of the channel is invalid"
                    );
                    Ok(false)
                }
            },
            State::Closed => {
                if *prev_channel.state() != State::Open {
                    tracing::info!(
                        "the state change of the channel is invalid"
                    );
                    return Ok(false);
                }
                match ChannelCloseInitData::try_from_slice(tx_data) {
                    Ok(_) => Ok(true),
                    Err(_) => {
                        match ChannelCloseConfirmData::try_from_slice(tx_data) {
                            Ok(data) => self.verify_channel_close_proof(
                                port_channel_id,
                                channel,
                                data,
                            ),
                            Err(e) => Err(Error::DecodingTxDataError(e)),
                        }
                    }
                }
            }
            _ => {
                tracing::info!("the state change of the channel is invalid");
                Ok(false)
            }
        }
    }

    fn verify_channel_try_proof(
        &self,
        port_channel_id: (PortId, ChannelId),
        channel: &ChannelEnd,
        tx_data: &[u8],
    ) -> Result<bool> {
        let data = ChannelOpenTryData::try_from_slice(tx_data)?;
        let expected_my_side = Counterparty::new(port_channel_id.0, None);

        self.verify_proofs(
            channel,
            expected_my_side,
            State::Init,
            data.proofs()?,
        )
    }

    fn verify_channel_ack_proof(
        &self,
        port_channel_id: (PortId, ChannelId),
        channel: &ChannelEnd,
        tx_data: &[u8],
    ) -> Result<bool> {
        let data = ChannelOpenAckData::try_from_slice(tx_data)?;
        let expected_my_side =
            Counterparty::new(port_channel_id.0, Some(port_channel_id.1));

        self.verify_proofs(
            channel,
            expected_my_side,
            State::TryOpen,
            data.proofs()?,
        )
    }

    fn verify_channel_confirm_proof(
        &self,
        port_channel_id: (PortId, ChannelId),
        channel: &ChannelEnd,
        tx_data: &[u8],
    ) -> Result<bool> {
        let data = ChannelOpenConfirmData::try_from_slice(tx_data)?;
        let expected_my_side =
            Counterparty::new(port_channel_id.0, Some(port_channel_id.1));

        self.verify_proofs(
            channel,
            expected_my_side,
            State::Open,
            data.proofs()?,
        )
    }

    fn verify_channel_close_proof(
        &self,
        port_channel_id: (PortId, ChannelId),
        channel: &ChannelEnd,
        data: ChannelCloseConfirmData,
    ) -> Result<bool> {
        let expected_my_side =
            Counterparty::new(port_channel_id.0, Some(port_channel_id.1));

        self.verify_proofs(
            channel,
            expected_my_side,
            State::Closed,
            data.proofs()?,
        )
    }

    fn verify_proofs(
        &self,
        channel: &ChannelEnd,
        expected_my_side: Counterparty,
        expected_state: State,
        proofs: Proofs,
    ) -> Result<bool> {
        let conn = match self.connection_from_channel(channel) {
            Ok(c) => c,
            Err(e) => {
                tracing::info!("{}", e);
                return Ok(false);
            }
        };
        let counterpart_conn_id = match conn.counterparty().connection_id() {
            Some(id) => id.clone(),
            None => {
                tracing::info!("the counterpart connection ID doesn't exist");
                return Ok(false);
            }
        };
        let expected_connection_hops = vec![counterpart_conn_id];
        let expected_channel = ChannelEnd::new(
            expected_state,
            channel.ordering().clone(),
            expected_my_side,
            expected_connection_hops,
            channel.version(),
        );

        match verify_channel_proofs(
            self,
            &channel,
            &conn,
            &expected_channel,
            &proofs,
        ) {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::info!("proof verification failed: {}", e);
                Ok(false)
            }
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
                            tracing::error!(
                                "Decoding a sequece index failed: {}",
                                e
                            );
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

    fn connection_from_channel(
        &self,
        channel: &ChannelEnd,
    ) -> Result<ConnectionEnd> {
        match channel.connection_hops().get(0) {
            Some(conn_id) => {
                match ChannelReader::connection_end(self, &conn_id) {
                    Some(conn) => Ok(conn),
                    None => Err(Error::NoConnectionError(
                        "the corresponding connection doesn't exist".to_owned(),
                    )),
                }
            }
            _ => Err(Error::NoConnectionError(
                "the corresponding connection ID doesn't exist".to_owned(),
            )),
        }
    }

    fn channel_end_pre(
        &self,
        port_channel_id: (PortId, ChannelId),
    ) -> Option<ChannelEnd> {
        let path =
            Path::ChannelEnds(port_channel_id.0, port_channel_id.1).to_string();
        let key =
            Key::ibc_key(path).expect("Creating a key for a channel failed");
        match self.ctx.read_pre(&key) {
            Ok(Some(value)) => ChannelEnd::decode_vec(&value).ok(),
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
        let port_channel_id = port_channel_id.clone();
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
        match self.lookup_module_by_port(port_id) {
            Some(cap) => {
                if self.authenticate(&cap, port_id) {
                    Ok(cap)
                } else {
                    Err(Ics4Kind::InvalidPortCapability.into())
                }
            }
            None => Err(Ics4Kind::NoPortCapability(port_id.clone()).into()),
        }
    }

    fn get_next_sequence_send(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Option<Sequence> {
        let port_channel_id = port_channel_id.clone();
        let path = Path::SeqSends(port_channel_id.0, port_channel_id.1);
        self.get_sequence(path)
    }

    fn get_next_sequence_recv(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Option<Sequence> {
        let port_channel_id = port_channel_id.clone();
        let path = Path::SeqRecvs(port_channel_id.0, port_channel_id.1);
        self.get_sequence(path)
    }

    fn get_next_sequence_ack(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Option<Sequence> {
        let port_channel_id = port_channel_id.clone();
        let path = Path::SeqAcks(port_channel_id.0, port_channel_id.1);
        self.get_sequence(path)
    }

    fn get_packet_commitment(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Option<String> {
        let key = key.clone();
        let path = Path::Commitments {
            port_id: key.0,
            channel_id: key.1,
            sequence: key.2,
        };
        self.get_packet_info(path)
    }

    fn get_packet_receipt(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Option<Receipt> {
        let key = key.clone();
        let path = Path::Receipts {
            port_id: key.0,
            channel_id: key.1,
            sequence: key.2,
        };
        let key = Key::ibc_key(path.to_string())
            .expect("Creating akey for a packet info shouldn't fail");
        match self.ctx.read_post(&key) {
            Ok(Some(_)) => Some(Receipt::Ok),
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
            Some(h) => Timestamp::from_datetime(h.time.into()),
            None => Timestamp::none(),
        }
    }

    fn channel_counter(&self) -> u64 {
        let key = Key::ibc_channel_counter();
        self.read_counter(&key)
    }
}
