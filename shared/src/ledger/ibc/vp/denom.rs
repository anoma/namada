//! IBC validity predicate for denom

use prost::Message;
use thiserror::Error;

use super::Ibc;
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ibc::core::ics04_channel::msgs::PacketMsg;
use crate::ibc::core::ics26_routing::msgs::MsgEnvelope;
use crate::ibc_proto::google::protobuf::Any;
use crate::ledger::ibc::storage;
use crate::ledger::native_vp::VpEnv;
use crate::ledger::storage::{self as ledger_storage, StorageHasher};
use crate::types::storage::KeySeg;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Decoding IBC data error: {0}")]
    DecodingData(prost::DecodeError),
    #[error("Invalid message: {0}")]
    IbcMessage(String),
    #[error("Decoding PacketData error: {0}")]
    DecodingPacketData(serde_json::Error),
    #[error("Denom error: {0}")]
    Denom(String),
}

/// IBC channel functions result
pub type Result<T> = std::result::Result<T, Error>;

impl<'a, DB, H, CA> Ibc<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    pub(super) fn validate_denom(&self, tx_data: &[u8]) -> Result<()> {
        let ibc_msg = Any::decode(&tx_data[..]).map_err(Error::DecodingData)?;
        let envelope: MsgEnvelope = ibc_msg.try_into().map_err(|e| {
            Error::IbcMessage(format!(
                "Decoding a MsgRecvPacket failed: Error {}",
                e
            ))
        })?;
        // A transaction only with MsgRecvPacket can update the denom store
        let msg = match envelope {
            MsgEnvelope::Packet(PacketMsg::Recv(msg)) => msg,
            _ => {
                return Err(Error::IbcMessage(
                    "Non-MsgRecvPacket message updated the denom store"
                        .to_string(),
                ));
            }
        };
        let data = serde_json::from_slice::<PacketData>(&msg.packet.data)
            .map_err(Error::DecodingPacketData)?;
        let denom = format!(
            "{}/{}/{}",
            &msg.packet.port_on_b, &msg.packet.chan_on_b, &data.token.denom,
        );
        let token_hash = storage::calc_hash(&denom);
        let denom_key = storage::ibc_denom_key(token_hash.raw());
        match self.ctx.read_bytes_post(&denom_key) {
            Ok(Some(v)) => match std::str::from_utf8(&v) {
                Ok(d) if d == denom => Ok(()),
                Ok(d) => Err(Error::Denom(format!(
                    "Mismatch the denom: original {}, denom {}",
                    denom, d
                ))),
                Err(e) => Err(Error::Denom(format!(
                    "Decoding the denom failed: key {}, error {}",
                    denom_key, e
                ))),
            },
            _ => Err(Error::Denom(format!(
                "Looking up the denom failed: Key {}",
                denom_key
            ))),
        }
    }
}
