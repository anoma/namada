use std::collections::BTreeMap;

use borsh::schema::{Declaration, Definition, Fields};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use ibc::apps::nft_transfer::types::PORT_ID_STR as NFT_PORT_ID_STR;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::PORT_ID_STR as FT_PORT_ID_STR;
use ibc::core::channel::types::msgs::PacketMsg;
use ibc::core::channel::types::packet::Packet;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::identifiers::{ChannelId, PortId, Sequence};
use ibc::primitives::proto::Protobuf;
use masp_primitives::transaction::Transaction as MaspTransaction;
use namada_core::borsh::BorshSerializeExt;
use namada_core::masp::MaspEpoch;
use namada_core::token::Amount;

use crate::trace::ibc_trace_for_nft;
use crate::Error;

/// The different variants of an Ibc message
#[derive(Debug, Clone)]
pub enum IbcMessage<Transfer> {
    /// Ibc Envelop
    Envelope(Box<MsgEnvelope>),
    /// Ibc transaprent transfer
    Transfer(Box<MsgTransfer<Transfer>>),
    /// NFT transfer
    NftTransfer(MsgNftTransfer<Transfer>),
}

/// IBC transfer message with `Transfer`
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone)]
pub struct MsgTransfer<Transfer> {
    /// IBC transfer message
    pub message: IbcMsgTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
    /// MASP transaction for refund
    pub refund_masp_tx: Option<(MaspEpoch, MaspTransaction)>,
}

impl<Transfer: BorshSerialize> BorshSerialize for MsgTransfer<Transfer> {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, &self.transfer, &self.refund_masp_tx);
        BorshSerialize::serialize(&members, writer)
    }
}

impl<Transfer: BorshDeserialize> BorshDeserialize for MsgTransfer<Transfer> {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer, refund_masp_tx): (
            Vec<u8>,
            Option<Transfer>,
            Option<(MaspEpoch, MaspTransaction)>,
        ) = BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self {
            message,
            transfer,
            refund_masp_tx,
        })
    }
}

impl<Transfer: BorshSchema> BorshSchema for MsgTransfer<Transfer> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        <(Vec<u8>, Option<Transfer>, Option<MaspTransaction>)>::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![<(
            Vec<u8>,
            Option<Transfer>,
            Option<(MaspEpoch, MaspTransaction)>,
        )>::declaration()]);
        definitions.insert(Self::declaration(), Definition::Struct { fields });
    }

    fn declaration() -> Declaration {
        "MsgTransfer".into()
    }
}

/// IBC NFT transfer message with `Transfer`
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone)]
pub struct MsgNftTransfer<Transfer> {
    /// IBC NFT transfer message
    pub message: IbcMsgNftTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
    /// MASP transaction for refund
    pub refund_masp_tx: Option<(MaspEpoch, MaspTransaction)>,
}

impl<Transfer: BorshSerialize> BorshSerialize for MsgNftTransfer<Transfer> {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, &self.transfer, &self.refund_masp_tx);
        BorshSerialize::serialize(&members, writer)
    }
}

impl<Transfer: BorshDeserialize> BorshDeserialize for MsgNftTransfer<Transfer> {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer, refund_masp_tx): (
            Vec<u8>,
            Option<Transfer>,
            Option<(MaspEpoch, MaspTransaction)>,
        ) = BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgNftTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self {
            message,
            transfer,
            refund_masp_tx,
        })
    }
}

impl<Transfer: BorshSchema> BorshSchema for MsgNftTransfer<Transfer> {
    fn add_definitions_recursively(
        definitions: &mut BTreeMap<Declaration, Definition>,
    ) {
        <(Vec<u8>, Option<Transfer>, Option<Transfer>)>::add_definitions_recursively(definitions);
        let fields = Fields::UnnamedFields(vec![<(
            Vec<u8>,
            Option<Transfer>,
            Option<(MaspEpoch, MaspTransaction)>,
        )>::declaration()]);
        definitions.insert(Self::declaration(), Definition::Struct { fields });
    }

    fn declaration() -> Declaration {
        "MsgNftTransfer".into()
    }
}

/// Shielding data in IBC packet memo
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct IbcShieldingData(pub MaspTransaction);

impl From<IbcShieldingData> for String {
    fn from(data: IbcShieldingData) -> Self {
        HEXUPPER.encode(&data.serialize_to_vec())
    }
}

/// Extract MASP transaction from IBC envelope
pub fn extract_masp_tx_from_envelope(
    envelope: &MsgEnvelope,
) -> Option<MaspTransaction> {
    match envelope {
        MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
            extract_masp_tx_from_packet(&msg.packet)
        }
        _ => None,
    }
}

/// Get the port ID, channel ID and sequence of the packet in the envelope
pub fn packet_info_from_envelope(
    envelope: &MsgEnvelope,
) -> Option<(&PortId, &ChannelId, Sequence)> {
    let packet = match envelope {
        MsgEnvelope::Packet(PacketMsg::Recv(msg)) => &msg.packet,
        MsgEnvelope::Packet(PacketMsg::Ack(msg)) => &msg.packet,
        MsgEnvelope::Packet(PacketMsg::Timeout(msg)) => &msg.packet,
        MsgEnvelope::Packet(PacketMsg::TimeoutOnClose(msg)) => &msg.packet,
        _ => return None,
    };
    Some((&packet.port_id_on_a, &packet.chan_id_on_a, packet.seq_on_a))
}

/// Decode IBC shielding data from the string
pub fn decode_ibc_shielding_data(
    s: impl AsRef<str>,
) -> Option<IbcShieldingData> {
    let bytes = HEXUPPER.decode(s.as_ref().as_bytes()).ok()?;
    IbcShieldingData::try_from_slice(&bytes).ok()
}

/// Extract MASP transaction from IBC packet memo
pub fn extract_masp_tx_from_packet(packet: &Packet) -> Option<MaspTransaction> {
    let memo = extract_memo_from_packet(packet, &packet.port_id_on_b)?;
    decode_ibc_shielding_data(memo).map(|data| data.0)
}

fn extract_memo_from_packet(
    packet: &Packet,
    port_id: &PortId,
) -> Option<String> {
    match port_id.as_str() {
        FT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<PacketData>(&packet.data).ok()?;
            if packet_data.memo.as_ref().is_empty() {
                None
            } else {
                Some(packet_data.memo.as_ref().to_string())
            }
        }
        NFT_PORT_ID_STR => {
            let packet_data =
                serde_json::from_slice::<NftPacketData>(&packet.data).ok()?;
            Some(packet_data.memo?.as_ref().to_string())
        }
        _ => {
            tracing::warn!(
                "Memo couldn't be extracted from the unsupported IBC packet \
                 data for Port ID {port_id}"
            );
            None
        }
    }
}

/// Get IBC memo string from MASP transaction for receiving
pub fn convert_masp_tx_to_ibc_memo(transaction: &MaspTransaction) -> String {
    IbcShieldingData(transaction.clone()).into()
}

/// IBC transfer info. for the MASP VP
#[allow(missing_docs)]
pub struct IbcTransferInfo {
    pub src_port_id: PortId,
    pub src_channel_id: ChannelId,
    pub ibc_traces: Vec<String>,
    pub amount: Amount,
    pub receiver: String,
}

impl TryFrom<IbcMsgTransfer> for IbcTransferInfo {
    type Error = Error;

    fn try_from(
        message: IbcMsgTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let ibc_traces = vec![message.packet_data.token.denom.to_string()];
        let amount =
            message.packet_data.token.amount.try_into().map_err(|e| {
                Error::Other(format!(
                    "Converting IBC amount to Namada amount failed: {e}"
                ))
            })?;
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            ibc_traces,
            amount,
            receiver,
        })
    }
}

impl TryFrom<IbcMsgNftTransfer> for IbcTransferInfo {
    type Error = Error;

    fn try_from(
        message: IbcMsgNftTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let ibc_traces = message
            .packet_data
            .token_ids
            .0
            .iter()
            .map(|token_id| {
                ibc_trace_for_nft(&message.packet_data.class_id, token_id)
            })
            .collect();
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            ibc_traces,
            amount: Amount::from_u64(1),
            receiver,
        })
    }
}

/// Receiving token info
#[allow(missing_docs)]
pub struct ReceiveInfo {
    pub ibc_traces: Vec<String>,
    pub amount: Amount,
    pub receiver: String,
}

/// Retrieve receiving token info
pub fn recv_info_from_packet(
    packet: &Packet,
    is_src_chain: bool,
) -> Result<ReceiveInfo, Error> {
    let port_id = if is_src_chain {
        &packet.port_id_on_a
    } else {
        &packet.port_id_on_b
    };
    match port_id.as_str() {
        FT_PORT_ID_STR => {
            let packet_data = serde_json::from_slice::<PacketData>(
                &packet.data,
            )
            .map_err(|e| {
                Error::Other(format!("Decoding the packet data failed: {e}"))
            })?;
            let receiver = packet_data.receiver.to_string();
            let ibc_denom = packet_data.token.denom.to_string();
            let amount = packet_data.token.amount.try_into().map_err(|e| {
                Error::Other(format!(
                    "Converting IBC amount to Namada amount failed: {e}"
                ))
            })?;
            Ok(ReceiveInfo {
                ibc_traces: vec![ibc_denom],
                amount,
                receiver,
            })
        }
        NFT_PORT_ID_STR => {
            let packet_data = serde_json::from_slice::<NftPacketData>(
                &packet.data,
            )
            .map_err(|e| {
                Error::Other(format!(
                    "Decoding the NFT packet data failed: {e}"
                ))
            })?;
            let receiver = packet_data.receiver.to_string();
            let ibc_traces = packet_data
                .token_ids
                .0
                .iter()
                .map(|token_id| {
                    ibc_trace_for_nft(&packet_data.class_id, token_id)
                })
                .collect();
            Ok(ReceiveInfo {
                ibc_traces,
                amount: Amount::from_u64(1),
                receiver,
            })
        }
        _ => Err(Error::Other(format!("Invalid IBC port: {packet}"))),
    }
}
