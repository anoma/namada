use borsh::{BorshDeserialize, BorshSerialize};
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::core::channel::types::msgs::{
    MsgAcknowledgement as IbcMsgAcknowledgement,
    MsgRecvPacket as IbcMsgRecvPacket, MsgTimeout as IbcMsgTimeout,
};
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::primitives::proto::Protobuf;
use namada_token::{ShieldingTransfer, UnshieldingTransferData};

/// The different variants of an Ibc message
pub enum IbcMessage {
    /// Ibc Envelop
    Envelope(Box<MsgEnvelope>),
    /// Ibc transaprent transfer
    Transfer(MsgTransfer),
    /// NFT transfer
    NftTransfer(MsgNftTransfer),
    /// Receiving a packet
    RecvPacket(MsgRecvPacket),
    /// Acknowledgement
    AckPacket(MsgAcknowledgement),
    /// Timeout
    Timeout(MsgTimeout),
}

/// IBC transfer message with `Transfer`
#[derive(Debug, Clone)]
pub struct MsgTransfer {
    /// IBC transfer message
    pub message: IbcMsgTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<ShieldingTransfer>,
    /// Optional data for masp fee payment in the source chain
    pub fee_unshield: Option<UnshieldingTransferData>,
}

impl BorshSerialize for MsgTransfer {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (
            encoded_msg,
            self.transfer.clone(),
            self.fee_unshield.clone(),
        );
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgTransfer {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer, fee_unshield): (
            Vec<u8>,
            Option<ShieldingTransfer>,
            Option<UnshieldingTransferData>,
        ) = BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self {
            message,
            transfer,
            fee_unshield,
        })
    }
}

/// IBC NFT transfer message with `Transfer`
#[derive(Debug, Clone)]
pub struct MsgNftTransfer {
    /// IBC NFT transfer message
    pub message: IbcMsgNftTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<ShieldingTransfer>,
    /// Optional data for masp fee payment in the source chain
    pub fee_unshield: Option<UnshieldingTransferData>,
}

impl BorshSerialize for MsgNftTransfer {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (
            encoded_msg,
            self.transfer.clone(),
            self.fee_unshield.clone(),
        );
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgNftTransfer {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer, fee_unshield): (
            Vec<u8>,
            Option<ShieldingTransfer>,
            Option<UnshieldingTransferData>,
        ) = BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgNftTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self {
            message,
            transfer,
            fee_unshield,
        })
    }
}

/// IBC receiving packet message with `Transfer`
#[derive(Debug, Clone)]
pub struct MsgRecvPacket {
    /// IBC receiving packet message
    pub message: IbcMsgRecvPacket,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<ShieldingTransfer>,
}

impl BorshSerialize for MsgRecvPacket {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, self.transfer.clone());
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgRecvPacket {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer): (Vec<u8>, Option<ShieldingTransfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgRecvPacket::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}

/// IBC acknowledgement message with `Transfer` for refunding to a shielded
/// address
#[derive(Debug, Clone)]
pub struct MsgAcknowledgement {
    /// IBC acknowledgement message
    pub message: IbcMsgAcknowledgement,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<ShieldingTransfer>,
}

impl BorshSerialize for MsgAcknowledgement {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, self.transfer.clone());
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgAcknowledgement {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer): (Vec<u8>, Option<ShieldingTransfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgAcknowledgement::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}

/// IBC timeout packet message with `Transfer` for refunding to a shielded
/// address
#[derive(Debug, Clone)]
pub struct MsgTimeout {
    /// IBC timeout message
    pub message: IbcMsgTimeout,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<ShieldingTransfer>,
}

impl BorshSerialize for MsgTimeout {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, self.transfer.clone());
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgTimeout {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer): (Vec<u8>, Option<ShieldingTransfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgTimeout::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}
