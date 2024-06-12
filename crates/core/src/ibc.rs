//! IBC-related data types

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::{DecodePartial, HEXLOWER, HEXLOWER_PERMISSIVE};
pub use ibc::*;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::address::{Address, InternalAddress, HASH_LEN};
use crate::ibc::apps::nft_transfer::context::{NftClassContext, NftContext};
use crate::ibc::apps::nft_transfer::types::error::NftTransferError;
use crate::ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use crate::ibc::apps::nft_transfer::types::{
    ClassData, ClassId, ClassUri, PrefixedClassId, TokenData, TokenId,
    TokenUri, TracePath as NftTracePath,
};
use crate::ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use crate::ibc::apps::transfer::types::{PrefixedDenom, TracePath};
use crate::ibc::core::channel::types::msgs::{
    MsgAcknowledgement as IbcMsgAcknowledgement,
    MsgRecvPacket as IbcMsgRecvPacket, MsgTimeout as IbcMsgTimeout,
};
use crate::ibc::core::handler::types::msgs::MsgEnvelope;
use crate::ibc::primitives::proto::Protobuf;
use crate::token::Transfer;

/// The event type defined in ibc-rs for receiving a token
pub const EVENT_TYPE_PACKET: &str = "fungible_token_packet";
/// The event type defined in ibc-rs for receiving an NFT
pub const EVENT_TYPE_NFT_PACKET: &str = "non_fungible_token_packet";
/// The escrow address for IBC transfer
pub const IBC_ESCROW_ADDRESS: Address = Address::Internal(InternalAddress::Ibc);

/// IBC token hash derived from a denomination.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[repr(transparent)]
pub struct IbcTokenHash(pub [u8; HASH_LEN]);

impl std::fmt::Display for IbcTokenHash {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

impl FromStr for IbcTokenHash {
    type Err = DecodePartial;

    fn from_str(h: &str) -> Result<Self, Self::Err> {
        let mut output = [0u8; HASH_LEN];
        HEXLOWER_PERMISSIVE.decode_mut(h.as_ref(), &mut output)?;
        Ok(IbcTokenHash(output))
    }
}

/// The different variants of an Ibc message
#[derive(Debug, Clone)]
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
    pub transfer: Option<Transfer>,
}

impl BorshSerialize for MsgTransfer {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, self.transfer.clone());
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgTransfer {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer): (Vec<u8>, Option<Transfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}

/// IBC NFT transfer message with `Transfer`
#[derive(Debug, Clone)]
pub struct MsgNftTransfer {
    /// IBC NFT transfer message
    pub message: IbcMsgNftTransfer,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
}

impl BorshSerialize for MsgNftTransfer {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, self.transfer.clone());
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgNftTransfer {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, transfer): (Vec<u8>, Option<Transfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgNftTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}

/// IBC shielded transfer
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub struct IbcShieldedTransfer {
    /// The IBC event type
    pub transfer: Transfer,
    /// The attributes of the IBC event
    pub masp_tx: masp_primitives::transaction::Transaction,
}

/// IBC receiving packet message with `Transfer`
#[derive(Debug, Clone)]
pub struct MsgRecvPacket {
    /// IBC receiving packet message
    pub message: IbcMsgRecvPacket,
    /// Shieleded transfer for MASP transaction
    pub transfer: Option<Transfer>,
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
        let (msg, transfer): (Vec<u8>, Option<Transfer>) =
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
    pub transfer: Option<Transfer>,
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
        let (msg, transfer): (Vec<u8>, Option<Transfer>) =
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
    pub transfer: Option<Transfer>,
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
        let (msg, transfer): (Vec<u8>, Option<Transfer>) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = IbcMsgTimeout::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self { message, transfer })
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("IBC transfer memo HEX decoding error: {0}")]
    DecodingHex(data_encoding::DecodeError),
    #[error("IBC transfer memo decoding error: {0}")]
    DecodingShieldedTransfer(std::io::Error),
}

/// Returns the trace path and the token string if the denom is an IBC
/// denom.
pub fn is_ibc_denom(denom: impl AsRef<str>) -> Option<(TracePath, String)> {
    let prefixed_denom = PrefixedDenom::from_str(denom.as_ref()).ok()?;
    let base_denom = prefixed_denom.base_denom.to_string();
    if prefixed_denom.trace_path.is_empty() || base_denom.contains('/') {
        // The denom is just a token or an NFT trace
        return None;
    }
    // The base token isn't decoded because it could be non Namada token
    Some((prefixed_denom.trace_path, base_denom))
}

/// Returns the trace path and the token string if the trace is an NFT one
pub fn is_nft_trace(
    trace: impl AsRef<str>,
) -> Option<(NftTracePath, String, String)> {
    // The trace should be {port}/{channel}/.../{class_id}/{token_id}
    if let Some((class_id, token_id)) = trace.as_ref().rsplit_once('/') {
        let prefixed_class_id = PrefixedClassId::from_str(class_id).ok()?;
        // The base token isn't decoded because it could be non Namada token
        Some((
            prefixed_class_id.trace_path,
            prefixed_class_id.base_class_id.to_string(),
            token_id.to_string(),
        ))
    } else {
        None
    }
}

/// NFT class
#[derive(Clone, Debug)]
pub struct NftClass {
    /// NFT class ID
    pub class_id: PrefixedClassId,
    /// NFT class URI
    pub class_uri: Option<ClassUri>,
    /// NFT class data
    pub class_data: Option<ClassData>,
}

impl BorshSerialize for NftClass {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.class_id.to_string(), writer)?;
        match &self.class_uri {
            Some(uri) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&uri.to_string(), writer)?;
            }
            None => BorshSerialize::serialize(&false, writer)?,
        }
        match &self.class_data {
            Some(data) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&data.to_string(), writer)
            }
            None => BorshSerialize::serialize(&false, writer),
        }
    }
}

impl BorshDeserialize for NftClass {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let class_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let class_id = class_id.parse().map_err(|e: NftTransferError| {
            Error::new(ErrorKind::InvalidData, e.to_string())
        })?;

        let is_uri: bool = BorshDeserialize::deserialize_reader(reader)?;
        let class_uri = if is_uri {
            let uri_str: String = BorshDeserialize::deserialize_reader(reader)?;
            Some(uri_str.parse().map_err(|e: NftTransferError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        let is_data: bool = BorshDeserialize::deserialize_reader(reader)?;
        let class_data = if is_data {
            let data_str: String =
                BorshDeserialize::deserialize_reader(reader)?;
            Some(data_str.parse().map_err(|e: NftTransferError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        Ok(Self {
            class_id,
            class_uri,
            class_data,
        })
    }
}

impl NftClassContext for NftClass {
    fn get_id(&self) -> &ClassId {
        &self.class_id.base_class_id
    }

    fn get_uri(&self) -> Option<&ClassUri> {
        self.class_uri.as_ref()
    }

    fn get_data(&self) -> Option<&ClassData> {
        self.class_data.as_ref()
    }
}

/// NFT metadata
#[derive(Clone, Debug)]
pub struct NftMetadata {
    /// NFT class ID
    pub class_id: PrefixedClassId,
    /// NFT ID
    pub token_id: TokenId,
    /// NFT URI
    pub token_uri: Option<TokenUri>,
    /// NFT data
    pub token_data: Option<TokenData>,
}

impl BorshSerialize for NftMetadata {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.class_id.to_string(), writer)?;
        BorshSerialize::serialize(&self.token_id.to_string(), writer)?;
        match &self.token_uri {
            Some(uri) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&uri.to_string(), writer)?;
            }
            None => BorshSerialize::serialize(&false, writer)?,
        }
        match &self.token_data {
            Some(data) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&data.to_string(), writer)
            }
            None => BorshSerialize::serialize(&false, writer),
        }
    }
}

impl BorshDeserialize for NftMetadata {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let class_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let class_id = class_id.parse().map_err(|e: NftTransferError| {
            Error::new(ErrorKind::InvalidData, e.to_string())
        })?;

        let token_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let token_id = token_id.parse().map_err(|e: NftTransferError| {
            Error::new(ErrorKind::InvalidData, e.to_string())
        })?;

        let is_uri: bool = BorshDeserialize::deserialize_reader(reader)?;
        let token_uri = if is_uri {
            let uri_str: String = BorshDeserialize::deserialize_reader(reader)?;
            Some(uri_str.parse().map_err(|e: NftTransferError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        let is_data: bool = BorshDeserialize::deserialize_reader(reader)?;
        let token_data = if is_data {
            let data_str: String =
                BorshDeserialize::deserialize_reader(reader)?;
            Some(data_str.parse().map_err(|e: NftTransferError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        Ok(Self {
            class_id,
            token_id,
            token_uri,
            token_data,
        })
    }
}

impl NftContext for NftMetadata {
    fn get_class_id(&self) -> &ClassId {
        &self.class_id.base_class_id
    }

    fn get_id(&self) -> &TokenId {
        &self.token_id
    }

    fn get_uri(&self) -> Option<&TokenUri> {
        self.token_uri.as_ref()
    }

    fn get_data(&self) -> Option<&TokenData> {
        self.token_data.as_ref()
    }
}
