//! IBC-related data types

use std::cmp::Ordering;
use std::collections::HashMap;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use data_encoding::{DecodePartial, HEXLOWER, HEXLOWER_PERMISSIVE, HEXUPPER};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::address::{Address, InternalAddress, HASH_LEN};
use crate::ibc::apps::nft_transfer::context::{NftClassContext, NftContext};
use crate::ibc::apps::nft_transfer::types::error::NftTransferError;
use crate::ibc::apps::nft_transfer::types::{
    ClassData, ClassId, ClassUri, PrefixedClassId, TokenData, TokenId,
    TokenUri, TracePath as NftTracePath,
};
use crate::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use crate::ibc::apps::transfer::types::{Memo, PrefixedDenom, TracePath};
use crate::ibc::core::handler::types::events::{
    Error as IbcEventError, IbcEvent as RawIbcEvent,
};
use crate::ibc::primitives::proto::Protobuf;
use crate::tendermint::abci::Event as AbciEvent;
use crate::types::masp::PaymentAddress;
use crate::types::token::Transfer;

/// The event type defined in ibc-rs for receiving a token
pub const EVENT_TYPE_PACKET: &str = "fungible_token_packet";
/// The event type defined in ibc-rs for IBC denom
pub const EVENT_TYPE_DENOM_TRACE: &str = "denomination_trace";
/// The event attribute key defined in ibc-rs for IBC denom
pub const EVENT_ATTRIBUTE_DENOM: &str = "denom";
/// The event attribute key defined in ibc-rs for a receiver
pub const EVENT_ATTRIBUTE_RECEIVER: &str = "receiver";
/// The event attribute key defined in ibc-rs for a trace hash
pub const EVENT_ATTRIBUTE_TRACE: &str = "trace_hash";
/// The event type defined in ibc-rs for receiving an NFT
pub const EVENT_TYPE_NFT_PACKET: &str = "non_fungible_token_packet";
/// The event type defined in ibc-rs for NFT trace
pub const EVENT_TYPE_TOKEN_TRACE: &str = "token_trace";
/// The event attribute key defined in ibc-rs for NFT class ID
pub const EVENT_ATTRIBUTE_CLASS: &str = "class";
/// The event attribute key defined in ibc-rs for NFT token ID
pub const EVENT_ATTRIBUTE_TOKEN: &str = "token";
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

    fn from_str(h: &str) -> std::result::Result<Self, Self::Err> {
        let mut output = [0u8; HASH_LEN];
        HEXLOWER_PERMISSIVE.decode_mut(h.as_ref(), &mut output)?;
        Ok(IbcTokenHash(output))
    }
}

/// Wrapped IbcEvent
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
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

impl std::cmp::PartialOrd for IbcEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.event_type.partial_cmp(&other.event_type)
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

/// IBC transfer message to send from a shielded address
#[derive(Debug, Clone)]
pub struct MsgShieldedTransfer {
    /// IBC transfer message
    pub message: MsgTransfer,
    /// MASP tx with token transfer
    pub shielded_transfer: IbcShieldedTransfer,
}

impl BorshSerialize for MsgShieldedTransfer {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let encoded_msg = self.message.clone().encode_vec();
        let members = (encoded_msg, self.shielded_transfer.clone());
        BorshSerialize::serialize(&members, writer)
    }
}

impl BorshDeserialize for MsgShieldedTransfer {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let (msg, shielded_transfer): (Vec<u8>, IbcShieldedTransfer) =
            BorshDeserialize::deserialize_reader(reader)?;
        let message = MsgTransfer::decode_vec(&msg)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        Ok(Self {
            message,
            shielded_transfer,
        })
    }
}

/// IBC shielded transfer
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IbcShieldedTransfer {
    /// The IBC event type
    pub transfer: Transfer,
    /// The attributes of the IBC event
    pub masp_tx: masp_primitives::transaction::Transaction,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("IBC event error: {0}")]
    IbcEvent(IbcEventError),
    #[error("IBC transfer memo HEX decoding error: {0}")]
    DecodingHex(data_encoding::DecodeError),
    #[error("IBC transfer memo decoding error: {0}")]
    DecodingShieldedTransfer(std::io::Error),
}

/// Conversion functions result
pub type Result<T> = std::result::Result<T, Error>;

impl TryFrom<RawIbcEvent> for IbcEvent {
    type Error = Error;

    fn try_from(e: RawIbcEvent) -> Result<Self> {
        let event_type = e.event_type().to_string();
        let abci_event = AbciEvent::try_from(e).map_err(Error::IbcEvent)?;
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

/// Returns the trace path and the token string if the denom is an IBC
/// denom.
pub fn is_ibc_denom(denom: impl AsRef<str>) -> Option<(TracePath, String)> {
    let prefixed_denom = PrefixedDenom::from_str(denom.as_ref()).ok()?;
    if prefixed_denom.trace_path.is_empty() {
        return None;
    }
    // The base token isn't decoded because it could be non Namada token
    Some((
        prefixed_denom.trace_path,
        prefixed_denom.base_denom.to_string(),
    ))
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

impl From<IbcShieldedTransfer> for Memo {
    fn from(shielded: IbcShieldedTransfer) -> Self {
        let bytes = shielded.serialize_to_vec();
        HEXUPPER.encode(&bytes).into()
    }
}

impl TryFrom<Memo> for IbcShieldedTransfer {
    type Error = Error;

    fn try_from(memo: Memo) -> Result<Self> {
        let bytes = HEXUPPER
            .decode(memo.as_ref().as_bytes())
            .map_err(Error::DecodingHex)?;
        Self::try_from_slice(&bytes).map_err(Error::DecodingShieldedTransfer)
    }
}

/// Get the shielded transfer from the memo
pub fn get_shielded_transfer(
    event: &IbcEvent,
) -> Result<Option<IbcShieldedTransfer>> {
    if event.event_type != EVENT_TYPE_PACKET {
        // This event is not for receiving a token
        return Ok(None);
    }
    let is_success =
        event.attributes.get("success") == Some(&"true".to_string());
    let receiver = event.attributes.get("receiver");
    let is_shielded = if let Some(receiver) = receiver {
        PaymentAddress::from_str(receiver).is_ok()
    } else {
        false
    };
    if !is_success || !is_shielded {
        return Ok(None);
    }

    event
        .attributes
        .get("memo")
        .map(|memo| IbcShieldedTransfer::try_from(Memo::from(memo.clone())))
        .transpose()
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
