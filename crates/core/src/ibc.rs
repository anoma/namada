//! IBC-related data types

use std::cmp::Ordering;
use std::collections::HashMap;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use data_encoding::{DecodePartial, HEXLOWER, HEXLOWER_PERMISSIVE, HEXUPPER};
pub use ibc::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::address::HASH_LEN;
use crate::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use crate::ibc::apps::transfer::types::{Memo, PrefixedDenom, TracePath};
use crate::ibc::core::handler::types::events::{
    Error as IbcEventError, IbcEvent as RawIbcEvent,
};
use crate::ibc::primitives::proto::Protobuf;
use crate::masp::PaymentAddress;
use crate::tendermint::abci::Event as AbciEvent;
use crate::token::Transfer;

/// The event type defined in ibc-rs for receiving a token
pub const EVENT_TYPE_PACKET: &str = "fungible_token_packet";
/// The event type defined in ibc-rs for IBC denom
pub const EVENT_TYPE_DENOM_TRACE: &str = "denomination_trace";

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
type Result<T> = std::result::Result<T, Error>;

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
