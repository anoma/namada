//! IBC-related data types

use std::cmp::Ordering;
use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

/// The event type defined in ibc-rs for receiving a token
pub const EVENT_TYPE_PACKET: &str = "fungible_token_packet";
/// The event type defined in ibc-rs for IBC denom
pub const EVENT_TYPE_DENOM_TRACE: &str = "denomination_trace";

/// Wrapped IbcEvent
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq, Eq,
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

/// IBC shielded transfer
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IbcShieldedTransfer {
    /// The IBC event type
    pub transfer: crate::types::token::Transfer,
    /// The attributes of the IBC event
    pub masp_tx: masp_primitives::transaction::Transaction,
}

#[cfg(any(feature = "abciplus", feature = "abcipp"))]
mod ibc_rs_conversion {
    use std::collections::HashMap;
    use std::str::FromStr;

    use borsh::{BorshDeserialize, BorshSerialize};
    use data_encoding::HEXUPPER;
    use thiserror::Error;

    use super::{IbcEvent, IbcShieldedTransfer, EVENT_TYPE_PACKET};
    use crate::ibc::applications::transfer::{Memo, PrefixedDenom, TracePath};
    use crate::ibc::core::events::{
        Error as IbcEventError, IbcEvent as RawIbcEvent,
    };
    use crate::tendermint_proto::abci::Event as AbciEvent;
    use crate::types::masp::PaymentAddress;

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

    impl From<IbcShieldedTransfer> for Memo {
        fn from(shielded: IbcShieldedTransfer) -> Self {
            let bytes =
                shielded.try_to_vec().expect("Encoding shouldn't failed");
            HEXUPPER.encode(&bytes).into()
        }
    }

    impl TryFrom<Memo> for IbcShieldedTransfer {
        type Error = Error;

        fn try_from(memo: Memo) -> Result<Self> {
            let bytes = HEXUPPER
                .decode(memo.as_ref().as_bytes())
                .map_err(Error::DecodingHex)?;
            Self::try_from_slice(&bytes)
                .map_err(Error::DecodingShieldedTransfer)
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
}

#[cfg(any(feature = "abciplus", feature = "abcipp"))]
pub use ibc_rs_conversion::*;
