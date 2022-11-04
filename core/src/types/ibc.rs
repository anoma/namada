//! IBC event without IBC-related data types

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

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

#[cfg(any(feature = "abciplus", feature = "abcipp"))]
mod ibc_rs_conversion {
    use std::collections::HashMap;

    use thiserror::Error;

    use super::IbcEvent;
    use crate::ibc::events::{Error as IbcEventError, IbcEvent as RawIbcEvent};
    use crate::tendermint::abci::Event as AbciEvent;

    #[allow(missing_docs)]
    #[derive(Error, Debug)]
    pub enum Error {
        #[error("IBC event error: {0}")]
        IbcEvent(IbcEventError),
    }

    /// Conversion functions result
    pub type Result<T> = std::result::Result<T, Error>;

    impl TryFrom<RawIbcEvent> for IbcEvent {
        type Error = Error;

        fn try_from(e: RawIbcEvent) -> Result<Self> {
            let event_type = e.event_type().as_str().to_string();
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
}

#[cfg(any(feature = "abciplus", feature = "abcipp"))]
pub use ibc_rs_conversion::*;
