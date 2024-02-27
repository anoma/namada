//! Logic to do with events emitted by the ledger.
pub mod log;

use std::collections::HashMap;

pub use namada_core::event::{Event, EventError, EventLevel, EventType};
use serde_json::Value;

// use crate::ledger::governance::utils::ProposalEvent;
use crate::error::{EncodingError, Error};

/// A thin wrapper around a HashMap for parsing event JSONs
/// returned in tendermint subscription responses.
#[derive(Debug)]
pub struct Attributes(HashMap<String, String>);

impl Attributes {
    /// Get a reference to the value associated with input key
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Get ownership of the value associated to the input key
    pub fn take(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }
}

impl TryFrom<&serde_json::Value> for Attributes {
    type Error = Error;

    fn try_from(json: &serde_json::Value) -> Result<Self, Self::Error> {
        let mut attributes = HashMap::new();
        let attrs: Vec<serde_json::Value> = serde_json::from_value(
            json.get("attributes")
                .ok_or(EventError::MissingAttributes)?
                .clone(),
        )
        .map_err(|err| EncodingError::Serde(err.to_string()))?;

        for attr in attrs {
            let key = serde_json::from_value(
                attr.get("key")
                    .ok_or_else(|| {
                        try_decoding_str(&attr, EventError::MissingKey)
                    })?
                    .clone(),
            )
            .map_err(|err| EncodingError::Serde(err.to_string()))?;
            let value = serde_json::from_value(
                attr.get("value")
                    .ok_or_else(|| {
                        try_decoding_str(&attr, EventError::MissingValue)
                    })?
                    .clone(),
            )
            .map_err(|err| EncodingError::Serde(err.to_string()))?;
            attributes.insert(key, value);
        }
        Ok(Attributes(attributes))
    }
}

fn try_decoding_str<F>(attr: &Value, err_type: F) -> Error
where
    F: FnOnce(String) -> EventError,
{
    match serde_json::to_string(attr) {
        Ok(e) => Error::from(err_type(e)),
        Err(err) => Error::from(EncodingError::Serde(format!(
            "Failure to decode attribute {}",
            err
        ))),
    }
}
