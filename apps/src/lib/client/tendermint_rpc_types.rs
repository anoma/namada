use anoma::proto::Tx;
use anoma::types::address::Address;
use jsonpath_lib as jsonpath;
use serde::Serialize;

use crate::cli::safe_exit;
#[cfg(not(feature = "ABCI"))]
use crate::node::ledger::events::Attributes;

/// Data needed for broadcasting a tx and
/// monitoring its progress on chain
///
/// Txs may be either a dry run or else
/// they should be encrypted and included
/// in a wrapper.
pub enum TxBroadcastData {
    DryRun(Tx),
    Wrapper {
        tx: Tx,
        wrapper_hash: String,
        decrypted_hash: Option<String>,
    },
}

/// A parsed event from tendermint relating to a transaction
#[derive(Debug, Serialize)]
pub struct TxResponse {
    pub info: String,
    pub log: String,
    pub height: String,
    pub hash: String,
    pub code: String,
    pub gas_used: String,
    pub initialized_accounts: Vec<Address>,
}

impl TxResponse {
    /// Find a tx with a given hash from the the websocket subscription
    /// to Tendermint events.
    pub fn find_tx(json: serde_json::Value, tx_hash: &str) -> Self {
        let tx_hash_json = serde_json::Value::String(tx_hash.to_string());
        let mut selector = jsonpath::selector(&json);
        let mut index = 0;
        #[cfg(feature = "ABCI")]
        let evt_key = "applied";
        #[cfg(not(feature = "ABCI"))]
        let evt_key = "accepted";
        // Find the tx with a matching hash
        let hash = loop {
            if let Ok(hash) =
                selector(&format!("$.events.['{}.hash'][{}]", evt_key, index))
            {
                let hash = hash[0].clone();
                if hash == tx_hash_json {
                    break hash;
                } else {
                    index += 1;
                }
            } else {
                eprintln!(
                    "Couldn't find tx with hash {} in the event string {}",
                    tx_hash, json
                );
                safe_exit(1)
            }
        };
        let info =
            selector(&format!("$.events.['{}.info'][{}]", evt_key, index))
                .unwrap();
        let log = selector(&format!("$.events.['{}.log'][{}]", evt_key, index))
            .unwrap();
        let height =
            selector(&format!("$.events.['{}.height'][{}]", evt_key, index))
                .unwrap();
        let code =
            selector(&format!("$.events.['{}.code'][{}]", evt_key, index))
                .unwrap();
        let gas_used =
            selector(&format!("$.events.['{}.gas_used'][{}]", evt_key, index))
                .unwrap();
        let initialized_accounts = selector(&format!(
            "$.events.['{}.initialized_accounts'][{}]",
            evt_key, index
        ));
        let initialized_accounts = match initialized_accounts {
            Ok(values) if !values.is_empty() => {
                // In a response, the initialized accounts are encoded as e.g.:
                // ```
                // "applied.initialized_accounts": Array([
                //   String(
                //     "[\"atest1...\"]",
                //   ),
                // ]),
                // ...
                // So we need to decode the inner string first ...
                let raw: String =
                    serde_json::from_value(values[0].clone()).unwrap();
                // ... and then decode the vec from the array inside the string
                serde_json::from_str(&raw).unwrap()
            }
            _ => vec![],
        };
        TxResponse {
            info: serde_json::from_value(info[0].clone()).unwrap(),
            log: serde_json::from_value(log[0].clone()).unwrap(),
            height: serde_json::from_value(height[0].clone()).unwrap(),
            hash: serde_json::from_value(hash).unwrap(),
            code: serde_json::from_value(code[0].clone()).unwrap(),
            gas_used: serde_json::from_value(gas_used[0].clone()).unwrap(),
            initialized_accounts,
        }
    }
}

#[cfg(not(feature = "ABCI"))]
mod params {
    use std::convert::TryFrom;
    use std::time::Duration;

    use serde::ser::SerializeTuple;
    use serde::{Deserialize, Serializer};
    use serde_json::value::RawValue;
    use tendermint_rpc::query::Query;

    use super::*;

    /// Opaque type for ordering events. Set by Tendermint
    #[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct Cursor(String);

    impl From<String> for Cursor {
        fn from(cursor: String) -> Self {
            Cursor(cursor)
        }
    }

    /// Struct used for querying Tendermint's event logs
    #[derive(Debug)]
    pub struct EventParams {
        /// The filter an event must satisfy in order to
        /// be returned
        pub filter: Query,
        /// The maximum number of eligible results to return.
        /// If zero or negative, the server will report a default number.
        pub max_results: u64,
        /// Return only items after this cursor. If empty, the limit is just
        /// before the the beginning of the event log
        pub after: Cursor,
        /// Return only items before this cursor.  If empty, the limit is just
        /// after the head of the event log.
        before: Cursor,
        /// Wait for up to this long for events to be available.
        pub wait_time: Duration,
    }

    /// Struct to help serialize [`EventParams`]
    #[derive(Serialize)]
    struct Filter {
        filter: String,
    }

    impl Serialize for EventParams {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut ser = serializer.serialize_tuple(5)?;
            ser.serialize_element(&Filter {
                filter: self.filter.to_string(),
            })?;
            ser.serialize_element(&self.max_results)?;
            ser.serialize_element(self.after.0.as_str())?;
            ser.serialize_element(self.before.0.as_str())?;
            ser.serialize_element(&self.wait_time.as_nanos())?;
            ser.end()
        }
    }

    impl EventParams {
        /// Initialize a new set of [`EventParams`]
        pub fn new(
            filter: Query,
            max_results: u64,
            wait_time: Duration,
        ) -> Self {
            Self {
                filter,
                max_results,
                after: Default::default(),
                before: Default::default(),
                wait_time,
            }
        }

        /// Convert this into a list of raw json values to give to the
        /// JSON RPC client.
        pub fn to_params(&self) -> [Box<RawValue>; 5] {
            [
                RawValue::from_string(format!(
                    "{{\"filter\": \"{}\"}}",
                    self.filter.to_string()
                ))
                .unwrap(),
                RawValue::from_string(self.max_results.to_string()).unwrap(),
                RawValue::from_string(format!("\"{}\"", self.after.0)).unwrap(),
                RawValue::from_string(format!("\"{}\"", self.before.0))
                    .unwrap(),
                RawValue::from_string(self.wait_time.as_nanos().to_string())
                    .unwrap(),
            ]
        }
    }

    /// A reply from Tendermint for events matching the given [`EventParams`]
    #[derive(Serialize, Deserialize)]
    pub struct EventReply {
        /// The items matching the request parameters, from newest
        /// to oldest, if any were available within the timeout.
        pub items: Vec<EventItem>,
        /// This is true if there is at least one older matching item
        /// available in the log that was not returned.
        #[allow(dead_code)]
        more: bool,
        /// The cursor of the oldest item in the log at the time of this reply,
        /// or "" if the log is empty.
        #[allow(dead_code)]
        oldest: Cursor,
        /// The cursor of the newest item in the log at the time of this reply,
        /// or "" if the log is empty.
        pub newest: Cursor,
    }

    /// An event returned from Tendermint
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct EventItem {
        /// this specifies where in the event log this event is
        #[allow(dead_code)]
        pub cursor: Cursor,
        /// The event type
        #[allow(dead_code)]
        pub event: String,
        /// The raw event value
        pub data: EventData,
    }

    /// Raw data of an event returned from Tendermint
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct EventData {
        pub r#type: String,
        pub value: serde_json::Value,
    }

    /// Parse the JSON payload received from the `events` JSON-RPC
    /// endpoint of Tendermint.
    ///
    /// Searches for custom events emitted from the ledger and converts
    /// them back to thin wrapper around a hashmap for further parsing.
    /// Returns none if the event is not found.
    #[cfg(not(feature = "ABCI"))]
    pub fn parse(reply: EventReply, tx_hash: &str) -> Option<TxResponse> {
        println!("{}", serde_json::to_string_pretty(&reply).unwrap());
        let mut event = if let Some(event) =
            reply.items.iter().find_map(|event| {
                if let Some(attrs) =
                    Attributes::try_from(&event.data.value).ok()
                {
                    match attrs.get("hash") {
                        Some(hash) if hash == tx_hash => Some(attrs),
                        _ => None,
                    }
                } else {
                    None
                }
            }) {
            event
        } else {
            return None;
        };

        let info = event.take("info").unwrap();
        let log = event.take("log").unwrap();
        let height = event.take("height").unwrap();
        let hash = event.take("hash").unwrap();
        let code = event.take("code").unwrap();
        let gas_used =
            event.take("gas_used").unwrap_or_else(|| String::from("0"));
        let initialized_accounts = event.take("initialized_accounts");
        let initialized_accounts = match initialized_accounts {
            Some(values) => serde_json::from_str(&values).unwrap(),
            _ => vec![],
        };

        Some(TxResponse {
            info,
            log,
            height,
            hash,
            code,
            gas_used,
            initialized_accounts,
        })
    }

    #[cfg(test)]
    mod test_rpc_types {
        use tendermint_rpc::query::EventType;

        use super::*;

        /// Test that [`EventParams`] is serialized correctly
        #[test]
        fn test_serialize_event_params() {
            let params = EventParams {
                filter: Query::from(EventType::NewBlock),
                max_results: 5,
                after: Cursor("16CCC798FB5F4670-0123".into()),
                before: Default::default(),
                wait_time: Duration::from_secs(59),
            };
            assert_eq!(
                serde_json::to_string(&params).expect("Test failed"),
                r#"[{"filter":"tm.event = 'NewBlock'"},5,"16CCC798FB5F4670-0123","",59000000000]"#
            )
        }

        /// Test that [`EventParams`] are parsed into a params array correctly
        #[test]
        fn test_to_params() {
            let params = EventParams {
                filter: Query::from(EventType::NewBlock),
                max_results: 5,
                after: Cursor("16CCC798FB5F4670-0123".into()),
                before: Default::default(),
                wait_time: Duration::from_secs(59),
            };
            let args = params.to_params();
            assert_eq!(args[0].get(), r#"{"filter": "tm.event = 'NewBlock'"}"#);
            assert_eq!(args[1].get(), "5");
            assert_eq!(args[2].get(), "\"16CCC798FB5F4670-0123\"");
            assert_eq!(args[3].get(), "\"\"");
            assert_eq!(args[4].get(), "59000000000");
        }
    }
}

#[cfg(not(feature = "ABCI"))]
pub use params::*;
