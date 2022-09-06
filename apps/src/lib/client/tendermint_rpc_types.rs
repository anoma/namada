use std::convert::TryFrom;

use jsonpath_lib as jsonpath;
use namada::proto::Tx;
use namada::types::address::Address;
use serde::Serialize;

use crate::cli::safe_exit;
use crate::node::ledger::events::{
    Attributes, Error, EventType as NamadaEventType,
};

/// Data needed for broadcasting a tx and
/// monitoring its progress on chain
///
/// Txs may be either a dry run or else
/// they should be encrypted and included
/// in a wrapper.
#[derive(Clone)]
pub enum TxBroadcastData {
    DryRun(Tx),
    Wrapper {
        tx: Tx,
        wrapper_hash: String,
        decrypted_hash: String,
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
    /// Parse the JSON payload received from a subscription
    ///
    /// Searches for custom events emitted from the ledger and converts
    /// them back to thin wrapper around a hashmap for further parsing.
    pub fn parse(
        json: serde_json::Value,
        event_type: NamadaEventType,
        tx_hash: &str,
    ) -> Result<Option<TxResponse>, Error> {
        let mut selector = jsonpath::selector(&json);
        let mut event = {
            match selector(&format!("$.events.[?(@.type=='{}')]", event_type))
                .unwrap()
                .pop()
            {
                Some(event) => {
                    let attrs = Attributes::try_from(event)?;
                    match attrs.get("hash") {
                        Some(hash) if hash == tx_hash => attrs,
                        _ => return Ok(None),
                    }
                }
                _ => return Ok(None),
            }
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
        Ok(Some(TxResponse {
            info,
            log,
            height,
            hash,
            code,
            gas_used,
            initialized_accounts,
        }))
    }

    /// Find a tx with a given hash from the the websocket subscription
    /// to Tendermint events.
    pub fn find_tx(json: serde_json::Value, tx_hash: &str) -> Self {
        let tx_hash_json = serde_json::Value::String(tx_hash.to_string());
        let mut selector = jsonpath::selector(&json);
        let mut index = 0;
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
