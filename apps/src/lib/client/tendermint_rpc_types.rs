use namada::proto::Tx;
use namada::types::address::Address;
use serde::Serialize;

use crate::cli::safe_exit;
use crate::facade::tendermint_rpc::event::Event;
use crate::node::ledger::events::EventType as NamadaEventType;

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
        event: Event,
        event_type: NamadaEventType,
        tx_hash: &str,
    ) -> Self {
        let events = event.events.expect(
            "We should have obtained Tx events from the websocket subscription",
        );
        let evt_key = event_type.to_string();
        // Find the tx with a matching hash
        let tx_error = || {
            eprintln!(
                "Couldn't find tx with hash {tx_hash} in events {events:?}",
            );
            safe_exit(1)
        };
        let (index, _) = events
            .get(&format!("{evt_key}.hash"))
            .unwrap_or_else(tx_error)
            .iter()
            .enumerate()
            .find(|(_, hash)| hash == tx_hash)
            .unwrap_or_else(tx_error);
        let info = events.get(&format!("{evt_key}.info")).unwrap()[index];
        let log = events.get(&format!("{evt_key}.log")).unwrap()[index];
        let height = events.get(&format!("{evt_key}.height")).unwrap()[index];
        let code = events.get(&format!("{evt_key}.code")).unwrap()[index];
        let gas_used =
            events.get(&format!("{evt_key}.gas_used")).unwrap()[index];
        let initialized_accounts = events
            .get(&format!("{evt_key}.initialized_accounts"))
            .unwrap()[index];
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
            hash: tx_hash.to_string(),
            code: serde_json::from_value(code[0].clone()).unwrap(),
            gas_used: serde_json::from_value(gas_used[0].clone()).unwrap(),
            initialized_accounts,
        }
    }
}
