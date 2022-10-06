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
        let events = event
            .events
            .expect("We should have obtained Tx events from the RPC");
        let evt_key = event_type.to_string();
        // Find the tx with a matching hash
        macro_rules! tx_error {
            () => {
                || {
                    eprintln!(
                        "Couldn't find tx with hash {tx_hash} in events \
                         {events:?}",
                    );
                    safe_exit(1)
                }
            };
        }
        let (index, _) = events
            .get(&format!("{evt_key}.hash"))
            .unwrap_or_else(tx_error!())
            .iter()
            .enumerate()
            .find(|(_, hash)| hash == &tx_hash)
            .unwrap_or_else(tx_error!());
        let info = events[&format!("{evt_key}.info")][index].clone();
        let log = events[&format!("{evt_key}.log")][index].clone();
        let height = events[&format!("{evt_key}.height")][index].clone();
        let code = events[&format!("{evt_key}.code")][index].clone();
        let gas_used = events[&format!("{evt_key}.gas_used")][index].clone();
        let initialized_accounts = events
            [&format!("{evt_key}.initialized_accounts")]
            .get(index)
            .as_ref()
            .map(|initialized_accounts| {
                serde_json::from_str(initialized_accounts).unwrap()
            })
            .unwrap_or_else(|| {
                eprintln!(
                    "Tendermint omitted one of the expected indices in events"
                );
                Vec::new()
            });
        TxResponse {
            info,
            log,
            height,
            code,
            gas_used,
            initialized_accounts,
            hash: tx_hash.to_string(),
        }
    }
}
