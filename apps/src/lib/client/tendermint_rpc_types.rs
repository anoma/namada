use std::convert::TryFrom;

use namada::proto::Tx;
use namada::types::address::Address;
use serde::Serialize;

use crate::cli::safe_exit;
use crate::node::ledger::events::Event;

/// Data needed for broadcasting a tx and
/// monitoring its progress on chain
///
/// Txs may be either a dry run or else
/// they should be encrypted and included
/// in a wrapper.
#[derive(Debug, Clone)]
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

impl TryFrom<Event> for TxResponse {
    type Error = String;

    fn try_from(event: Event) -> Result<Self, Self::Error> {
        fn missing_field_err(field: &str) -> String {
            format!("Field \"{field}\" not present in event")
        }

        let hash = event
            .get("hash")
            .ok_or_else(|| missing_field_err("hash"))?
            .clone();
        let info = event
            .get("info")
            .ok_or_else(|| missing_field_err("info"))?
            .clone();
        let log = event
            .get("log")
            .ok_or_else(|| missing_field_err("log"))?
            .clone();
        let height = event
            .get("height")
            .ok_or_else(|| missing_field_err("height"))?
            .clone();
        let code = event
            .get("code")
            .ok_or_else(|| missing_field_err("code"))?
            .clone();
        let gas_used = event
            .get("gas_used")
            .ok_or_else(|| missing_field_err("gas_used"))?
            .clone();
        let initialized_accounts = event
            .get("initialized_accounts")
            .map(String::as_str)
            // TODO: fix finalize block, to return initialized accounts,
            // even when we reject a tx?
            .or(Some("[]"))
            // NOTE: at this point we only have `Some(vec)`, not `None`
            .ok_or_else(|| unreachable!())
            .and_then(|initialized_accounts| {
                serde_json::from_str(initialized_accounts)
                    .map_err(|err| format!("JSON decode error: {err}"))
            })?;

        Ok(TxResponse {
            hash,
            info,
            log,
            height,
            code,
            gas_used,
            initialized_accounts,
        })
    }
}

impl TxResponse {
    /// Convert an [`Event`] to a [`TxResponse`], or error out.
    pub fn from_event(event: Event) -> Self {
        event.try_into().unwrap_or_else(|err| {
            eprintln!("Error fetching TxResponse: {err}");
            safe_exit(1);
        })
    }
}
