use namada_sdk::events::Event;
use namada_sdk::rpc::{TxEventQuery, TxResponse};
use namada_sdk::tx::data::TxResult;

use super::*;

/// Call the corresponding `tx_event_query` RPC method, to fetch
/// the current status of a transation.
pub async fn query_tx_events(
    tendermint_addr: &str,
    tx_hash: &str,
) -> Result<Option<Event>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    let tx_event_query = TxEventQuery::Applied(tx_hash);
    rpc::query_tx_events(&client, tx_event_query)
        .await
        .map_err(|e| Error::Other(e.to_string()))
}

/// Dry run a transaction
pub async fn dry_run_tx(
    tendermint_addr: &str,
    tx_bytes: Vec<u8>,
) -> Result<TxResult, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    let (data, height, prove) = (Some(tx_bytes), None, false);
    let result = RPC
        .shell()
        .dry_run_tx(&client, data, height, prove)
        .await
        .map_err(|err| {
            Error::from(namada_sdk::error::QueryError::NoResponse(
                err.to_string(),
            ))
        })?
        .data;
    Ok(result)
}

/// Lookup the full response accompanying the specified transaction event
pub async fn query_tx_response(
    tendermint_addr: &str,
    tx_hash: &str,
) -> Result<TxResponse, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    let tx_query = TxEventQuery::Applied(tx_hash);
    rpc::query_tx_response(&client, tx_query)
        .await
        .map_err(|e| Error::Other(e.to_string()))
}

/// Query the status of a given transaction.
pub async fn query_tx_status(
    tendermint_addr: &str,
    tx_hash: &str,
) -> Result<Event, Error> {
    let maybe_event = query_tx_events(tendermint_addr, tx_hash).await?;
    if let Some(e) = maybe_event {
        Ok(e)
    } else {
        Err(Error::Tx(namada_sdk::error::TxSubmitError::AppliedTimeout))
    }
}
