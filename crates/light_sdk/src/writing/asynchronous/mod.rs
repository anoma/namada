use std::str::FromStr;

use namada_sdk::error::{EncodingError, Error, TxSubmitError};
use namada_sdk::io::Client;
use namada_sdk::tx::Tx;
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use tendermint_rpc::error::Error as RpcError;
use tendermint_rpc::HttpClient;

/// Broadcast a transaction to be included in the blockchain. This
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx has been included on the blockchain
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx(
    tendermint_addr: &str,
    tx: Tx,
) -> Result<Response, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    // NOTE: if we need an explicit client timeout, use
    // `HttpClient::builder` to instantiate client
    let response = client
        .broadcast_tx_sync(tx.to_bytes())
        .await
        .map_err(|e| Error::from(TxSubmitError::TxBroadcast(e)))?;

    if response.code == 0.into() {
        Ok(response)
    } else {
        Err(Error::from(TxSubmitError::TxBroadcast(RpcError::server(
            serde_json::to_string(&response).map_err(|err| {
                Error::from(EncodingError::Serde(err.to_string()))
            })?,
        ))))
    }
}
