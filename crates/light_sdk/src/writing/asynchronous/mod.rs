use std::str::FromStr;

use namada_sdk::error::{EncodingError, Error, TxSubmitError};
use namada_sdk::queries::Client;
use namada_sdk::tx::Tx;
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use tendermint_rpc::error::Error as RpcError;
use tendermint_rpc::HttpClient;

/// Broadcast a transaction to be included in the blockchain. This
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx with encrypted payload has been included on the blockchain
/// 3. The decrypted payload of the tx has been included on the blockchain.
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

    let wrapper_tx_hash = tx.header_hash().to_string();
    // We use this to determine when the decrypted inner tx makes it
    // on-chain
    let decrypted_tx_hash = tx.raw_header_hash().to_string();

    // TODO: configure an explicit timeout value? we need to hack away at
    // `tendermint-rs` for this, which is currently using a hard-coded 30s
    // timeout.
    let response = client
        .broadcast_tx_sync(tx.to_bytes())
        .await
        .map_err(|e| Error::from(TxSubmitError::TxBroadcast(e)))?;

    if response.code == 0.into() {
        println!("Transaction added to mempool: {:?}", response);
        // Print the transaction identifiers to enable the extraction of
        // acceptance/application results later
        {
            println!("Wrapper transaction hash: {:?}", wrapper_tx_hash);
            println!("Inner transaction hash: {:?}", decrypted_tx_hash);
        }
        Ok(response)
    } else {
        Err(Error::from(TxSubmitError::TxBroadcast(RpcError::server(
            serde_json::to_string(&response).map_err(|err| {
                Error::from(EncodingError::Serde(err.to_string()))
            })?,
        ))))
    }
}
