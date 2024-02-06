use std::str::FromStr;

use namada_sdk::address::Address;
use namada_sdk::error::{EncodingError, Error};
use namada_sdk::io::StdIo;
use namada_sdk::queries::RPC;
use namada_sdk::rpc;
use namada_sdk::state::LastBlock;
use namada_sdk::storage::BlockResults;
use namada_sdk::token::{self, DenominatedAmount};
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::HttpClient;

pub mod account;
pub mod governance;
pub mod pgf;
pub mod pos;
pub mod tx;

/// Query the address of the native token
pub async fn query_native_token(
    tendermint_addr: &str,
) -> Result<Address, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_native_token(&client).await
}

/// Query the last committed block, if any.
pub async fn query_block(
    tendermint_addr: &str,
) -> Result<Option<LastBlock>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_block(&client).await
}

/// Query the results of the last committed block
pub async fn query_results(
    tendermint_addr: &str,
) -> Result<Vec<BlockResults>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_results(&client).await
}

/// Get a properly denominated amount of a token
pub async fn denominate_amount(
    tendermint_addr: &str,
    amount: u64,
    token: &str,
) -> Result<DenominatedAmount, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    let token = Address::decode(token)
        .map_err(|e| Error::Encode(EncodingError::Decoding(e.to_string())))?;
    Ok(rpc::denominate_amount(
        &client,
        &StdIo {},
        &token,
        token::Amount::from(amount),
    )
    .await)
}
