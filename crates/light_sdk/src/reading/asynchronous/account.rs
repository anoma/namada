use namada_sdk::account::Account;
use namada_sdk::key::common;

use super::*;

/// Query token amount of owner.
pub async fn get_token_balance(
    tendermint_addr: &str,
    token: &Address,
    owner: &Address,
) -> Result<token::Amount, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_token_balance(&client, token, owner).await
}

/// Check if the address exists on chain. Established address exists if it
/// has a stored validity predicate. Implicit and internal addresses
/// always return true.
pub async fn known_address(
    tendermint_addr: &str,
    address: &Address,
) -> Result<bool, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::known_address(&client, address).await
}

/// Query the accunt substorage space of an address
pub async fn get_account_info(
    tendermint_addr: &str,
    owner: &Address,
) -> Result<Option<Account>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_account_info(&client, owner).await
}

/// Query if the public_key is revealed
pub async fn is_public_key_revealed(
    tendermint_addr: &str,
    owner: &Address,
) -> Result<bool, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::is_public_key_revealed(&client, owner).await
}

/// Query an account substorage at a specific index
pub async fn get_public_key_at(
    tendermint_addr: &str,
    owner: &Address,
    index: u8,
) -> Result<Option<common::PublicKey>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_public_key_at(&client, owner, index).await
}
