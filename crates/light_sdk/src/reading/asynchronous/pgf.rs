use super::*;

/// Check if the given address is a pgf steward.
pub async fn is_steward(
    tendermint_addr: &str,
    address: &Address,
) -> Result<bool, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    Ok(rpc::is_steward(&client, address).await)
}
