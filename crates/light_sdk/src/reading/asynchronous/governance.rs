use namada_sdk::governance::parameters::GovernanceParameters;
use namada_sdk::governance::storage::proposal::StorageProposal;
use namada_sdk::governance::utils::Vote;

use super::*;

/// Query proposal by Id
pub async fn query_proposal_by_id(
    tendermint_addr: &str,
    proposal_id: u64,
) -> Result<Option<StorageProposal>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_proposal_by_id(&client, proposal_id).await
}

/// Get the givernance parameters
pub async fn query_governance_parameters(
    tendermint_addr: &str,
) -> Result<GovernanceParameters, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    Ok(rpc::query_governance_parameters(&client).await)
}

/// Get the givernance parameters
pub async fn query_proposal_votes(
    tendermint_addr: &str,
    proposal_id: u64,
) -> Result<Vec<Vote>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_proposal_votes(&client, proposal_id).await
}
