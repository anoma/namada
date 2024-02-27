use std::collections::{BTreeSet, HashMap, HashSet};

use namada_sdk::key::common;
use namada_sdk::proof_of_stake::types::{
    BondsAndUnbondsDetails, CommissionPair, ValidatorMetaData, ValidatorState,
};
use namada_sdk::proof_of_stake::PosParams;
use namada_sdk::queries::vp::pos::EnrichedBondsAndUnbondsDetails;
use namada_sdk::storage::{BlockHeight, Epoch};

use super::*;

/// Query the epoch of the last committed block
pub async fn query_epoch(tendermint_addr: &str) -> Result<Epoch, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_epoch(&client).await
}

/// Query the epoch of the given block height, if it exists.
/// Will return none if the input block height is greater than
/// the latest committed block height.
pub async fn query_epoch_at_height(
    tendermint_addr: &str,
    height: BlockHeight,
) -> Result<Option<Epoch>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_epoch_at_height(&client, height).await
}

/// Check if the given address is a known validator.
pub async fn is_validator(
    tendermint_addr: &str,
    address: &Address,
) -> Result<bool, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::is_validator(&client, address).await
}

/// Check if a given address is a known delegator
pub async fn is_delegator(
    tendermint_addr: &str,
    address: &Address,
) -> Result<bool, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::is_delegator(&client, address).await
}

/// Check if a given address is a known delegator at the given epoch
pub async fn is_delegator_at(
    tendermint_addr: &str,
    address: &Address,
    epoch: Epoch,
) -> Result<bool, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::is_delegator_at(&client, address, epoch).await
}

/// Get the set of consensus keys registered in the network
pub async fn get_consensus_keys(
    tendermint_addr: &str,
) -> Result<BTreeSet<common::PublicKey>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_consensus_keys(&client).await
}

/// Get the PoS parameters
pub async fn get_pos_params(tendermint_addr: &str) -> Result<PosParams, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_pos_params(&client).await
}

/// Get all validators in the given epoch
pub async fn get_all_validators(
    tendermint_addr: &str,
    epoch: Epoch,
) -> Result<HashSet<Address>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_all_validators(&client, epoch).await
}

/// Get the total staked tokens in the given epoch
pub async fn get_total_staked_tokens(
    tendermint_addr: &str,
    epoch: Epoch,
) -> Result<token::Amount, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_total_staked_tokens(&client, epoch).await
}

/// Get the given validator's stake at the given epoch
pub async fn get_validator_stake(
    tendermint_addr: &str,
    epoch: Epoch,
    validator: &Address,
) -> Result<token::Amount, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_validator_stake(&client, epoch, validator).await
}

/// Query and return a validator's state
pub async fn get_validator_state(
    tendermint_addr: &str,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<Option<ValidatorState>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_validator_state(&client, validator, epoch).await
}

/// Get the delegator's delegation
pub async fn get_delegators_delegation(
    tendermint_addr: &str,
    address: &Address,
) -> Result<HashSet<Address>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_delegators_delegation(&client, address).await
}

/// Get the delegator's delegation at some epoh
pub async fn get_delegators_delegation_at(
    tendermint_addr: &str,
    address: &Address,
    epoch: Epoch,
) -> Result<HashMap<Address, token::Amount>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_delegators_delegation_at(&client, address, epoch).await
}

/// Query and return validator's commission rate and max commission rate
/// change per epoch
pub async fn query_commission_rate(
    tendermint_addr: &str,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<Option<CommissionPair>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_commission_rate(&client, validator, epoch).await
}

/// Query and return validator's metadata, including the commission rate and
/// max commission rate change
pub async fn query_metadata(
    tendermint_addr: &str,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<(Option<ValidatorMetaData>, Option<CommissionPair>), Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_metadata(&client, validator, epoch).await
}

/// Query and return the incoming redelegation epoch for a given pair of
/// source validator and delegator, if there is any.
pub async fn query_incoming_redelegations(
    tendermint_addr: &str,
    src_validator: &Address,
    delegator: &Address,
) -> Result<Option<Epoch>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_incoming_redelegations(&client, src_validator, delegator).await
}

/// Query a validator's bonds for a given epoch
pub async fn query_bond(
    tendermint_addr: &str,
    source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<token::Amount, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_bond(&client, source, validator, epoch).await
}

/// Query withdrawable tokens in a validator account for a given epoch
pub async fn query_withdrawable_tokens(
    tendermint_addr: &str,
    bond_source: &Address,
    validator: &Address,
    epoch: Option<Epoch>,
) -> Result<token::Amount, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_withdrawable_tokens(&client, bond_source, validator, epoch).await
}

/// Query all unbonds for a validator, applying slashes
pub async fn query_unbond_with_slashing(
    tendermint_addr: &str,
    source: &Address,
    validator: &Address,
) -> Result<HashMap<(Epoch, Epoch), token::Amount>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::query_unbond_with_slashing(&client, source, validator).await
}

/// Get the bond amount at the given epoch
pub async fn get_bond_amount_at(
    tendermint_addr: &str,
    delegator: &Address,
    validator: &Address,
    epoch: Epoch,
) -> Result<token::Amount, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::get_bond_amount_at(&client, delegator, validator, epoch).await
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs.
pub async fn bonds_and_unbonds(
    tendermint_addr: &str,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> Result<BondsAndUnbondsDetails, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::bonds_and_unbonds(&client, source, validator).await
}

/// Get bonds and unbonds with all details (slashes and rewards, if any)
/// grouped by their bond IDs, enriched with extra information calculated
/// from the data.
pub async fn enriched_bonds_and_unbonds(
    tendermint_addr: &str,
    current_epoch: Epoch,
    source: &Option<Address>,
    validator: &Option<Address>,
) -> Result<EnrichedBondsAndUnbondsDetails, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    rpc::enriched_bonds_and_unbonds(&client, current_epoch, source, validator)
        .await
}
