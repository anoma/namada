use std::str::FromStr;

use namada_core::ledger::storage::LastBlock;
use namada_core::types::address::Address;
use namada_core::types::storage::BlockResults;
use namada_core::types::token;
use namada_sdk::error::Error;
use namada_sdk::queries::RPC;
use namada_sdk::rpc;
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::HttpClient;
use tokio::runtime::Runtime;

/// Query the address of the native token
pub fn query_native_token(tendermint_addr: &str) -> Result<Address, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    let rt = Runtime::new().unwrap();
    rt.block_on(rpc::query_native_token(&client))
}

/// Query the last committed block, if any.
pub fn query_block(tendermint_addr: &str) -> Result<Option<LastBlock>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    let rt = Runtime::new().unwrap();
    rt.block_on(rpc::query_block(&client))
}

/// Query the results of the last committed block
pub fn query_results(
    tendermint_addr: &str,
) -> Result<Vec<BlockResults>, Error> {
    let client = HttpClient::new(
        TendermintAddress::from_str(tendermint_addr)
            .map_err(|e| Error::Other(e.to_string()))?,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    let rt = Runtime::new().unwrap();
    rt.block_on(rpc::query_results(&client))
}

pub mod tx {
    use namada_sdk::events::Event;
    use namada_sdk::rpc::{TxEventQuery, TxResponse};

    use super::*;

    /// Call the corresponding `tx_event_query` RPC method, to fetch
    /// the current status of a transation.
    pub fn query_tx_events(
        tendermint_addr: &str,
        tx_hash: &str,
    ) -> Result<Option<Event>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        let tx_event_query = TxEventQuery::Applied(tx_hash);
        rt.block_on(rpc::query_tx_events(&client, tx_event_query))
            .map_err(|e| Error::Other(e.to_string()))
    }

    /// Dry run a transaction
    pub fn dry_run_tx(
        tendermint_addr: &str,
        tx_bytes: Vec<u8>,
    ) -> Result<namada_core::types::transaction::TxResult, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let (data, height, prove) = (Some(tx_bytes), None, false);
        let rt = Runtime::new().unwrap();
        let result = rt
            .block_on(RPC.shell().dry_run_tx(&client, data, height, prove))
            .map_err(|err| {
                Error::from(namada_sdk::error::QueryError::NoResponse(
                    err.to_string(),
                ))
            })?
            .data;
        println!("Dry-run result: {}", result);
        Ok(result)
    }

    /// Lookup the full response accompanying the specified transaction event
    pub fn query_tx_response(
        tendermint_addr: &str,
        tx_hash: &str,
    ) -> Result<TxResponse, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let tx_query = TxEventQuery::Applied(tx_hash);
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_tx_response(&client, tx_query))
            .map_err(|e| Error::Other(e.to_string()))
    }

    /// Query the status of a given transaction.
    pub async fn query_tx_status(
        tendermint_addr: &str,
        tx_hash: &str,
    ) -> Result<Event, Error> {
        let maybe_event = query_tx_events(tendermint_addr, tx_hash)?;
        if let Some(e) = maybe_event {
            Ok(e)
        } else {
            Err(Error::Tx(namada_sdk::error::TxError::AppliedTimeout))
        }
    }
}

pub mod governance {
    use namada_core::ledger::governance::parameters::GovernanceParameters;
    use namada_core::ledger::governance::storage::proposal::StorageProposal;
    use namada_core::ledger::governance::utils::Vote;

    use super::*;

    /// Query proposal by Id
    pub fn query_proposal_by_id(
        tendermint_addr: &str,
        proposal_id: u64,
    ) -> Result<Option<StorageProposal>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_proposal_by_id(&client, proposal_id))
    }

    /// Get the givernance parameters
    pub fn query_governance_parameters(
        tendermint_addr: &str,
    ) -> Result<GovernanceParameters, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        Ok(rt.block_on(rpc::query_governance_parameters(&client)))
    }

    /// Get the givernance parameters
    pub fn query_proposal_votes(
        tendermint_addr: &str,
        proposal_id: u64,
    ) -> Result<Vec<Vote>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_proposal_votes(&client, proposal_id))
    }
}

pub mod pos {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use namada_core::types::address::Address;
    use namada_core::types::key::common;
    use namada_core::types::storage::{BlockHeight, Epoch};
    use namada_sdk::proof_of_stake::types::{
        BondsAndUnbondsDetails, CommissionPair, ValidatorMetaData,
        ValidatorState,
    };
    use namada_sdk::proof_of_stake::PosParams;
    use namada_sdk::queries::vp::pos::EnrichedBondsAndUnbondsDetails;

    use super::*;

    /// Query the epoch of the last committed block
    pub fn query_epoch(tendermint_addr: &str) -> Result<Epoch, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_epoch(&client))
    }

    /// Query the epoch of the given block height, if it exists.
    /// Will return none if the input block height is greater than
    /// the latest committed block height.
    pub fn query_epoch_at_height(
        tendermint_addr: &str,
        height: BlockHeight,
    ) -> Result<Option<Epoch>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_epoch_at_height(&client, height))
    }

    /// Check if the given address is a known validator.
    pub fn is_validator(
        tendermint_addr: &str,
        address: &Address,
    ) -> Result<bool, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::is_validator(&client, address))
    }

    /// Check if a given address is a known delegator
    pub fn is_delegator(
        tendermint_addr: &str,
        address: &Address,
    ) -> Result<bool, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::is_delegator(&client, address))
    }

    /// Check if a given address is a known delegator at the given epoch
    pub fn is_delegator_at(
        tendermint_addr: &str,
        address: &Address,
        epoch: Epoch,
    ) -> Result<bool, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::is_delegator_at(&client, address, epoch))
    }

    /// Get the set of consensus keys registered in the network
    pub fn get_consensus_keys(
        tendermint_addr: &str,
    ) -> Result<BTreeSet<common::PublicKey>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_consensus_keys(&client))
    }

    /// Get the PoS parameters
    pub fn get_pos_params(tendermint_addr: &str) -> Result<PosParams, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_pos_params(&client))
    }

    /// Get all validators in the given epoch
    pub fn get_all_validators(
        tendermint_addr: &str,
        epoch: Epoch,
    ) -> Result<HashSet<Address>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_all_validators(&client, epoch))
    }

    /// Get the total staked tokens in the given epoch
    pub fn get_total_staked_tokens(
        tendermint_addr: &str,
        epoch: Epoch,
    ) -> Result<token::Amount, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_total_staked_tokens(&client, epoch))
    }

    /// Get the given validator's stake at the given epoch
    pub fn get_validator_stake(
        tendermint_addr: &str,
        epoch: Epoch,
        validator: &Address,
    ) -> Result<token::Amount, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_validator_stake(&client, epoch, validator))
    }

    /// Query and return a validator's state
    pub fn get_validator_state(
        tendermint_addr: &str,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Result<Option<ValidatorState>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_validator_state(&client, validator, epoch))
    }

    /// Get the delegator's delegation
    pub fn get_delegators_delegation(
        tendermint_addr: &str,
        address: &Address,
    ) -> Result<HashSet<Address>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_delegators_delegation(&client, address))
    }

    /// Get the delegator's delegation at some epoh
    pub fn get_delegators_delegation_at(
        tendermint_addr: &str,
        address: &Address,
        epoch: Epoch,
    ) -> Result<HashMap<Address, token::Amount>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_delegators_delegation_at(&client, address, epoch))
    }

    /// Query and return validator's commission rate and max commission rate
    /// change per epoch
    pub fn query_commission_rate(
        tendermint_addr: &str,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Result<Option<CommissionPair>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_commission_rate(&client, validator, epoch))
    }

    /// Query and return validator's metadata, including the commission rate and
    /// max commission rate change
    pub fn query_metadata(
        tendermint_addr: &str,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Result<(Option<ValidatorMetaData>, Option<CommissionPair>), Error>
    {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_metadata(&client, validator, epoch))
    }

    /// Query and return the incoming redelegation epoch for a given pair of
    /// source validator and delegator, if there is any.
    pub fn query_incoming_redelegations(
        tendermint_addr: &str,
        src_validator: &Address,
        delegator: &Address,
    ) -> Result<Option<Epoch>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_incoming_redelegations(
            &client,
            src_validator,
            delegator,
        ))
    }

    /// Query a validator's bonds for a given epoch
    pub fn query_bond(
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
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_bond(&client, source, validator, epoch))
    }

    /// Query a validator's unbonds for a given epoch
    pub fn query_and_print_unbonds(
        tendermint_addr: &str,
        source: &Address,
        validator: &Address,
    ) -> Result<(), Error> {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let unbonds =
                query_unbond_with_slashing(tendermint_addr, source, validator)?;
            let current_epoch = query_epoch(tendermint_addr)?;

            let mut total_withdrawable = token::Amount::zero();
            let mut not_yet_withdrawable =
                HashMap::<Epoch, token::Amount>::new();
            for ((_start_epoch, withdraw_epoch), amount) in unbonds.into_iter()
            {
                if withdraw_epoch <= current_epoch {
                    total_withdrawable += amount;
                } else {
                    let withdrawable_amount =
                        not_yet_withdrawable.entry(withdraw_epoch).or_default();
                    *withdrawable_amount += amount;
                }
            }
            if !total_withdrawable.is_zero() {
                println!(
                    "Total withdrawable now: {}.",
                    total_withdrawable.to_string_native()
                );
            }
            if !not_yet_withdrawable.is_empty() {
                println!("Current epoch: {current_epoch}.")
            }
            for (withdraw_epoch, amount) in not_yet_withdrawable {
                println!(
                    "Amount {} withdrawable starting from epoch \
                     {withdraw_epoch}.",
                    amount.to_string_native()
                );
            }
            Ok(())
        })
    }

    /// Query withdrawable tokens in a validator account for a given epoch
    pub fn query_withdrawable_tokens(
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
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_withdrawable_tokens(
            &client,
            bond_source,
            validator,
            epoch,
        ))
    }

    /// Query all unbonds for a validator, applying slashes
    pub fn query_unbond_with_slashing(
        tendermint_addr: &str,
        source: &Address,
        validator: &Address,
    ) -> Result<HashMap<(Epoch, Epoch), token::Amount>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::query_unbond_with_slashing(&client, source, validator))
    }

    /// Get the bond amount at the given epoch
    pub fn get_bond_amount_at(
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
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_bond_amount_at(
            &client, delegator, validator, epoch,
        ))
    }

    /// Get bonds and unbonds with all details (slashes and rewards, if any)
    /// grouped by their bond IDs.
    pub fn bonds_and_unbonds(
        tendermint_addr: &str,
        source: &Option<Address>,
        validator: &Option<Address>,
    ) -> Result<BondsAndUnbondsDetails, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::bonds_and_unbonds(&client, source, validator))
    }

    /// Get bonds and unbonds with all details (slashes and rewards, if any)
    /// grouped by their bond IDs, enriched with extra information calculated
    /// from the data.
    pub fn enriched_bonds_and_unbonds(
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
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::enriched_bonds_and_unbonds(
            &client,
            current_epoch,
            source,
            validator,
        ))
    }
}

pub mod account {
    use namada_core::types::account::Account;
    use namada_core::types::address::Address;
    use namada_core::types::key::common;

    use super::*;

    /// Query token amount of owner.
    pub fn get_token_balance(
        tendermint_addr: &str,
        token: &Address,
        owner: &Address,
    ) -> Result<token::Amount, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_token_balance(&client, token, owner))
    }

    /// Check if the address exists on chain. Established address exists if it
    /// has a stored validity predicate. Implicit and internal addresses
    /// always return true.
    pub fn known_address(
        tendermint_addr: &str,
        address: &Address,
    ) -> Result<bool, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::known_address(&client, address))
    }

    /// Query the accunt substorage space of an address
    pub fn get_account_info(
        tendermint_addr: &str,
        owner: &Address,
    ) -> Result<Option<Account>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_account_info(&client, owner))
    }

    /// Query if the public_key is revealed
    pub fn is_public_key_revealed(
        tendermint_addr: &str,
        owner: &Address,
    ) -> Result<bool, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::is_public_key_revealed(&client, owner))
    }

    /// Query an account substorage at a specific index
    pub fn get_public_key_at(
        tendermint_addr: &str,
        owner: &Address,
        index: u8,
    ) -> Result<Option<common::PublicKey>, Error> {
        let client = HttpClient::new(
            TendermintAddress::from_str(tendermint_addr)
                .map_err(|e| Error::Other(e.to_string()))?,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        let rt = Runtime::new().unwrap();
        rt.block_on(rpc::get_public_key_at(&client, owner, index))
    }
}

pub mod pgf {
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
        let rt = Runtime::new().unwrap();
        Ok(rt.block_on(rpc::is_steward(&client, address)))
    }
}
