use std::collections::HashMap;

use namada::core::ledger::governance::storage::keys as gov_storage;
use namada::core::ledger::governance::storage::proposal::{
    AddRemove, PGFAction, ProposalType,
};
use namada::core::ledger::governance::utils::{
    compute_proposal_result, ProposalVotes, TallyResult, TallyType, TallyVote,
    VotePower,
};
use namada::core::ledger::governance::ADDRESS as gov_address;
use namada::core::ledger::storage_api::governance as gov_api;
use namada::ledger::governance::utils::ProposalEvent;
use namada::ledger::pos::BondId;
use namada::ledger::protocol;
use namada::ledger::storage::types::encode;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::ledger::storage_api::{token, StorageWrite};
use namada::proof_of_stake::parameters::PosParams;
use namada::proof_of_stake::{
    bond_amount, read_total_stake, read_validator_stake,
};
use namada::types::address::Address;
use namada::types::storage::Epoch;

use super::*;

#[derive(Default)]
pub struct ProposalsResult {
    passed: Vec<u64>,
    rejected: Vec<u64>,
}

pub fn execute_governance_proposals<D, H>(
    shell: &mut Shell<D, H>,
    response: &mut shim::response::FinalizeBlock,
) -> Result<ProposalsResult>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let mut proposals_result = ProposalsResult::default();

    for id in std::mem::take(&mut shell.proposal_data) {
        let proposal_funds_key = gov_storage::get_funds_key(id);
        let proposal_end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
        let proposal_type_key = gov_storage::get_proposal_type_key(id);

        let funds: token::Amount =
            force_read(&shell.wl_storage, &proposal_funds_key)?;
        let proposal_end_epoch: Epoch =
            force_read(&shell.wl_storage, &proposal_end_epoch_key)?;
        let proposal_type: ProposalType =
            force_read(&shell.wl_storage, &proposal_type_key)?;

        let params = read_pos_params(&shell.wl_storage)?;
        let total_voting_power =
            read_total_stake(&shell.wl_storage, &params, proposal_end_epoch)?;

        let tally_type = TallyType::from(proposal_type.clone());
        let votes = compute_proposal_votes(
            &shell.wl_storage,
            &params,
            id,
            proposal_end_epoch,
        )?;
        let proposal_result = compute_proposal_result(
            votes,
            total_voting_power.into(),
            tally_type,
        );

        let transfer_address = match proposal_result.result {
            TallyResult::Passed => {
                let proposal_event = match proposal_type {
                    ProposalType::Default(code) => {
                        let result =
                            execute_default_proposal(shell, id, code.clone())?;

                        ProposalEvent::default_proposal_event(
                            id,
                            code.is_some(),
                            result,
                        )
                        .into()
                    }
                    ProposalType::PGFSteward(stewards) => {
                        let _result =
                            execute_pgf_steward_proposal(id, stewards);
                        ProposalEvent::pgf_steward_proposal_event(id).into()
                    }
                    ProposalType::PGFPayment(payments) => {
                        let _result =
                            execute_pgf_payment_proposal(id, payments);
                        ProposalEvent::pgf_payments_proposal_event(id).into()
                    }
                    ProposalType::ETHBridge(_data) => {
                        let _result = execute_eth_proposal(id);
                        ProposalEvent::eth_proposal_event(id).into()
                    }
                };
                response.events.push(proposal_event);
                proposals_result.passed.push(id);

                let proposal_author_key = gov_storage::get_author_key(id);
                shell.wl_storage.read::<Address>(&proposal_author_key)?
            }
            TallyResult::Rejected => {
                let proposal_event =
                    ProposalEvent::rejected_proposal_event(id).into();
                response.events.push(proposal_event);
                proposals_result.rejected.push(id);

                None
            }
        };

        let native_token = shell.wl_storage.storage.native_token.clone();
        if let Some(address) = transfer_address {
            token::transfer(
                &mut shell.wl_storage,
                &native_token,
                &gov_address,
                &address,
                funds,
            )?;
        } else {
            token::burn(
                &mut shell.wl_storage,
                &native_token,
                &gov_address,
                funds,
            )?;
        }
    }

    Ok(proposals_result)
}

pub fn force_read<S, T>(storage: &S, key: &Key) -> storage_api::Result<T>
where
    S: StorageRead,
    T: BorshDeserialize,
{
    storage
        .read::<T>(key)
        .transpose()
        .expect("Storage key must be present.")
}

fn compute_proposal_votes<S>(
    storage: &S,
    params: &PosParams,
    proposal_id: u64,
    epoch: Epoch,
) -> storage_api::Result<ProposalVotes>
where
    S: StorageRead,
{
    let votes = gov_api::get_proposal_votes(storage, proposal_id)?;

    let mut validators_vote: HashMap<Address, TallyVote> = HashMap::default();
    let mut validator_voting_power: HashMap<Address, VotePower> =
        HashMap::default();
    let mut delegators_vote: HashMap<Address, TallyVote> = HashMap::default();
    let mut delegator_voting_power: HashMap<
        Address,
        HashMap<Address, VotePower>,
    > = HashMap::default();

    for vote in votes {
        if vote.is_validator() {
            let validator = vote.validator.clone();
            let vote_data = vote.data.clone();

            let validator_stake =
                get_validator_stake_at(storage, params, &validator, epoch);

            validators_vote.insert(validator.clone(), vote_data.into());
            validator_voting_power.insert(validator, validator_stake.into());
        } else {
            let validator = vote.validator.clone();
            let delegator = vote.delegator.clone();
            let vote_data = vote.data.clone();

            let delegator_stake = get_delegator_bond_at(
                storage, params, &validator, &delegator, epoch,
            );

            delegators_vote.insert(delegator.clone(), vote_data.into());
            delegator_voting_power
                .entry(delegator)
                .or_default()
                .insert(validator, delegator_stake.into());
        }
    }

    Ok(ProposalVotes {
        validators_vote,
        validator_voting_power,
        delegators_vote,
        delegator_voting_power,
    })
}

fn get_validator_stake_at<S>(
    storage: &S,
    pos_params: &PosParams,
    validator: &Address,
    epoch: Epoch,
) -> token::Amount
where
    S: StorageRead,
{
    match read_validator_stake(storage, pos_params, validator, epoch) {
        Ok(stake) => stake.unwrap_or_default(),
        Err(_) => token::Amount::default(),
    }
}

fn get_delegator_bond_at<S>(
    storage: &S,
    pos_params: &PosParams,
    validator: &Address,
    delegator: &Address,
    epoch: Epoch,
) -> token::Amount
where
    S: StorageRead,
{
    let bond_id = BondId {
        source: delegator.clone(),
        validator: validator.clone(),
    };
    let (_, bound_amount) =
        bond_amount(storage, pos_params, &bond_id, epoch).unwrap_or_default();

    bound_amount
}

fn execute_default_proposal<D, H>(
    shell: &mut Shell<D, H>,
    id: u64,
    proposal_code: Option<Vec<u8>>,
) -> storage_api::Result<bool>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    if let Some(code) = proposal_code {
        let pending_execution_key = gov_storage::get_proposal_execution_key(id);
        shell.wl_storage.write(&pending_execution_key, ())?;

        let tx = Tx::new(code, Some(encode(&id)), shell.chain_id.clone(), None);
        let tx_type = TxType::Decrypted(DecryptedTx::Decrypted {
            tx,
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        });
        //  0 parameter is used to compute the fee
        // based on the code size. We dont
        // need it here.
        let tx_result = protocol::apply_tx(
            tx_type,
            0,
            TxIndex::default(),
            &mut BlockGasMeter::default(),
            &mut shell.wl_storage.write_log,
            &shell.wl_storage.storage,
            &mut shell.vp_wasm_cache,
            &mut shell.tx_wasm_cache,
        );
        shell
            .wl_storage
            .storage
            .delete(&pending_execution_key)
            .expect("Should be able to delete the storage.");
        match tx_result {
            Ok(tx_result) => {
                if tx_result.is_accepted() {
                    shell.wl_storage.commit_tx();
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => {
                shell.wl_storage.drop_tx();
                Ok(false)
            }
        }
    } else {
        Ok(true)
    }
}

fn execute_pgf_steward_proposal(
    _id: u64,
    _stewards: HashSet<AddRemove<Address>>,
) -> bool {
    true
}

fn execute_pgf_payment_proposal(_id: u64, _actions: Vec<PGFAction>) -> bool {
    true
}

fn execute_eth_proposal(_id: u64) -> bool {
    true
}
