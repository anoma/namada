use std::collections::HashMap;

use namada::governance::pgf::storage::keys as pgf_storage;
use namada::governance::pgf::storage::steward::StewardDetail;
use namada::governance::pgf::{storage as pgf, ADDRESS};
use namada::governance::storage::keys as gov_storage;
use namada::governance::storage::proposal::{
    AddRemove, PGFAction, ProposalType, StoragePgfFunding,
};
use namada::governance::utils::{
    compute_proposal_result, ProposalVotes, TallyResult, TallyType, TallyVote,
    VotePower,
};
use namada::governance::{storage as gov_api, ADDRESS as gov_address};
use namada::ledger::governance::utils::ProposalEvent;
use namada::ledger::pos::BondId;
use namada::ledger::protocol;
use namada::proof_of_stake::bond_amount;
use namada::proof_of_stake::parameters::PosParams;
use namada::proof_of_stake::storage::read_total_stake;
use namada::state::{DBIter, StorageHasher, StorageWrite, DB};
use namada::token;
use namada::tx::{Code, Data};
use namada::types::address::Address;
use namada::types::encode;
use namada::types::storage::Epoch;

use super::utils::force_read;
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
        let proposal_author_key = gov_storage::get_author_key(id);

        let funds: token::Amount =
            force_read(&shell.wl_storage, &proposal_funds_key)?;
        let proposal_end_epoch: Epoch =
            force_read(&shell.wl_storage, &proposal_end_epoch_key)?;
        let proposal_type: ProposalType =
            force_read(&shell.wl_storage, &proposal_type_key)?;
        let proposal_author: Address =
            force_read(&shell.wl_storage, &proposal_author_key)?;

        let is_steward = pgf::is_steward(&shell.wl_storage, &proposal_author)?;

        let params = read_pos_params(&shell.wl_storage)?;
        let total_voting_power =
            read_total_stake(&shell.wl_storage, &params, proposal_end_epoch)?;

        let tally_type = TallyType::from(proposal_type.clone(), is_steward);
        let votes = compute_proposal_votes(
            &shell.wl_storage,
            &params,
            id,
            proposal_end_epoch,
        )?;
        let proposal_result =
            compute_proposal_result(votes, total_voting_power, tally_type);
        let proposal_result_key = gov_storage::get_proposal_result_key(id);
        shell
            .wl_storage
            .write(&proposal_result_key, proposal_result)?;

        let transfer_address = match proposal_result.result {
            TallyResult::Passed => {
                let proposal_event = match proposal_type {
                    ProposalType::Default(_) => {
                        let proposal_code_key =
                            gov_storage::get_proposal_code_key(id);
                        let proposal_code =
                            shell.wl_storage.read_bytes(&proposal_code_key)?;
                        let result = execute_default_proposal(
                            shell,
                            id,
                            proposal_code.clone(),
                        )?;
                        tracing::info!(
                            "Governance proposal (default) {} has been \
                             executed ({}) and passed.",
                            id,
                            result
                        );

                        ProposalEvent::default_proposal_event(
                            id,
                            proposal_code.is_some(),
                            result,
                        )
                        .into()
                    }
                    ProposalType::PGFSteward(stewards) => {
                        let result = execute_pgf_steward_proposal(
                            &mut shell.wl_storage,
                            stewards,
                        )?;
                        tracing::info!(
                            "Governance proposal (pgf stewards){} has been \
                             executed and passed.",
                            id
                        );

                        ProposalEvent::pgf_steward_proposal_event(id, result)
                            .into()
                    }
                    ProposalType::PGFPayment(payments) => {
                        let native_token =
                            &shell.wl_storage.get_native_token()?;
                        let result = execute_pgf_payment_proposal(
                            &mut shell.wl_storage,
                            native_token,
                            payments,
                            id,
                        )?;
                        tracing::info!(
                            "Governance proposal (pgf funding) {} has been \
                             executed and passed.",
                            id
                        );

                        ProposalEvent::pgf_payments_proposal_event(id, result)
                            .into()
                    }
                };
                response.events.push(proposal_event);
                proposals_result.passed.push(id);

                let proposal_author_key = gov_storage::get_author_key(id);
                shell.wl_storage.read::<Address>(&proposal_author_key)?
            }
            TallyResult::Rejected => {
                if let ProposalType::PGFPayment(_) = proposal_type {
                    if proposal_result.two_thirds_nay_over_two_thirds_total() {
                        pgf::remove_steward(
                            &mut shell.wl_storage,
                            &proposal_author,
                        )?;

                        tracing::info!(
                            "Governance proposal {} was rejected with 2/3 of \
                             nay votes over 2/3 of the total voting power. If \
                             {} is a steward, it's being removed from the \
                             stewards set.",
                            id,
                            proposal_author
                        );
                    }
                }
                let proposal_event =
                    ProposalEvent::rejected_proposal_event(id).into();
                response.events.push(proposal_event);
                proposals_result.rejected.push(id);

                tracing::info!(
                    "Governance proposal {} has been executed and rejected.",
                    id
                );

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

fn compute_proposal_votes<S>(
    storage: &S,
    params: &PosParams,
    proposal_id: u64,
    epoch: Epoch,
) -> namada::state::StorageResult<ProposalVotes>
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
                read_total_stake(storage, params, epoch).unwrap_or_default();

            validators_vote.insert(validator.clone(), vote_data.into());
            validator_voting_power.insert(validator, validator_stake);
        } else {
            let validator = vote.validator.clone();
            let delegator = vote.delegator.clone();
            let vote_data = vote.data.clone();

            let bond_id = BondId {
                source: delegator.clone(),
                validator: validator.clone(),
            };
            let delegator_stake =
                bond_amount(storage, &bond_id, epoch).unwrap_or_default();

            delegators_vote.insert(delegator.clone(), vote_data.into());
            delegator_voting_power
                .entry(delegator)
                .or_default()
                .insert(validator, delegator_stake);
        }
    }

    Ok(ProposalVotes {
        validators_vote,
        validator_voting_power,
        delegators_vote,
        delegator_voting_power,
    })
}

fn execute_default_proposal<D, H>(
    shell: &mut Shell<D, H>,
    id: u64,
    proposal_code: Option<Vec<u8>>,
) -> namada::state::StorageResult<bool>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    if let Some(code) = proposal_code {
        let pending_execution_key = gov_storage::get_proposal_execution_key(id);
        shell.wl_storage.write(&pending_execution_key, ())?;

        let mut tx = Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_data(Data::new(encode(&id)));
        tx.set_code(Code::new(code, None));

        let tx_result = protocol::dispatch_tx(
            tx,
            &[], /*  this is used to compute the fee
                  * based on the code size. We dont
                  * need it here. */
            TxIndex::default(),
            &mut TxGasMeter::new_from_sub_limit(u64::MAX.into()), /* No gas limit for governance proposal */
            &mut shell.wl_storage,
            &mut shell.vp_wasm_cache,
            &mut shell.tx_wasm_cache,
            None,
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
        tracing::info!(
            "Governance proposal {} doesn't have any associated proposal code.",
            id
        );
        Ok(true)
    }
}

fn execute_pgf_steward_proposal<S>(
    storage: &mut S,
    stewards: HashSet<AddRemove<Address>>,
) -> Result<bool>
where
    S: StorageRead + StorageWrite,
{
    for action in stewards {
        match action {
            AddRemove::Add(address) => {
                pgf_storage::stewards_handle().insert(
                    storage,
                    address.to_owned(),
                    StewardDetail::base(address),
                )?;
            }
            AddRemove::Remove(address) => {
                pgf_storage::stewards_handle().remove(storage, &address)?;
            }
        }
    }

    Ok(true)
}

fn execute_pgf_payment_proposal<S>(
    storage: &mut S,
    token: &Address,
    payments: Vec<PGFAction>,
    proposal_id: u64,
) -> Result<bool>
where
    S: StorageRead + StorageWrite,
{
    for payment in payments {
        match payment {
            PGFAction::Continuous(action) => match action {
                AddRemove::Add(target) => {
                    pgf_storage::fundings_handle().insert(
                        storage,
                        target.target.clone(),
                        StoragePgfFunding::new(target.clone(), proposal_id),
                    )?;
                    tracing::info!(
                        "Execute ContinousPgf from proposal id {}: set {} to \
                         {}.",
                        proposal_id,
                        target.amount.to_string_native(),
                        target.target
                    );
                }
                AddRemove::Remove(target) => {
                    pgf_storage::fundings_handle()
                        .remove(storage, &target.target)?;
                    tracing::info!(
                        "Execute ContinousPgf from proposal id {}: set {} to \
                         {}.",
                        proposal_id,
                        target.amount.to_string_native(),
                        target.target
                    );
                }
            },
            PGFAction::Retro(target) => {
                match token::transfer(
                    storage,
                    token,
                    &ADDRESS,
                    &target.target,
                    target.amount,
                ) {
                    Ok(()) => tracing::info!(
                        "Execute RetroPgf from proposal id {}: sent {} to {}.",
                        proposal_id,
                        target.amount.to_string_native(),
                        target.target
                    ),
                    Err(e) => tracing::warn!(
                        "Error in RetroPgf transfer from proposal id {}, \
                         amount {} to {}: {}",
                        proposal_id,
                        target.amount.to_string_native(),
                        target.target,
                        e
                    ),
                }
            }
        }
    }

    Ok(true)
}
