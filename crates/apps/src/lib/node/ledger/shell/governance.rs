use namada::core::collections::HashMap;
use namada::core::encode;
use namada::core::storage::Epoch;
use namada::governance::event::GovernanceEvent;
use namada::governance::pgf::storage::keys as pgf_storage;
use namada::governance::pgf::storage::steward::StewardDetail;
use namada::governance::pgf::{storage as pgf, ADDRESS};
use namada::governance::storage::proposal::{
    AddRemove, PGFAction, PGFTarget, ProposalType, StoragePgfFunding,
};
use namada::governance::storage::{keys as gov_storage, load_proposals};
use namada::governance::utils::{
    compute_proposal_result, ProposalVotes, TallyResult, TallyType, VotePower,
};
use namada::governance::{
    storage as gov_api, ProposalVote, ADDRESS as gov_address,
};
use namada::ibc;
use namada::ledger::events::extend::{ComposeEvent, Height};
use namada::proof_of_stake::bond_amount;
use namada::proof_of_stake::parameters::PosParams;
use namada::proof_of_stake::storage::{
    read_total_active_stake, validator_state_handle,
};
use namada::proof_of_stake::types::{BondId, ValidatorState};
use namada::sdk::events::{EmitEvents, EventLevel};
use namada::state::StorageWrite;
use namada::token::event::{TokenEvent, TokenOperation, UserAccount};
use namada::token::read_balance;
use namada::tx::{Code, Data};
use namada_sdk::proof_of_stake::storage::read_validator_stake;

use super::utils::force_read;
use super::*;

pub fn finalize_block<D, H>(
    shell: &mut Shell<D, H>,
    events: &mut impl EmitEvents,
    current_epoch: Epoch,
    is_new_epoch: bool,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if is_new_epoch {
        load_and_execute_governance_proposals(shell, events, current_epoch)?;
    }
    Ok(())
}

#[derive(Default)]
pub struct ProposalsResult {
    passed: Vec<u64>,
    rejected: Vec<u64>,
}

pub fn load_and_execute_governance_proposals<D, H>(
    shell: &mut Shell<D, H>,
    events: &mut impl EmitEvents,
    current_epoch: Epoch,
) -> Result<ProposalsResult>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let proposal_ids = load_proposals(&shell.state, current_epoch)?;

    let proposals_result =
        execute_governance_proposals(shell, events, proposal_ids)?;

    Ok(proposals_result)
}

fn execute_governance_proposals<D, H>(
    shell: &mut Shell<D, H>,
    events: &mut impl EmitEvents,
    proposal_ids: BTreeSet<u64>,
) -> Result<ProposalsResult>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let mut proposals_result = ProposalsResult::default();

    for id in proposal_ids {
        let proposal_funds_key = gov_storage::get_funds_key(id);
        let proposal_end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
        let proposal_type_key = gov_storage::get_proposal_type_key(id);
        let proposal_author_key = gov_storage::get_author_key(id);

        let funds: token::Amount =
            force_read(&shell.state, &proposal_funds_key)?;
        let proposal_end_epoch: Epoch =
            force_read(&shell.state, &proposal_end_epoch_key)?;
        let proposal_type: ProposalType =
            force_read(&shell.state, &proposal_type_key)?;
        let proposal_author: Address =
            force_read(&shell.state, &proposal_author_key)?;

        let is_steward = pgf::is_steward(&shell.state, &proposal_author)?;

        let params = read_pos_params(&shell.state)?;
        let total_active_voting_power =
            read_total_active_stake(&shell.state, &params, proposal_end_epoch)?;

        let tally_type = TallyType::from(proposal_type.clone(), is_steward);
        let votes = compute_proposal_votes(
            &shell.state,
            &params,
            id,
            proposal_end_epoch,
        )?;
        let proposal_result = compute_proposal_result(
            votes,
            total_active_voting_power,
            tally_type,
        )
        .expect("Proposal result calculation must not over/underflow");
        gov_api::write_proposal_result(&mut shell.state, id, proposal_result)?;

        let transfer_address = match proposal_result.result {
            TallyResult::Passed => {
                let proposal_event = match proposal_type {
                    ProposalType::Default => {
                        let proposal_code =
                            gov_api::get_proposal_code(&shell.state, id)?
                                .unwrap_or_default();
                        let _result = execute_default_proposal(
                            shell,
                            id,
                            proposal_code.clone(),
                        )?;
                        tracing::info!(
                            "Default Governance proposal {} has been executed \
                             and passed.",
                            id,
                        );

                        GovernanceEvent::passed_proposal(id, false, false)
                    }
                    ProposalType::DefaultWithWasm(_) => {
                        let proposal_code =
                            gov_api::get_proposal_code(&shell.state, id)?
                                .unwrap_or_default();
                        let result = execute_default_proposal(
                            shell,
                            id,
                            proposal_code.clone(),
                        )?;
                        tracing::info!(
                            "DefaultWithWasm Governance proposal {} has been \
                             executed and passed, wasm executiong was {}.",
                            id,
                            if result { "successful" } else { "unsuccessful" }
                        );

                        GovernanceEvent::passed_proposal(id, true, result)
                    }
                    ProposalType::PGFSteward(stewards) => {
                        let _result = execute_pgf_steward_proposal(
                            &mut shell.state,
                            stewards,
                        )?;
                        tracing::info!(
                            "Governance proposal (pgf stewards){} has been \
                             executed and passed.",
                            id
                        );

                        GovernanceEvent::passed_proposal(id, false, false)
                    }
                    ProposalType::PGFPayment(payments) => {
                        let native_token = &shell.state.get_native_token()?;
                        let _result = execute_pgf_funding_proposal(
                            &mut shell.state,
                            events,
                            native_token,
                            payments,
                            id,
                        )?;
                        tracing::info!(
                            "Governance proposal (pgf funding) {} has been \
                             executed and passed.",
                            id
                        );

                        GovernanceEvent::passed_proposal(id, false, false)
                    }
                };
                events.emit(proposal_event);
                proposals_result.passed.push(id);

                // Take events that could have been emitted by PGF
                // over IBC, governance proposal execution, etc
                let current_height =
                    shell.state.in_mem().get_last_block_height().next_height();

                events.emit_many(
                    shell
                        .state
                        .write_log_mut()
                        .take_events()
                        .into_iter()
                        .map(|event| event.with(Height(current_height))),
                );

                gov_api::get_proposal_author(&shell.state, id)?
            }
            TallyResult::Rejected => {
                if let ProposalType::PGFPayment(_) = proposal_type {
                    if proposal_result.two_thirds_nay_over_two_thirds_total() {
                        pgf::remove_steward(
                            &mut shell.state,
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
                let proposal_event = GovernanceEvent::rejected_proposal(
                    id,
                    matches!(proposal_type, ProposalType::DefaultWithWasm(_)),
                );
                events.emit(proposal_event);
                proposals_result.rejected.push(id);

                tracing::info!(
                    "Governance proposal {} has been executed and rejected.",
                    id
                );

                None
            }
        };

        let native_token = shell.state.get_native_token()?;
        if let Some(address) = transfer_address {
            token::transfer(
                &mut shell.state,
                &native_token,
                &gov_address,
                &address,
                funds,
            )?;

            const DESCRIPTOR: &str = "governance-locked-funds-refund";

            let final_gov_balance =
                read_balance(&shell.state, &native_token, &gov_address)?.into();
            let final_target_balance =
                read_balance(&shell.state, &native_token, &address)?.into();

            events.emit(TokenEvent {
                descriptor: DESCRIPTOR.into(),
                level: EventLevel::Block,
                token: native_token.clone(),
                operation: TokenOperation::Transfer {
                    amount: funds.into(),
                    source: UserAccount::Internal(gov_address),
                    target: UserAccount::Internal(address),
                    source_post_balance: final_gov_balance,
                    target_post_balance: Some(final_target_balance),
                },
            });
        } else {
            token::burn_tokens(
                &mut shell.state,
                &native_token,
                &gov_address,
                funds,
            )?;

            const DESCRIPTOR: &str = "governance-locked-funds-burn";

            let final_gov_balance =
                read_balance(&shell.state, &native_token, &gov_address)?.into();

            events.emit(TokenEvent {
                descriptor: DESCRIPTOR.into(),
                level: EventLevel::Block,
                token: native_token.clone(),
                operation: TokenOperation::Burn {
                    amount: funds.into(),
                    target_account: UserAccount::Internal(gov_address),
                    post_balance: final_gov_balance,
                },
            });
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

    let mut validators_vote: HashMap<Address, ProposalVote> =
        HashMap::default();
    let mut validator_voting_power: HashMap<Address, VotePower> =
        HashMap::default();
    let mut delegators_vote: HashMap<Address, ProposalVote> =
        HashMap::default();
    let mut delegator_voting_power: HashMap<
        Address,
        HashMap<Address, VotePower>,
    > = HashMap::default();

    for vote in votes {
        // Skip votes involving jailed or inactive validators
        let validator = vote.validator.clone();
        let validator_state =
            validator_state_handle(&validator).get(storage, epoch, params)?;

        if matches!(
            validator_state,
            Some(ValidatorState::Jailed) | Some(ValidatorState::Inactive)
        ) {
            continue;
        }
        if validator_state.is_none() {
            tracing::error!(
                "While computing votes for proposal id {proposal_id} in epoch \
                 {epoch}, encountered validator {validator} that has no \
                 stored state. Please report this as a bug. Skipping this \
                 vote."
            );
            continue;
        }

        // Tally the votes involving active validators
        if vote.is_validator() {
            let vote_data = vote.data.clone();

            let validator_stake =
                read_validator_stake(storage, params, &validator, epoch)
                    .unwrap_or_default();

            validators_vote.insert(validator.clone(), vote_data);
            validator_voting_power.insert(validator, validator_stake);
        } else {
            let delegator = vote.delegator.clone();
            let vote_data = vote.data.clone();

            let bond_id = BondId {
                source: delegator.clone(),
                validator: validator.clone(),
            };
            let delegator_stake = bond_amount(storage, &bond_id, epoch);

            if let Ok(stake) = delegator_stake {
                delegators_vote.insert(delegator.clone(), vote_data);
                delegator_voting_power
                    .entry(delegator)
                    .or_default()
                    .insert(validator, stake);
            } else {
                continue;
            }
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
    proposal_code: Vec<u8>,
) -> namada::state::StorageResult<bool>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let pending_execution_key = gov_storage::get_proposal_execution_key(id);
    shell.state.write(&pending_execution_key, ())?;

    let mut tx = Tx::from_type(TxType::Raw);
    tx.header.chain_id = shell.chain_id.clone();
    tx.set_data(Data::new(encode(&id)));
    tx.set_code(Code::new(proposal_code, None));

    let tx_result = protocol::dispatch_tx(
        tx,
        &[], /*  this is used to compute the fee
              * based on the code size. We dont
              * need it here. */
        TxIndex::default(),
        &RefCell::new(TxGasMeter::new_from_sub_limit(u64::MAX.into())), /* No gas limit for governance proposal */
        &mut shell.state,
        &mut shell.vp_wasm_cache,
        &mut shell.tx_wasm_cache,
        None,
    );
    shell
        .state
        .delete(&pending_execution_key)
        .expect("Should be able to delete the storage.");
    match tx_result {
        Ok(tx_result) => {
            if tx_result.is_accepted() {
                shell.state.commit_tx();
                Ok(true)
            } else {
                shell.state.drop_tx();
                Ok(false)
            }
        }
        Err(_) => {
            shell.state.drop_tx();
            Ok(false)
        }
    }
}

fn execute_pgf_steward_proposal<S>(
    storage: &mut S,
    stewards: BTreeSet<AddRemove<Address>>,
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

fn execute_pgf_funding_proposal<D, H>(
    state: &mut WlState<D, H>,
    events: &mut impl EmitEvents,
    token: &Address,
    fundings: BTreeSet<PGFAction>,
    proposal_id: u64,
) -> Result<bool>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    for funding in fundings {
        match funding {
            PGFAction::Continuous(action) => match action {
                AddRemove::Add(target) => {
                    pgf_storage::fundings_handle().insert(
                        state,
                        target.target().clone(),
                        StoragePgfFunding::new(target.clone(), proposal_id),
                    )?;
                    tracing::info!(
                        "Added/Updated ContinuousPgf from proposal id {}: set \
                         {} to {}.",
                        proposal_id,
                        target.amount().to_string_native(),
                        target.target()
                    );
                }
                AddRemove::Remove(target) => {
                    pgf_storage::fundings_handle()
                        .remove(state, &target.target())?;
                    tracing::info!(
                        "Removed ContinuousPgf from proposal id {}: set {} to \
                         {}.",
                        proposal_id,
                        target.amount().to_string_native(),
                        target.target()
                    );
                }
            },
            PGFAction::Retro(target) => {
                let (result, event) = match &target {
                    PGFTarget::Internal(target) => (
                        token::transfer(
                            state,
                            token,
                            &ADDRESS,
                            &target.target,
                            target.amount,
                        ),
                        TokenEvent {
                            descriptor: "pgf-payments".into(),
                            level: EventLevel::Block,
                            token: token.clone(),
                            operation: TokenOperation::Transfer {
                                amount: target.amount.into(),
                                source: UserAccount::Internal(ADDRESS),
                                target: UserAccount::Internal(
                                    target.target.clone(),
                                ),
                                source_post_balance: read_balance(
                                    state, token, &ADDRESS,
                                )?
                                .into(),
                                target_post_balance: Some(
                                    read_balance(state, token, &target.target)?
                                        .into(),
                                ),
                            },
                        },
                    ),
                    PGFTarget::Ibc(target) => (
                        ibc::transfer_over_ibc(state, token, &ADDRESS, target),
                        TokenEvent {
                            descriptor: "pgf-payments-over-ibc".into(),
                            level: EventLevel::Block,
                            token: token.clone(),
                            operation: TokenOperation::Transfer {
                                amount: target.amount.into(),
                                source: UserAccount::Internal(ADDRESS),
                                target: UserAccount::External(
                                    target.target.clone(),
                                ),
                                source_post_balance: read_balance(
                                    state, token, &ADDRESS,
                                )?
                                .into(),
                                target_post_balance: None,
                            },
                        },
                    ),
                };
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "Execute RetroPgf from proposal id {}: sent {} to \
                             {}.",
                            proposal_id,
                            target.amount().to_string_native(),
                            target.target()
                        );
                        events.emit(event);
                    }
                    Err(e) => tracing::warn!(
                        "Error in RetroPgf transfer from proposal id {}, \
                         amount {} to {}: {}",
                        proposal_id,
                        target.amount().to_string_native(),
                        target.target(),
                        e
                    ),
                }
            }
        }
    }

    Ok(true)
}
