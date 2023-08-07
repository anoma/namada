use std::collections::{BTreeSet, HashMap};

use namada::core::ledger::governance::storage::keys as gov_storage;
use namada::core::ledger::governance::storage::proposal::{
    AddRemove, PGFAction, PGFTarget, ProposalType,
};
use namada::core::ledger::governance::utils::{
    compute_proposal_result, ProposalVotes, TallyResult, TallyType, TallyVote,
    VotePower,
};
use namada::core::ledger::governance::ADDRESS as gov_address;
use namada::core::ledger::pgf::storage::keys as pgf_storage;
use namada::core::ledger::pgf::ADDRESS;
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
use namada::proto::{Code, Data};
use namada::types::address::Address;
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
        let proposal_result =
            compute_proposal_result(votes, total_voting_power, tally_type);

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
                        )?;
                        tracing::info!(
                            "Governance proposal (pgs payments) {} has been \
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
                    let two_third_nay = proposal_result.two_third_nay();
                    if two_third_nay {
                        let pgf_stewards_key = pgf_storage::get_stewards_key();
                        let proposal_author = gov_storage::get_author_key(id);

                        let mut pgf_stewards = shell
                            .wl_storage
                            .read::<BTreeSet<Address>>(&pgf_stewards_key)?
                            .unwrap_or_default();
                        let proposal_author: Address =
                            force_read(&shell.wl_storage, &proposal_author)?;

                        pgf_stewards.remove(&proposal_author);
                        shell
                            .wl_storage
                            .write(&pgf_stewards_key, pgf_stewards)?;

                        tracing::info!(
                            "Governance proposal {} was rejected with 2/3 of \
                             nay votes. Removing {} from stewards set.",
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
                read_total_stake(storage, params, epoch).unwrap_or_default();

            validators_vote.insert(validator.clone(), vote_data.into());
            validator_voting_power.insert(validator, validator_stake.into());
        } else {
            let validator = vote.validator.clone();
            let delegator = vote.delegator.clone();
            let vote_data = vote.data.clone();

            let bond_id = BondId {
                source: delegator.clone(),
                validator: validator.clone(),
            };
            let (_, delegator_stake) =
                bond_amount(storage, &bond_id, epoch).unwrap_or_default();

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

        let mut tx = Tx::new(TxType::Decrypted(DecryptedTx::Decrypted {
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        }));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_data(Data::new(encode(&id)));
        tx.set_code(Code::new(code));

        //  0 parameter is used to compute the fee
        // based on the code size. We dont
        // need it here.
        let tx_result = protocol::dispatch_tx(
            tx,
            0, /*  this is used to compute the fee
                * based on the code size. We dont
                * need it here. */
            TxIndex::default(),
            &mut BlockGasMeter::default(),
            &mut shell.wl_storage,
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
    let stewards_key = pgf_storage::get_stewards_key();
    let mut storage_stewards: BTreeSet<Address> =
        storage.read(&stewards_key)?.unwrap_or_default();

    for action in stewards {
        match action {
            AddRemove::Add(steward) => storage_stewards.insert(steward),
            AddRemove::Remove(steward) => storage_stewards.remove(&steward),
        };
    }

    let write_result = storage.write(&stewards_key, storage_stewards);
    Ok(write_result.is_ok())
}

fn execute_pgf_payment_proposal<S>(
    storage: &mut S,
    token: &Address,
    payments: Vec<PGFAction>,
) -> Result<bool>
where
    S: StorageRead + StorageWrite,
{
    let continous_payments_key = pgf_storage::get_payments_key();
    let mut continous_payments: BTreeSet<PGFTarget> =
        storage.read(&continous_payments_key)?.unwrap_or_default();

    for payment in payments {
        match payment {
            PGFAction::Continuous(action) => match action {
                AddRemove::Add(target) => {
                    continous_payments.insert(target);
                }
                AddRemove::Remove(target) => {
                    continous_payments.remove(&target);
                }
            },
            PGFAction::Retro(target) => {
                token::transfer(
                    storage,
                    token,
                    &ADDRESS,
                    &target.target,
                    target.amount,
                )?;
            }
        }
    }

    let write_result =
        storage.write(&continous_payments_key, continous_payments);
    Ok(write_result.is_ok())
}
