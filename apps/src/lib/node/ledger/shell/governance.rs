use std::collections::BTreeMap;

use namada::core::ledger::slash_fund::ADDRESS as slash_fund_address;
use namada::core::types::transaction::governance::ProposalType;
use namada::ledger::events::EventType;
use namada::ledger::governance::{
    storage as gov_storage, ADDRESS as gov_address,
};
use namada::ledger::native_vp::governance::utils::{
    compute_tally, get_proposal_votes, ProposalEvent,
};
use namada::ledger::protocol;
use namada::ledger::storage::types::encode;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::ledger::storage_api::{token, StorageWrite};
use namada::proof_of_stake::read_total_stake;
use namada::types::address::Address;
use namada::types::governance::{Council, Tally, TallyResult, VotePower};
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
    gas_table: &BTreeMap<String, u64>,
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

        let funds = shell
            .read_storage_key::<token::Amount>(&proposal_funds_key)
            .ok_or_else(|| {
                Error::BadProposal(id, "Invalid proposal funds.".to_string())
            })?;
        let proposal_end_epoch = shell
            .read_storage_key::<Epoch>(&proposal_end_epoch_key)
            .ok_or_else(|| {
                Error::BadProposal(
                    id,
                    "Invalid proposal end_epoch.".to_string(),
                )
            })?;

        let proposal_type = shell
            .read_storage_key::<ProposalType>(&proposal_type_key)
            .ok_or_else(|| {
                Error::BadProposal(id, "Invalid proposal type".to_string())
            })?;

        let votes =
            get_proposal_votes(&shell.wl_storage, proposal_end_epoch, id)
                .map_err(|msg| Error::BadProposal(id, msg.to_string()))?;
        let params = read_pos_params(&shell.wl_storage)
            .map_err(|msg| Error::BadProposal(id, msg.to_string()))?;
        let total_stake =
            read_total_stake(&shell.wl_storage, &params, proposal_end_epoch)
                .map_err(|msg| Error::BadProposal(id, msg.to_string()))?;
        let total_stake = VotePower::from(u64::from(total_stake));
        let tally_result = compute_tally(votes, total_stake, &proposal_type)
            .map_err(|msg| Error::BadProposal(id, msg.to_string()))?
            .result;

        // Execute proposal if succesful
        let transfer_address = match tally_result {
            TallyResult::Passed(tally) => {
                let (successful_execution, proposal_event) = match tally {
                    Tally::Default => {
                        execute_default_proposal(shell, id, gas_table)
                    }
                    Tally::PGFCouncil(council) => {
                        execute_pgf_proposal(id, council)
                    }
                    Tally::ETHBridge => execute_eth_proposal(id),
                };

                response.events.push(proposal_event);
                if successful_execution {
                    proposals_result.passed.push(id);
                    shell
                        .read_storage_key::<Address>(
                            &gov_storage::get_author_key(id),
                        )
                        .ok_or_else(|| {
                            Error::BadProposal(
                                id,
                                "Invalid proposal author.".to_string(),
                            )
                        })?
                } else {
                    proposals_result.rejected.push(id);
                    slash_fund_address
                }
            }
            TallyResult::Rejected => {
                let proposal_event: Event = ProposalEvent::new(
                    EventType::Proposal.to_string(),
                    TallyResult::Rejected,
                    id,
                    false,
                    false,
                )
                .into();
                response.events.push(proposal_event);
                proposals_result.rejected.push(id);

                slash_fund_address
            }
        };

        let native_token = shell.wl_storage.storage.native_token.clone();
        // transfer proposal locked funds
        token::transfer(
            &mut shell.wl_storage,
            &native_token,
            &gov_address,
            &transfer_address,
            funds,
        )
        .expect(
            "Must be able to transfer governance locked funds after proposal \
             has been tallied",
        );
    }

    Ok(proposals_result)
}

fn execute_default_proposal<D, H>(
    shell: &mut Shell<D, H>,
    id: u64,
    gas_table: &BTreeMap<String, u64>,
) -> (bool, Event)
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let proposal_code_key = gov_storage::get_proposal_code_key(id);
    let proposal_code = shell.read_storage_key_bytes(&proposal_code_key);
    match proposal_code {
        Some(proposal_code) => {
            let tx = Tx::new(
                proposal_code,
                Some(encode(&id)),
                shell.chain_id.clone(),
                None,
            );
            let tx_type = TxType::Decrypted(DecryptedTx::Decrypted {
                tx,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            });
            let pending_execution_key =
                gov_storage::get_proposal_execution_key(id);
            shell
                .wl_storage
                .write(&pending_execution_key, ())
                .expect("Should be able to write to storage.");
            let tx_result = protocol::apply_tx(
                tx_type,
                TxIndex::default(),
                &mut TxGasMeter::new(u64::MAX), /* No gas limit for
                                                 * governance proposals */
                gas_table,
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
                Ok(tx_result) if tx_result.is_accepted() => {
                    shell.wl_storage.commit_tx();
                    (
                        tx_result.is_accepted(),
                        ProposalEvent::new(
                            EventType::Proposal.to_string(),
                            TallyResult::Passed(Tally::Default),
                            id,
                            true,
                            tx_result.is_accepted(),
                        )
                        .into(),
                    )
                }
                _ => {
                    shell.wl_storage.drop_tx();
                    (
                        false,
                        ProposalEvent::new(
                            EventType::Proposal.to_string(),
                            TallyResult::Passed(Tally::Default),
                            id,
                            true,
                            false,
                        )
                        .into(),
                    )
                }
            }
        }
        None => (
            true,
            ProposalEvent::new(
                EventType::Proposal.to_string(),
                TallyResult::Passed(Tally::Default),
                id,
                false,
                false,
            )
            .into(),
        ),
    }
}

fn execute_pgf_proposal(id: u64, council: Council) -> (bool, Event) {
    // TODO: implement when PGF is in place, update the PGF
    // council in storage
    (
        true,
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed(Tally::PGFCouncil(council)),
            id,
            false,
            false,
        )
        .into(),
    )
}

fn execute_eth_proposal(id: u64) -> (bool, Event) {
    // TODO: implement when ETH Bridge. Apply the
    // modification requested by the proposal
    // <https://github.com/anoma/namada/issues/1166>
    (
        true,
        ProposalEvent::new(
            EventType::Proposal.to_string(),
            TallyResult::Passed(Tally::ETHBridge),
            id,
            false,
            false,
        )
        .into(),
    )
}
