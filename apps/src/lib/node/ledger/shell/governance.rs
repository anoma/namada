use namada::core::ledger::slash_fund::ADDRESS as slash_fund_address;
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
use namada::types::address::Address;
use namada::types::governance::TallyResult;
use namada::types::storage::Epoch;
use namada::types::token;

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

        let votes = get_proposal_votes(&shell.storage, proposal_end_epoch, id);
        let is_accepted = votes.and_then(|votes| {
            compute_tally(&shell.storage, proposal_end_epoch, votes)
        });

        let transfer_address = match is_accepted {
            Ok(true) => {
                let proposal_author_key = gov_storage::get_author_key(id);
                let proposal_author = shell
                    .read_storage_key::<Address>(&proposal_author_key)
                    .ok_or_else(|| {
                        Error::BadProposal(
                            id,
                            "Invalid proposal author.".to_string(),
                        )
                    })?;

                let proposal_code_key = gov_storage::get_proposal_code_key(id);
                let proposal_code =
                    shell.read_storage_key_bytes(&proposal_code_key);
                match proposal_code {
                    Some(proposal_code) => {
                        let tx = Tx::new(proposal_code, Some(encode(&id)));
                        let tx_type =
                            TxType::Decrypted(DecryptedTx::Decrypted {
                                tx,
                                #[cfg(not(feature = "mainnet"))]
                                has_valid_pow: false,
                            });
                        let pending_execution_key =
                            gov_storage::get_proposal_execution_key(id);
                        shell
                            .storage
                            .write(&pending_execution_key, "")
                            .expect("Should be able to write to storage.");
                        let tx_result = protocol::apply_tx(
                            tx_type,
                            0, /*  this is used to compute the fee
                                * based on the code size. We dont
                                * need it here. */
                            TxIndex::default(),
                            &mut BlockGasMeter::default(),
                            &mut shell.write_log,
                            &shell.storage,
                            &mut shell.vp_wasm_cache,
                            &mut shell.tx_wasm_cache,
                        );
                        shell
                            .storage
                            .delete(&pending_execution_key)
                            .expect("Should be able to delete the storage.");
                        match tx_result {
                            Ok(tx_result) => {
                                if tx_result.is_accepted() {
                                    shell.write_log.commit_tx();
                                    let proposal_event: Event =
                                        ProposalEvent::new(
                                            EventType::Proposal.to_string(),
                                            TallyResult::Passed,
                                            id,
                                            true,
                                            true,
                                        )
                                        .into();
                                    response.events.push(proposal_event);
                                    proposals_result.passed.push(id);

                                    proposal_author
                                } else {
                                    shell.write_log.drop_tx();
                                    let proposal_event: Event =
                                        ProposalEvent::new(
                                            EventType::Proposal.to_string(),
                                            TallyResult::Passed,
                                            id,
                                            true,
                                            false,
                                        )
                                        .into();
                                    response.events.push(proposal_event);
                                    proposals_result.rejected.push(id);

                                    slash_fund_address
                                }
                            }
                            Err(_e) => {
                                shell.write_log.drop_tx();
                                let proposal_event: Event = ProposalEvent::new(
                                    EventType::Proposal.to_string(),
                                    TallyResult::Passed,
                                    id,
                                    true,
                                    false,
                                )
                                .into();
                                response.events.push(proposal_event);
                                proposals_result.rejected.push(id);

                                slash_fund_address
                            }
                        }
                    }
                    None => {
                        let proposal_event: Event = ProposalEvent::new(
                            EventType::Proposal.to_string(),
                            TallyResult::Passed,
                            id,
                            false,
                            false,
                        )
                        .into();
                        response.events.push(proposal_event);
                        proposals_result.passed.push(id);

                        proposal_author
                    }
                }
            }
            Ok(false) => {
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
            Err(err) => {
                tracing::error!(
                    "Unexpectedly failed to tally proposal ID {id} with error \
                     {err}"
                );
                let proposal_event: Event = ProposalEvent::new(
                    EventType::Proposal.to_string(),
                    TallyResult::Failed,
                    id,
                    false,
                    false,
                )
                .into();
                response.events.push(proposal_event);

                slash_fund_address
            }
        };

        let native_token = shell.storage.native_token.clone();
        // transfer proposal locked funds
        shell.storage.transfer(
            &native_token,
            funds,
            &gov_address,
            &transfer_address,
        );
    }

    Ok(proposals_result)
}

// #[cfg(test)]
// mod test_governance_tx {
//     // IMPORTANT: do not import anything directly from this `crate` here, only
//     // via `namada_tests`. This gets us around the `core -> tests -> core` dep
//     // cycle, which is okay, because `tests` is only a `dev-dependency` of
//     // core and allows us to test the code in the same module as its defined.
//     //
//     // This imports the same code as `super::*` but from a different version of
//     // this crate (one that `namada_tests` depends on). It's re-exported
//     // from `namada_tests` so that we can use it together with
//     // `namada_tests` modules back in here.
   
//     //use namada_tests::namada::core::types::{address, token};

//     use super::*;

//     // how to access mockdb
//     use namada::ledger::storage::mockdb::MockDB;
//     use namada::ledger::storage::Sha256Hasher;
//     // use namada::ledger::storage::traits::Sha256Hasher;
//     use namada::types::address;
//     pub type TestStorage = Storage<MockDB, Sha256Hasher>;

//     #[test]
//     fn test_compute_tally(){
//         let storage = TestStorage::default();
//         let mut write_log = WriteLog::default();

//     }

//     #[test]
//     fn test_execute_proposal() {
        
//         let mut tx_env = TestTxEnv::default();

//         // Source address that's using PoW (this would be derived from the tx
//         // wrapper pk)
//         let source = address::testing::established_address_2();

//         // Ensure that the addresses exists, so we can use them in a tx
//         tx_env.spawn_accounts([&faucet_address, &source]);

//         init_faucet_storage(
//             &mut tx_env.storage,
//             &faucet_address,
//             difficulty,
//             withdrawal_limit,
//         )?;

//         let challenge = Challenge::new(
//             &mut tx_env.storage,
//             &faucet_address,
//             source.clone(),
//         )?;

//         let solution = challenge.solve();

//         // The solution must be valid
//         assert!(solution.verify_solution(source.clone()));

//         // Changing the solution to `0` invalidates it
//         {
//             let mut solution = solution.clone();
//             solution.value = 0;
//             // If you're unlucky and this fails, try changing the solution to
//             // a different literal.
//             assert!(!solution.verify_solution(source.clone()));
//         }
//         // Changing the counter invalidates it
//         {
//             let mut solution = solution.clone();
//             solution.params.counter = 10;
//             // If you're unlucky and this fails, try changing the counter to
//             // a different literal.
//             assert!(!solution.verify_solution(source.clone()));
//         }

//         // Apply the solution from a tx
//         vp::vp_host_env::init_from_tx(
//             faucet_address.clone(),
//             tx_env,
//             |_addr| {
//                 solution
//                     .apply_from_tx(tx::ctx(), &faucet_address, &source)
//                     .unwrap();
//             },
//         );

//         // Check that it's valid
//         let is_valid = solution.validate(
//             &vp::ctx().pre(),
//             &faucet_address,
//             source.clone(),
//         )?;
//         assert!(is_valid);

//         // Commit the tx
//         let vp_env = vp::vp_host_env::take();
//         tx::tx_host_env::set_from_vp_env(vp_env);
//         tx::tx_host_env::commit_tx_and_block();
//         let tx_env = tx::tx_host_env::take();

//         // Re-apply the same solution from a tx
//         vp::vp_host_env::init_from_tx(
//             faucet_address.clone(),
//             tx_env,
//             |_addr| {
//                 solution
//                     .apply_from_tx(tx::ctx(), &faucet_address, &source)
//                     .unwrap();
//             },
//         );

//         // Check that it's not longer valid
//         let is_valid =
//             solution.validate(&vp::ctx().pre(), &faucet_address, source)?;
//         assert!(!is_valid);

//         Ok(())
//     }
// }
