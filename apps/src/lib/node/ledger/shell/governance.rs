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
use namada::ledger::storage_api::{token, StorageWrite};
use namada::types::address::Address;
use namada::types::governance::TallyResult;
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
        let votes =
            get_proposal_votes(&shell.wl_storage, proposal_end_epoch, id);
        let is_accepted = votes.and_then(|votes| {
            compute_tally(&shell.wl_storage, proposal_end_epoch, votes)
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
                            .wl_storage
                            .write(&pending_execution_key, ())
                            .expect("Should be able to write to storage.");
                        let tx_result = protocol::apply_tx(
                            tx_type,
                            0, /*  this is used to compute the fee
                                * based on the code size. We dont
                                * need it here. */
                            TxIndex::default(),
                            &mut BlockGasMeter::default(),
                            &mut shell.wl_storage.write_log,
                            &shell.wl_storage.storage,
                            &mut shell.vp_wasm_cache,
                            &mut shell.tx_wasm_cache,
                        );
                        shell
                            .wl_storage
                            .delete(&pending_execution_key)
                            .expect("Should be able to delete the storage.");
                        match tx_result {
                            Ok(tx_result) => {
                                if tx_result.is_accepted() {
                                    shell.wl_storage.write_log.commit_tx();
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
                                    shell.wl_storage.write_log.drop_tx();
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
                                shell.wl_storage.write_log.drop_tx();
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

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use namada::ledger::governance::parameters::GovParams;
    use namada::ledger::storage_api::governance::{vote_proposal, init_proposal};
    use namada::types::address::testing::established_address_1;
    use namada::types::governance::ProposalVote;
    use namada::types::transaction::governance::{VoteProposalData, InitProposalData};    
    use std::collections::HashMap;

    use eyre::Result;
    use namada::ledger::events::EventLevel;
    use namada::ledger::native_vp::governance::utils::{Votes};
    use namada::ledger::storage_api::StorageWrite;
    use namada::proof_of_stake::{read_consensus_validator_set_addresses, read_consensus_validator_set_addresses_with_stake, bond_tokens};
    use namada::core::types::address::{gen_established_address};
    use namada::core::types::governance::{VotePower};
    
    
    use crate::node::ledger::shell::test_utils::TestShell;

    use super::*;

    /// Tests that if no governance proposals are present in
    /// `shell.proposal_data`, then no proposals are executed.
    #[test]
    fn test_no_governance_proposals() -> Result<()> {
        let (mut shell, _) = test_utils::setup(3);

        assert!(shell.proposal_data.is_empty());

        let mut resp = shim::response::FinalizeBlock::default();

        let proposals_result =
            execute_governance_proposals(&mut shell, &mut resp)?;

        assert!(
            shell.proposal_data.is_empty(),
            "shell.proposal_data should always be empty after a \
             `execute_governance_proposals` call"
        );
        assert!(proposals_result.passed.is_empty());
        assert!(proposals_result.rejected.is_empty());
        assert!(resp.events.is_empty());
        // TODO: also check expected key changes in `shell.storage` (for this
        // test, that should be no keys changed?)

        Ok(())
    }

    /// Tests that a governance proposal that ends without any votes is
    /// rejected.
    #[test]
    fn test_reject_single_governance_proposal() -> Result<()> {
        let (mut shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();


        // we don't bother setting up the shell to be at the right epoch for
        // this test
        // TODO: maybe commit blocks up here in `TestShell` up until just before
        // the first block of Epoch(9), to be more realistic? As governance
        // proposals should only happen at epoch transitions

        // set up a proposal in storage
        // proposals must be in sequence starting from one (or zero?)
        let proposal_id = 1;

        let proposal_funds = token::Amount::from(100_000_000);
        let proposal_funds_key = gov_storage::get_funds_key(proposal_id);
        StorageWrite::write(
            &mut shell.wl_storage,
            &proposal_funds_key,
            proposal_funds,
        )?;

        let proposal_end_epoch = Epoch(0);
        let proposal_end_epoch_key =
            gov_storage::get_voting_end_epoch_key(proposal_id);
        StorageWrite::write(
            &mut shell.wl_storage,
            &proposal_end_epoch_key,
            proposal_end_epoch,
        )?;

        // TODO: more keys need to be set up in storage for this proposal to
        // be realistic - see <https://github.com/anoma/namada/blob/main/tx_prelude/src/governance.rs#L13-L66>

        shell.proposal_data = HashSet::from([proposal_id]);

        let mut resp = shim::response::FinalizeBlock::default();

        let proposals_result =
            execute_governance_proposals(&mut shell, &mut resp)?;

        assert!(
            shell.proposal_data.is_empty(),
            "shell.proposal_data should always be empty after a \
             `execute_governance_proposals` call"
        );
        assert!(proposals_result.passed.is_empty());
        assert_eq!(proposals_result.rejected, vec![proposal_id]);
        assert_eq!(
            resp.events,
            vec![Event {
                event_type: EventType::Proposal,
                level: EventLevel::Block,
                attributes: HashMap::from([
                    ("proposal_id".to_string(), proposal_id.to_string()),
                    (
                        "has_proposal_code".to_string(),
                        (true as u64).to_string()
                    ),
                    (
                        "tally_result".to_string(),
                        TallyResult::Rejected.to_string()
                    ),
                    (
                        "proposal_code_exit_status".to_string(),
                        (true as u64).to_string()
                    ),
                ])
            }]
        );
        // TODO: also check expected key changes in `shell.storage`

        Ok(())
    }

    #[test]
    fn test_accept_single_governance_proposal() -> Result<()> {
        let (mut shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();

        let mut gov_params = GovParams::default();
        gov_params.init_storage(&mut shell.wl_storage.storage);
        // we don't bother setting up the shell to be at the right epoch for
        // this test
        // TODO: maybe commit blocks up here in `TestShell` up until just before
        // the first block of Epoch(9), to be more realistic? As governance
        // proposals should only happen at epoch transitions

        // Set up validators and delegations
        let validator_set = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage, epoch
        ).unwrap();



        let mut validator_set_iterator = validator_set.iter();
    
        let val1 = validator_set_iterator.next().unwrap();
        let val2 = validator_set_iterator.next().unwrap();
        let val3 = validator_set_iterator.next().unwrap();
        
        let mut yay_voters = spawn_delegators(1, val1.bonded_stake.clone(), &mut shell, val1, epoch);
        yay_voters.push(val1.address.clone());
        yay_voters.push(val2.address.clone());
        yay_voters.push(val3.address.clone());

        let nay_voters = spawn_delegators(1, val1.bonded_stake.clone(), &mut shell, val1, epoch);
        
        let proposal_id = 1;
        shell.proposal_data = HashSet::from([1]);

        let mut vote_proposals = Vec::new();
        let mut yay_vote_proposals = vote_on_proposal(&mut shell, proposal_id, yay_voters, ProposalVote::Yay);
        let mut nay_vote_proposals = vote_on_proposal(&mut shell, proposal_id, nay_voters, ProposalVote::Nay);
        vote_proposals.append(&mut yay_vote_proposals);
        vote_proposals.append(&mut nay_vote_proposals);
        
        
        // Source the proposal author with some tokens
        token::credit_tokens(&mut shell.wl_storage, &address::nam(), &established_address_1(), token::Amount::whole(10_000)).unwrap();

        let proposal_data = InitProposalData{
            id: Some(1),
            /// The proposal content
            content: vec![],
            /// The proposal author address
            author: established_address_1(),
            /// The epoch from which voting is allowed
            voting_start_epoch: Epoch(2),
            /// The epoch from which voting is stopped
            voting_end_epoch: Epoch(3),
            /// The epoch from which this changes are executed
            grace_epoch: Epoch(4),
            /// The code containing the storage changes
            proposal_code: None,

        };

        //advance the epoch beforehand
        advance_epoch(&mut shell);
        
        init_proposal(&mut shell.wl_storage, proposal_data).unwrap();
        shell.wl_storage.commit_block().unwrap();


        advance_epoch(&mut shell);
        for vote_p in vote_proposals.iter(){
            vote_proposal(&mut shell.wl_storage, vote_p.to_owned()).unwrap();
        }
        shell.wl_storage.commit_block().unwrap();

        // Let validators vote on the respective proposal
        let mut resp = shim::response::FinalizeBlock::default();
        
        let proposals_result =
            execute_governance_proposals(&mut shell, &mut resp)?;

        assert!(
            shell.proposal_data.is_empty(),
            "shell.proposal_data should always be empty after a \
             `execute_governance_proposals` call"
        );
        assert!(!proposals_result.passed.is_empty());
        assert!(proposals_result.rejected.is_empty());
    
        Ok(())
    }

    #[test]
    fn test_compute_tally_rejects_empty_votes() {
        let (shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();

        let votes = Votes {
            yay_validators: HashMap::default(),
            yay_delegators: HashMap::default(),
            nay_delegators: HashMap::default(),
        };

        let result = compute_tally(&shell.wl_storage, epoch, votes);

        assert_matches!(result, Ok(false));
    }

    #[test]
    fn test_compute_tally_accepts_enough_yay_votes() {
        let (shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();

        let validator_set = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage, epoch
        ).unwrap();

        
        let mut validator_set_iterator = validator_set.iter();
        
        let val1 = validator_set_iterator.next().unwrap();
        let val2 = validator_set_iterator.next().unwrap();

        let votes = Votes {
            yay_validators: HashMap::from([
                (val1.address.clone(), val1.bonded_stake.clone().into()),
                (val2.address.clone(), val2.bonded_stake.clone().into()),
            ]),
            yay_delegators: HashMap::default(),
            nay_delegators: HashMap::default(),
        };

        let result = compute_tally(&shell.wl_storage, epoch, votes);

        assert_matches!(result, Ok(true));
    }

    #[test]
    fn test_compute_tally_rejects_not_enough_yay_votes() {
        let (shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();

        let validator_set = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage, epoch).unwrap();

        let val1 = validator_set.iter().next().unwrap();

        let votes = Votes {
            yay_validators: HashMap::from([(
                val1.address.clone(),
                val1.bonded_stake.clone().into(),
            )]),
            nay_delegators: HashMap::default(),
            yay_delegators: HashMap::default(),
        };
        
        let result = compute_tally(&shell.wl_storage, epoch, votes);

        assert_matches!(result, Ok(false));
    }
    #[test]
    fn test_compute_tally_rejects_enough_nay_votes() {
        let (mut shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();

        let validator_set = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage, epoch).unwrap();
        

        let mut validator_set_iterator = validator_set.iter();
    
        let val1 = validator_set_iterator.next().unwrap();
        let val2 = validator_set_iterator.next().unwrap();
        
        let delegator1 = gen_established_address("four-twenty");

        token::credit_tokens(&mut shell.wl_storage, &address::nam(), &delegator1, val1.bonded_stake.clone().into()).unwrap();

        bond_tokens(&mut shell.wl_storage, Some(&delegator1), &val1.address, val1.bonded_stake.clone().into(), epoch).unwrap();

        let val1_vote_power : VotePower = u64::from(val1.bonded_stake).into();

        let mut nay_delegator = HashMap::default();
        nay_delegator.insert(delegator1, HashMap::from([(val1.address.clone(), val1_vote_power)]));

        

        let votes = Votes {
            yay_validators: HashMap::from([
                (val1.address.clone(), val1.bonded_stake.clone().into()),
                (val2.address.clone(), val2.bonded_stake.clone().into()),
            ]),
            yay_delegators: HashMap::default(),
            nay_delegators: nay_delegator,
        
        };
    
        let result = compute_tally(&shell.wl_storage, epoch, votes);

        assert_matches!(result, Ok(false));
    }

    #[test]
    fn test_compute_tally_accepts_delegates() {
        let (mut shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();

        let validator_set = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage, epoch).unwrap();
        

        let mut validator_set_iterator = validator_set.iter();
    
        let val1 = validator_set_iterator.next().unwrap();

        let val1_vote_power : VotePower = u64::from(val1.bonded_stake).into();

        let delegators = spawn_delegators(2, val1.bonded_stake.clone(), &mut shell, val1, epoch);
        let mut yay_delegators = HashMap::default();

        for delegator in delegators{
            yay_delegators.insert(delegator, HashMap::from([(val1.address.clone(), val1_vote_power)]));
        
        };
        let votes = Votes {
            yay_validators: HashMap::default(),
            yay_delegators: yay_delegators,
            nay_delegators: HashMap::default(),
        
        };
    
        let result = compute_tally(&shell.wl_storage, epoch, votes);

        assert_matches!(result, Ok(true));
    }

    #[test]
    fn test_vote_proposal(){
        
        let (mut shell, _) = test_utils::setup(3);
        let epoch = Epoch::default();

        let validator_set = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage, epoch
        ).unwrap();


        let mut validator_set_iterator = validator_set.iter();
    
        let val1 = validator_set_iterator.next().unwrap();
        
        let yay_delegators = spawn_delegators(2, val1.bonded_stake.clone(), &mut shell, val1, epoch);

        let nay_delegators = spawn_delegators(1, val1.bonded_stake.clone(), &mut shell, val1, epoch);
        
        let proposal_id = 1;

        let mut vote_proposals = Vec::new();
        let mut yay_vote_proposals = vote_on_proposal(&mut shell, proposal_id, yay_delegators, ProposalVote::Yay);
        let mut nay_vote_proposals = vote_on_proposal(&mut shell, proposal_id, nay_delegators, ProposalVote::Nay);

        vote_proposals.append(&mut nay_vote_proposals);
        vote_proposals.append(&mut nay_vote_proposals);
        
        for vote_p in vote_proposals.iter(){
            vote_proposal(&mut shell.wl_storage, vote_p.to_owned()).unwrap();
        }
        
        // TODO: Now check that keys actually changed


    }

    fn advance_epoch(s: &mut TestShell) -> Epoch {
        let params = &proof_of_stake::read_pos_params(&s.wl_storage).unwrap();
        s.wl_storage.storage.block.epoch = s.wl_storage.storage.block.epoch.next();
        let current_epoch = s.wl_storage.storage.block.epoch;
        proof_of_stake::copy_validator_sets_and_positions(
            &mut s.wl_storage,
            current_epoch,
            current_epoch + params.pipeline_len,
            &proof_of_stake::consensus_validator_set_handle(),
            &proof_of_stake::below_capacity_validator_set_handle(),
        )
        .unwrap();
        current_epoch
    }

    fn spawn_delegators(num_delegators :u8, bond_amount: token::Amount, shell : &mut TestShell, validator : &proof_of_stake::types::WeightedValidator, epoch : Epoch) -> Vec<Address>{
        
        let mut delegators = Vec::new();

        for i in 0..num_delegators{
            let del_address = gen_established_address(i.to_string());
            token::credit_tokens(&mut shell.wl_storage, &address::nam(), &del_address, bond_amount.into()).unwrap();
            bond_tokens(&mut shell.wl_storage, Some(&del_address), &validator.address, bond_amount.into(), epoch).unwrap();

            delegators.push(del_address);
        }

        return delegators;
    
    }

    /// Creates n votes from n delegators, all voting on some proposal id 
    fn vote_on_proposal(shell: &mut TestShell, proposal_id : u64, delegators: Vec<Address>, vote_type : ProposalVote) -> Vec<VoteProposalData> {

        let mut vote_proposals: Vec<VoteProposalData> = Vec::new();
        for delegator in delegators{
            let delegations : Vec<Address>= proof_of_stake::find_delegation_validators(&shell.wl_storage, &delegator).unwrap().into_iter().collect();
            let vote_proposal_data = VoteProposalData {
                id : proposal_id,
                vote : vote_type.clone(),
                voter: delegator,
                delegations: delegations
            };
            vote_proposals.push(vote_proposal_data);

        };

        return vote_proposals

    }
}

