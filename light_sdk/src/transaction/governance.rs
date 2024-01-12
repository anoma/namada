use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::ledger::governance::storage::vote::ProposalVote;
use namada_core::proto::Tx;
use namada_core::types::address::Address;
use namada_core::types::hash::Hash;
use namada_core::types::key::common;
use namada_core::types::storage::Epoch;

use super::GlobalArgs;
use crate::transaction;

const TX_INIT_PROPOSAL_WASM: &str = "tx_init_proposal.wasm";
const TX_VOTE_PROPOSAL: &str = "tx_vote_proposal.wasm";

/// Transaction to initialize a governance proposal
pub struct InitProposal(Tx);

impl InitProposal {
    /// Build a raw InitProposal transaction from the given parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Option<u64>,
        content: Hash,
        author: Address,
        r#type: ProposalType,
        voting_start_epoch: Epoch,
        voting_end_epoch: Epoch,
        grace_epoch: Epoch,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal =
            namada_core::types::transaction::governance::InitProposalData {
                id,
                content,
                author,
                r#type,
                voting_start_epoch,
                voting_end_epoch,
                grace_epoch,
            };

        Self(transaction::build_tx(
            args,
            init_proposal,
            TX_INIT_PROPOSAL_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

/// Transaction to vote on a governance proposal
pub struct VoteProposal(Tx);

impl VoteProposal {
    /// Build a raw VoteProposal transaction from the given parameters
    pub fn new(
        id: u64,
        vote: ProposalVote,
        voter: Address,
        delegations: Vec<Address>,
        args: GlobalArgs,
    ) -> Self {
        let vote_proposal =
            namada_core::types::transaction::governance::VoteProposalData {
                id,
                vote,
                voter,
                delegations,
            };

        Self(transaction::build_tx(
            args,
            vote_proposal,
            TX_VOTE_PROPOSAL.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
