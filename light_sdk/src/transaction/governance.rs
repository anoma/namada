use crate::transaction;
use borsh_ext::BorshSerializeExt;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::ledger::governance::storage::vote::StorageProposalVote;
use namada_core::proto::Section;
use namada_core::proto::SignatureIndex;
use namada_core::proto::Signer;
use namada_core::proto::TxError;
use namada_core::proto::{Signature, Tx};
use namada_core::types::address::Address;
use namada_core::types::chain::ChainId;
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token;
use namada_core::types::token::{Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::Fee;
use namada_core::types::transaction::GasLimit;
use std::collections::BTreeMap;
use std::str::FromStr;

use super::GlobalArgs;

const TX_INIT_PROPOSAL_WASM: &str = "tx_init_proposal.wasm";
const TX_VOTE_PROPOSAL: &str = "tx_vote_proposal.wasm";

pub struct InitProposal(Tx);

impl InitProposal {
    /// Build a raw InitProposal transaction from the given parameters
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
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct VoteProposal(Tx);

impl VoteProposal {
    /// Build a raw VoteProposal transaction from the given parameters
    pub fn new(
        id: u64,
        vote: StorageProposalVote,
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
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}
