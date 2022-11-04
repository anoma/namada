//! Files defyining the types used in governance.

use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::key::common::{self, Signature};
use crate::types::key::SigScheme;
use crate::types::storage::Epoch;
use crate::types::token::SCALE;
use crate::types::transaction::governance::InitProposalData;

/// Type alias for vote power
pub type VotePower = u128;

#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Eq,
)]
/// The vote for a proposal
pub enum ProposalVote {
    /// Yes
    Yay,
    /// No
    Nay,
}

impl ProposalVote {
    /// Check if a vote is yay
    pub fn is_yay(&self) -> bool {
        match self {
            ProposalVote::Yay => true,
            ProposalVote::Nay => false,
        }
    }
}

impl Display for ProposalVote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalVote::Yay => write!(f, "yay"),
            ProposalVote::Nay => write!(f, "nay"),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProposalVoteParseError {
    #[error("Invalid vote. Vote shall be yay or nay.")]
    InvalidVote,
}

impl FromStr for ProposalVote {
    type Err = ProposalVoteParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq("yay") {
            Ok(ProposalVote::Yay)
        } else if s.eq("nay") {
            Ok(ProposalVote::Nay)
        } else {
            Err(ProposalVoteParseError::InvalidVote)
        }
    }
}

/// The result of a proposal
pub enum TallyResult {
    /// Proposal was accepted
    Passed,
    /// Proposal was rejected
    Rejected,
    /// A critical error in tally computation
    Failed,
}

/// The result with votes of a proposal
pub struct ProposalResult {
    /// The result of a proposal
    pub result: TallyResult,
    /// The total voting power during the proposal tally
    pub total_voting_power: VotePower,
    /// The total voting power from yay votes
    pub total_yay_power: VotePower,
    /// The total voting power from nay votes (unused at the moment)
    pub total_nay_power: VotePower,
}

impl Display for ProposalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let percentage = Decimal::checked_div(
            self.total_yay_power.into(),
            self.total_voting_power.into(),
        )
        .unwrap_or_default();

        write!(
            f,
            "{} with {} yay votes over {} ({:.2}%)",
            self.result,
            self.total_yay_power / SCALE as u128,
            self.total_voting_power / SCALE as u128,
            percentage.checked_mul(100.into()).unwrap_or_default()
        )
    }
}

impl Display for TallyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TallyResult::Passed => write!(f, "passed"),
            TallyResult::Rejected => write!(f, "rejected"),
            TallyResult::Failed => write!(f, "failed"),
        }
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The proposal structure
pub struct Proposal {
    /// The proposal id
    pub id: Option<u64>,
    /// The proposal content
    pub content: BTreeMap<String, String>,
    /// The proposal author address
    pub author: Address,
    /// The epoch from which voting is allowed
    pub voting_start_epoch: Epoch,
    /// The epoch from which voting is stopped
    pub voting_end_epoch: Epoch,
    /// The epoch from which this changes are executed
    pub grace_epoch: Epoch,
    /// The code containing the storage changes
    pub proposal_code_path: Option<String>,
}

impl Display for Proposal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "id: {:?}, author: {:?}", self.id, self.author)
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum ProposalError {
    #[error("Invalid proposal data.")]
    InvalidProposalData,
}

impl TryFrom<Proposal> for InitProposalData {
    type Error = ProposalError;

    fn try_from(proposal: Proposal) -> Result<Self, Self::Error> {
        let proposal_code = if let Some(path) = proposal.proposal_code_path {
            match std::fs::read(path) {
                Ok(bytes) => Some(bytes),
                Err(_) => return Err(Self::Error::InvalidProposalData),
            }
        } else {
            None
        };

        Ok(InitProposalData {
            id: proposal.id,
            content: proposal.content.try_to_vec().unwrap(),
            author: proposal.author,
            voting_start_epoch: proposal.voting_start_epoch,
            voting_end_epoch: proposal.voting_end_epoch,
            grace_epoch: proposal.grace_epoch,
            proposal_code,
        })
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The offline proposal structure
pub struct OfflineProposal {
    /// The proposal content
    pub content: BTreeMap<String, String>,
    /// The proposal author address
    pub author: Address,
    /// The epoch from which this changes are executed
    pub tally_epoch: Epoch,
    /// The signature over proposal data
    pub signature: Signature,
    /// The address corresponding to the signature pk
    pub address: Address,
}

impl OfflineProposal {
    /// Create an offline proposal with a signature
    pub fn new(
        proposal: Proposal,
        address: Address,
        signing_key: &common::SecretKey,
    ) -> Self {
        let content_serialized = serde_json::to_vec(&proposal.content)
            .expect("Conversion to bytes shouldn't fail.");
        let author_serialized = serde_json::to_vec(&proposal.author)
            .expect("Conversion to bytes shouldn't fail.");
        let tally_epoch_serialized = serde_json::to_vec(&proposal.grace_epoch)
            .expect("Conversion to bytes shouldn't fail.");
        let proposal_serialized = &[
            content_serialized,
            author_serialized,
            tally_epoch_serialized,
        ]
        .concat();
        let proposal_data_hash = Hash::sha256(&proposal_serialized);
        let signature =
            common::SigScheme::sign(signing_key, &proposal_data_hash);
        Self {
            content: proposal.content,
            author: proposal.author,
            tally_epoch: proposal.grace_epoch,
            signature,
            address,
        }
    }

    /// Check whether the signature is valid or not
    pub fn check_signature(&self, public_key: &common::PublicKey) -> bool {
        let proposal_data_hash = self.compute_hash();
        common::SigScheme::verify_signature(
            public_key,
            &proposal_data_hash,
            &self.signature,
        )
        .is_ok()
    }

    /// Compute the hash of the proposal
    pub fn compute_hash(&self) -> Hash {
        let content_serialized = serde_json::to_vec(&self.content)
            .expect("Conversion to bytes shouldn't fail.");
        let author_serialized = serde_json::to_vec(&self.author)
            .expect("Conversion to bytes shouldn't fail.");
        let tally_epoch_serialized = serde_json::to_vec(&self.tally_epoch)
            .expect("Conversion to bytes shouldn't fail.");
        let proposal_serialized = &[
            content_serialized,
            author_serialized,
            tally_epoch_serialized,
        ]
        .concat();
        Hash::sha256(&proposal_serialized)
    }
}

#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
/// The offline proposal structure
pub struct OfflineVote {
    /// The proposal data hash
    pub proposal_hash: Hash,
    /// The proposal vote
    pub vote: ProposalVote,
    /// The signature over proposal data
    pub signature: Signature,
    /// The address corresponding to the signature pk
    pub address: Address,
}

impl OfflineVote {
    /// Create an offline vote for a proposal
    pub fn new(
        proposal: &OfflineProposal,
        vote: ProposalVote,
        address: Address,
        signing_key: &common::SecretKey,
    ) -> Self {
        let proposal_hash = proposal.compute_hash();
        let proposal_hash_data = proposal_hash
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let proposal_vote_data = vote
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let vote_serialized =
            &[proposal_hash_data, proposal_vote_data].concat();
        let signature = common::SigScheme::sign(signing_key, &vote_serialized);
        Self {
            proposal_hash,
            vote,
            signature,
            address,
        }
    }

    /// compute the hash of a proposal
    pub fn compute_hash(&self) -> Hash {
        let proposal_hash_data = self
            .proposal_hash
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let proposal_vote_data = self
            .vote
            .try_to_vec()
            .expect("Conversion to bytes shouldn't fail.");
        let vote_serialized =
            &[proposal_hash_data, proposal_vote_data].concat();

        Hash::sha256(vote_serialized)
    }

    /// Check whether the signature is valid or not
    pub fn check_signature(&self, public_key: &common::PublicKey) -> bool {
        let vote_data_hash = self.compute_hash();
        common::SigScheme::verify_signature(
            public_key,
            &vote_data_hash,
            &self.signature,
        )
        .is_ok()
    }
}
