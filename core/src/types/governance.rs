//! Files defyining the types used in governance.

use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Display};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::key::common::{self, Signature};
use crate::types::key::SigScheme;
use crate::types::storage::Epoch;
use crate::types::token::{
    Amount, DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES,
};

use super::token;

/// Type alias for vote power
pub type VotePower = token::Amount;

/// A PGF cocuncil composed of the address and spending cap
pub type Council = (Address, Amount);

/// The type of a governance vote with the optional associated Memo
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
pub enum VoteType {
    /// A default vote without Memo
    Default,
    /// A vote for the PGF council
    PGFCouncil(HashSet<Council>),
    /// A vote for ETH bridge carrying the signature over the proposed message
    ETHBridge(Signature),
}

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
    Yay(VoteType),
    /// No
    Nay,
}

impl ProposalVote {
    /// Check if a vote is yay
    pub fn is_yay(&self) -> bool {
        matches!(self, ProposalVote::Yay(_))
    }

    /// Check if vote is of type default
    pub fn is_default_vote(&self) -> bool {
        matches!(
            self,
            ProposalVote::Yay(VoteType::Default) | ProposalVote::Nay
        )
    }
}

impl Display for ProposalVote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalVote::Yay(vote_type) => match vote_type {
                VoteType::Default => write!(f, "yay"),
                VoteType::PGFCouncil(councils) => {
                    writeln!(f, "yay with councils:")?;
                    for (address, spending_cap) in councils {
                        writeln!(
                            f,
                            "Council: {}, spending cap: {}",
                            address,
                            spending_cap.to_string_native()
                        )?
                    }

                    Ok(())
                }
                VoteType::ETHBridge(sig) => {
                    write!(f, "yay with signature: {:#?}", sig)
                }
            },

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

/// The type of the tally
#[derive(Clone, Debug)]
pub enum Tally {
    /// Default proposal
    Default,
    /// PGF proposal
    PGFCouncil(Council)
}

/// The result of a proposal
#[derive(Clone, Debug)]
pub enum TallyResult {
    /// Proposal was accepted with the associated value
    Passed(Tally),
    /// Proposal was rejected
    Rejected,
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
        let percentage = DenominatedAmount {
            amount: Amount::from_uint(
                self.total_yay_power
                    .checked_div(self.total_voting_power)
                    .unwrap_or_default(),
                0,
            )
            .unwrap(),
            denom: 2.into(),
        };

        write!(
            f,
            "{} with {} yay votes over {} ({}%)",
            self.result,
            DenominatedAmount {
                amount: Amount::from_uint(self.total_yay_power, 0).unwrap(),
                denom: NATIVE_MAX_DECIMAL_PLACES.into()
            },
            DenominatedAmount {
                amount: Amount::from_uint(self.total_voting_power, 0).unwrap(),
                denom: NATIVE_MAX_DECIMAL_PLACES.into()
            },
            percentage
        )
    }
}

impl Display for TallyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TallyResult::Passed(vote) => match vote {
                Tally::Default => write!(f, "passed"),
                Tally::PGFCouncil((council, cap)) => write!(
                    f,
                    "passed with PGF council address: {}, spending cap: {}",
                    council,
                    cap.to_string_native()
                ),
            },
            TallyResult::Rejected => write!(f, "rejected"),
        }
    }
}

/// The type of a governance proposal
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub enum ProposalType {
    /// A default proposal with the optional path to wasm code
    Default(Option<String>),
    /// A PGF council proposal
    PGFCouncil,
    /// An ETH bridge proposal
    ETHBridge,
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
    /// The proposal type
    pub r#type: ProposalType,
    /// The epoch from which voting is allowed
    pub voting_start_epoch: Epoch,
    /// The epoch from which voting is stopped
    pub voting_end_epoch: Epoch,
    /// The epoch from which this changes are executed
    pub grace_epoch: Epoch,
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
        let proposal_data_hash = Hash::sha256(proposal_serialized);
        let signature =
            common::SigScheme::sign(signing_key, proposal_data_hash);
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
        Hash::sha256(proposal_serialized)
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
        let signature = common::SigScheme::sign(signing_key, vote_serialized);
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
