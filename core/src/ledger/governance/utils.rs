use std::collections::HashMap;
use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};

use super::cli::offline::OfflineVote;
use super::storage::proposal::ProposalType;
use super::storage::vote::ProposalVote;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

/// Proposal status
pub enum ProposalStatus {
    /// Pending proposal status
    Pending,
    /// Ongoing proposal status
    OnGoing,
    /// Ended proposal status
    Ended,
}

impl Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalStatus::Pending => write!(f, "pending"),
            ProposalStatus::OnGoing => write!(f, "on-going"),
            ProposalStatus::Ended => write!(f, "ended"),
        }
    }
}

/// Alias to comulate voting power
pub type VotePower = token::Amount;

/// Structure rappresenting a proposal vote
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Vote {
    /// Field holding the address of the validator
    pub validator: Address,
    /// Field holding the address of the delegator
    pub delegator: Address,
    /// Field holding vote data
    pub data: ProposalVote,
}

impl Display for Vote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Voter: {}", self.delegator)?;
        write!(f, "Vote: {}", self.data)
    }
}

impl Vote {
    /// Check if a vote is from a validator
    pub fn is_validator(&self) -> bool {
        self.validator.eq(&self.delegator)
    }
}

/// Represent a tally type
#[derive(Copy, Clone, BorshSerialize, BorshDeserialize)]
pub enum TallyType {
    /// Represent a tally type for proposal requiring 2/3 of the total voting
    /// power to be yay
    TwoThirds,
    /// Represent a tally type for proposal requiring 1/2 of yay votes over at
    /// least 1/3 of the voting power
    OneHalfOverOneThird,
    /// Represent a tally type for proposal requiring less than 1/2 of nay
    /// votes over at least 1/3 of the voting power
    LessOneHalfOverOneThirdNay,
}

impl TallyType {
    /// Compute the type of tally for a proposal
    pub fn from(proposal_type: ProposalType, is_steward: bool) -> Self {
        match (proposal_type, is_steward) {
            (ProposalType::Default(_), _) => TallyType::TwoThirds,
            (ProposalType::PGFSteward(_), _) => TallyType::OneHalfOverOneThird,
            (ProposalType::PGFPayment(_), true) => {
                TallyType::LessOneHalfOverOneThirdNay
            }
            (ProposalType::PGFPayment(_), false) => {
                TallyType::OneHalfOverOneThird
            }
        }
    }
}

/// The result of a proposal
#[derive(Copy, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum TallyResult {
    /// Proposal was accepted with the associated value
    Passed,
    /// Proposal was rejected
    Rejected,
}

impl Display for TallyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TallyResult::Passed => write!(f, "passed"),
            TallyResult::Rejected => write!(f, "rejected"),
        }
    }
}

impl TallyResult {
    /// Create a new tally result
    pub fn new(
        tally_type: &TallyType,
        yay_voting_power: VotePower,
        nay_voting_power: VotePower,
        abstain_voting_power: VotePower,
        total_voting_power: VotePower,
    ) -> Self {
        let passed = match tally_type {
            TallyType::TwoThirds => {
                yay_voting_power >= total_voting_power * 2 / 3
            }
            TallyType::OneHalfOverOneThird => {
                let at_least_one_third_voted =
                    yay_voting_power + nay_voting_power + abstain_voting_power
                        >= total_voting_power / 3;

                // At least half of non-abstained votes are yay
                let at_last_half_voted_yay =
                    yay_voting_power >= nay_voting_power;
                at_least_one_third_voted && at_last_half_voted_yay
            }
            TallyType::LessOneHalfOverOneThirdNay => {
                let less_one_third_voted =
                    yay_voting_power + nay_voting_power + abstain_voting_power
                        < total_voting_power / 3;

                // More than half of non-abstained votes are yay
                let more_than_half_voted_yay =
                    yay_voting_power > nay_voting_power;
                less_one_third_voted || more_than_half_voted_yay
            }
        };

        if passed { Self::Passed } else { Self::Rejected }
    }
}

/// The result with votes of a proposal
#[derive(Clone, Copy, BorshDeserialize, BorshSerialize)]
pub struct ProposalResult {
    /// The result of a proposal
    pub result: TallyResult,
    /// The type of tally required for this proposal
    pub tally_type: TallyType,
    /// The total voting power during the proposal tally
    pub total_voting_power: VotePower,
    /// The total voting power from yay votes
    pub total_yay_power: VotePower,
    /// The total voting power from nay votes
    pub total_nay_power: VotePower,
    /// The total voting power from abstained votes
    pub total_abstain_power: VotePower,
}

impl ProposalResult {
    /// Return true if at least 1/3 of the total voting power voted and at least
    /// two third of the non-abstained voting power voted nay
    pub fn two_thirds_nay_over_two_thirds_total(&self) -> bool {
        let at_least_two_thirds_voted = self.total_yay_power
            + self.total_nay_power
            + self.total_abstain_power
            >= self.total_voting_power * 2 / 3;

        let at_least_two_thirds_nay = self.total_nay_power
            >= (self.total_nay_power + self.total_yay_power) * 2 / 3;

        at_least_two_thirds_voted && at_least_two_thirds_nay
    }
}

impl Display for ProposalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let threshold = match self.tally_type {
            TallyType::TwoThirds => self.total_voting_power / 3 * 2,
            _ => {
                let threshold_one_third = self.total_voting_power / 3;
                threshold_one_third / 2
            }
        };

        write!(
            f,
            "{} with {} yay votes, {} nay votes and {} abstain votes, total \
             voting power: {} threshold was: {}",
            self.result,
            self.total_yay_power.to_string_native(),
            self.total_nay_power.to_string_native(),
            self.total_abstain_power.to_string_native(),
            self.total_voting_power.to_string_native(),
            threshold.to_string_native()
        )
    }
}

/// /// General rappresentation of a vote
#[derive(Debug)]
pub enum TallyVote {
    /// Rappresent a vote for a proposal onchain
    OnChain(ProposalVote),
    /// Rappresent a vote for a proposal offline
    Offline(OfflineVote),
}

impl From<ProposalVote> for TallyVote {
    fn from(vote: ProposalVote) -> Self {
        Self::OnChain(vote)
    }
}

impl From<OfflineVote> for TallyVote {
    fn from(vote: OfflineVote) -> Self {
        Self::Offline(vote)
    }
}

impl TallyVote {
    /// Check if a vote is yay
    pub fn is_yay(&self) -> bool {
        match self {
            TallyVote::OnChain(vote) => vote.is_yay(),
            TallyVote::Offline(vote) => vote.is_yay(),
        }
    }

    /// Check if a vote is nay
    pub fn is_nay(&self) -> bool {
        match self {
            TallyVote::OnChain(vote) => vote.is_nay(),
            TallyVote::Offline(vote) => vote.is_nay(),
        }
    }

    /// Check if a vote is abstain
    pub fn is_abstain(&self) -> bool {
        match self {
            TallyVote::OnChain(vote) => vote.is_abstain(),
            TallyVote::Offline(vote) => vote.is_abstain(),
        }
    }

    /// Check if two votes are equal, returns an error if the variants of the
    /// two instances are different
    pub fn is_same_side(
        &self,
        other: &TallyVote,
    ) -> Result<bool, &'static str> {
        match (self, other) {
            (TallyVote::OnChain(vote), TallyVote::OnChain(other_vote)) => {
                Ok(vote == other_vote)
            }
            (TallyVote::Offline(vote), TallyVote::Offline(other_vote)) => {
                Ok(vote.vote == other_vote.vote)
            }
            _ => Err("Cannot compare different variants of governance votes"),
        }
    }
}

/// Proposal structure holding votes information necessary to compute the
/// outcome
#[derive(Default, Debug)]
pub struct ProposalVotes {
    /// Map from validator address to vote
    pub validators_vote: HashMap<Address, TallyVote>,
    /// Map from validator to their voting power
    pub validator_voting_power: HashMap<Address, VotePower>,
    /// Map from delegation address to their vote
    pub delegators_vote: HashMap<Address, TallyVote>,
    /// Map from delegator address to the corresponding validator voting power
    pub delegator_voting_power: HashMap<Address, HashMap<Address, VotePower>>,
}

/// Compute the result of a proposal
pub fn compute_proposal_result(
    votes: ProposalVotes,
    total_voting_power: VotePower,
    tally_type: TallyType,
) -> ProposalResult {
    let mut yay_voting_power = VotePower::default();
    let mut nay_voting_power = VotePower::default();
    let mut abstain_voting_power = VotePower::default();

    for (address, vote_power) in votes.validator_voting_power {
        let vote_type = votes.validators_vote.get(&address);
        if let Some(vote) = vote_type {
            if vote.is_yay() {
                yay_voting_power += vote_power;
            } else if vote.is_nay() {
                nay_voting_power += vote_power;
            } else if vote.is_abstain() {
                abstain_voting_power += vote_power;
            }
        }
    }

    for (delegator, delegations) in votes.delegator_voting_power {
        let delegator_vote = match votes.delegators_vote.get(&delegator) {
            Some(vote) => vote,
            None => continue,
        };
        for (validator, voting_power) in delegations {
            let validator_vote = votes.validators_vote.get(&validator);
            if let Some(validator_vote) = validator_vote {
                let validator_vote_is_same_side =
                    match validator_vote.is_same_side(delegator_vote) {
                        Ok(result) => result,
                        Err(_) => {
                            // Unexpected path, all the votes should be
                            // validated by the VP and only online votes should
                            // be allowed in storage
                            tracing::warn!(
                                "Found unexpected offline vote type: forcing \
                                 the proposal to fail."
                            );
                            // Force failure of the proposal
                            return ProposalResult {
                                result: TallyResult::Rejected,
                                tally_type,
                                total_voting_power: VotePower::default(),
                                total_yay_power: VotePower::default(),
                                total_nay_power: VotePower::default(),
                                total_abstain_power: VotePower::default(),
                            };
                        }
                    };
                if !validator_vote_is_same_side {
                    if delegator_vote.is_yay() {
                        yay_voting_power += voting_power;
                        if validator_vote.is_nay() {
                            nay_voting_power -= voting_power;
                        } else if validator_vote.is_abstain() {
                            abstain_voting_power -= voting_power;
                        }
                    } else if delegator_vote.is_nay() {
                        nay_voting_power += voting_power;
                        if validator_vote.is_yay() {
                            yay_voting_power -= voting_power;
                        } else if validator_vote.is_abstain() {
                            abstain_voting_power -= voting_power;
                        }
                    } else if delegator_vote.is_abstain() {
                        abstain_voting_power += voting_power;
                        if validator_vote.is_yay() {
                            yay_voting_power -= voting_power;
                        } else if validator_vote.is_nay() {
                            nay_voting_power -= voting_power;
                        }
                    }
                }
            } else if delegator_vote.is_yay() {
                yay_voting_power += voting_power;
            } else if delegator_vote.is_nay() {
                nay_voting_power += voting_power;
            } else if delegator_vote.is_abstain() {
                abstain_voting_power += voting_power;
            }
        }
    }

    let tally_result = TallyResult::new(
        &tally_type,
        yay_voting_power,
        nay_voting_power,
        abstain_voting_power,
        total_voting_power,
    );

    ProposalResult {
        result: tally_result,
        tally_type,
        total_voting_power,
        total_yay_power: yay_voting_power,
        total_nay_power: nay_voting_power,
        total_abstain_power: abstain_voting_power,
    }
}

/// Calculate the valid voting window for validator given a proposal epoch
/// details
pub fn is_valid_validator_voting_period(
    current_epoch: Epoch,
    voting_start_epoch: Epoch,
    voting_end_epoch: Epoch,
) -> bool {
    if voting_start_epoch >= voting_end_epoch {
        false
    } else {
        let duration = voting_end_epoch - voting_start_epoch;
        let two_third_duration = (duration / 3) * 2;
        current_epoch <= voting_start_epoch + two_third_duration
    }
}
