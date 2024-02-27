use std::collections::HashMap;
use std::fmt::Display;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::dec::Dec;
use namada_core::storage::Epoch;
use namada_core::token;

use super::cli::offline::OfflineVote;
use super::storage::proposal::ProposalType;
use super::storage::vote::ProposalVote;

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
#[derive(Copy, Debug, Clone, BorshSerialize, BorshDeserialize)]
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
                let at_least_two_third_voted = Self::get_total_voted_power(
                    yay_voting_power,
                    nay_voting_power,
                    abstain_voting_power,
                ) >= total_voting_power
                    .mul_ceil(Dec::two() / 3);

                let at_least_two_third_voted_yay = yay_voting_power
                    >= (nay_voting_power + yay_voting_power)
                        .mul_ceil(Dec::two() / 3);

                at_least_two_third_voted && at_least_two_third_voted_yay
            }
            TallyType::OneHalfOverOneThird => {
                let at_least_one_third_voted = Self::get_total_voted_power(
                    yay_voting_power,
                    nay_voting_power,
                    abstain_voting_power,
                ) >= total_voting_power
                    .mul_ceil(Dec::one() / 3);

                // Yay votes must be more than half of the total votes
                let more_than_half_voted_yay =
                    yay_voting_power > nay_voting_power;
                at_least_one_third_voted && more_than_half_voted_yay
            }
            TallyType::LessOneHalfOverOneThirdNay => {
                let less_than_one_third = Self::get_total_voted_power(
                    yay_voting_power,
                    nay_voting_power,
                    abstain_voting_power,
                ) < total_voting_power
                    .mul_ceil(Dec::one() / 3);

                // Nay votes must be less than half of the total votes
                let more_than_half_voted_yay =
                    yay_voting_power > nay_voting_power;

                less_than_one_third || more_than_half_voted_yay
            }
        };

        if passed { Self::Passed } else { Self::Rejected }
    }

    fn get_total_voted_power(
        yay_voting_power: VotePower,
        nay_voting_power: VotePower,
        abstain_voting_power: VotePower,
    ) -> VotePower {
        yay_voting_power + nay_voting_power + abstain_voting_power
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
    /// Return true if at least 2/3 of the total voting power voted and at least
    /// two third of the non-abstained voting power voted nay
    pub fn two_thirds_nay_over_two_thirds_total(&self) -> bool {
        let at_least_two_third_voted = self.total_yay_power
            + self.total_nay_power
            + self.total_abstain_power
            >= self.total_voting_power.mul_ceil(Dec::two() / 3);

        let at_least_two_thirds_voted_nay = self.total_nay_power
            >= (self.total_yay_power + self.total_nay_power)
                .mul_ceil(Dec::two() / 3);

        at_least_two_third_voted && at_least_two_thirds_voted_nay
    }
}

impl Display for ProposalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let threshold = match self.tally_type {
            TallyType::TwoThirds => {
                self.total_voting_power.mul_ceil(Dec::two() / 3)
            }
            _ => self.total_voting_power.mul_ceil(Dec::one() / 3),
        };

        let thresh_frac =
            Dec::from(threshold) / Dec::from(self.total_voting_power);

        write!(
            f,
            "{} with {} yay votes, {} nay votes and {} abstain votes, total \
             voting power: {}, threshold (fraction) of total voting power \
             needed to tally: {} ({})",
            self.result,
            self.total_yay_power.to_string_native(),
            self.total_nay_power.to_string_native(),
            self.total_abstain_power.to_string_native(),
            self.total_voting_power.to_string_native(),
            threshold.to_string_native(),
            thresh_frac
        )
    }
}

/// General representation of a vote
#[derive(Debug, Clone)]
pub enum TallyVote {
    /// Represent a vote for a proposal onchain
    OnChain(ProposalVote),
    /// Represent a vote for a proposal offline
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
    pub fn is_same_side(&self, other: &TallyVote) -> bool {
        match (self, other) {
            (TallyVote::OnChain(vote), TallyVote::OnChain(other_vote)) => {
                vote == other_vote
            }
            (TallyVote::Offline(vote), TallyVote::Offline(other_vote)) => {
                vote.vote == other_vote.vote
            }
            _ => false,
        }
    }
}

/// Proposal structure holding votes information necessary to compute the
/// outcome
#[derive(Default, Debug, Clone)]
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

impl ProposalVotes {
    /// Add vote correspoding to a validator
    pub fn add_validator(
        &mut self,
        address: &Address,
        voting_power: VotePower,
        vote: TallyVote,
    ) {
        match self.validators_vote.insert(address.clone(), vote) {
            None => {
                self.validator_voting_power
                    .insert(address.clone(), voting_power);
            }
            // the value was update, this should never happen
            _ => tracing::error!(
                "Duplicate vote for validator {}",
                address.clone()
            ),
        };
    }

    /// Add vote corresponding to a delegator
    pub fn add_delegator(
        &mut self,
        address: &Address,
        validator_address: &Address,
        voting_power: VotePower,
        vote: TallyVote,
    ) {
        self.delegator_voting_power
            .entry(address.clone())
            .or_default()
            .insert(validator_address.clone(), voting_power);
        self.delegators_vote.insert(address.clone(), vote);
    }
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
                    validator_vote.is_same_side(delegator_vote);

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

#[cfg(test)]
mod test {
    use std::ops::{Add, Sub};

    use namada_core::address;

    use super::*;

    #[test]
    fn test_proposal_result_no_votes_should_fail() {
        let proposal_votes = ProposalVotes::default();

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                token::Amount::from_u64(1),
                tally_type,
            );
            let _result = if matches!(
                tally_type,
                TallyType::LessOneHalfOverOneThirdNay
            ) {
                TallyResult::Passed
            } else {
                TallyResult::Rejected
            };
            assert!(
                matches!(proposal_result.result, _result),
                "{tally_type:?}"
            );
        }
    }

    #[test]
    fn test_proposal_result_one_validator_with_100_voting_power() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            );
            assert!(
                matches!(proposal_result.result, TallyResult::Passed),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power,
                validator_voting_power
            );
            assert_eq!(proposal_result.total_yay_power, validator_voting_power);
            assert_eq!(proposal_result.total_nay_power, token::Amount::zero());
            assert_eq!(
                proposal_result.total_abstain_power,
                token::Amount::zero()
            );
        }
    }

    #[test]
    fn test_proposal_one() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(90);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            );
            assert!(
                matches!(proposal_result.result, TallyResult::Passed),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power,
                validator_voting_power
            );
            assert_eq!(proposal_result.total_yay_power, validator_voting_power);
            assert_eq!(proposal_result.total_nay_power, token::Amount::zero());
            assert_eq!(
                proposal_result.total_abstain_power,
                token::Amount::zero()
            );
        }
    }

    #[test]
    fn test_proposal_two() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(90);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            );
            assert!(
                matches!(proposal_result.result, TallyResult::Rejected),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power,
                validator_voting_power
            );
            assert_eq!(
                proposal_result.total_yay_power,
                validator_voting_power.sub(delegator_voting_power)
            );
            assert_eq!(proposal_result.total_nay_power, delegator_voting_power);
            assert_eq!(
                proposal_result.total_abstain_power,
                token::Amount::zero()
            );
        }
    }

    #[test]
    fn test_proposal_three() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(90);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay.into(),
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(10);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address,
            delegator_voting_power_two,
            ProposalVote::Abstain.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            );
            assert!(
                matches!(proposal_result.result, TallyResult::Rejected),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power, validator_voting_power,
                "total"
            );
            assert_eq!(
                proposal_result.total_yay_power,
                validator_voting_power
                    .sub(delegator_voting_power)
                    .sub(delegator_voting_power_two),
                "yay"
            );
            assert_eq!(
                proposal_result.total_nay_power, delegator_voting_power,
                "nay"
            );
            assert_eq!(
                proposal_result.total_abstain_power, delegator_voting_power_two,
                "abstain"
            );
        }
    }

    // should pass
    #[test]
    fn test_proposal_four() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(10);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay.into(),
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(20);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address,
            delegator_voting_power_two,
            ProposalVote::Abstain.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            );
            assert!(
                matches!(proposal_result.result, TallyResult::Passed),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power, validator_voting_power,
                "total"
            );
            assert_eq!(
                proposal_result.total_yay_power,
                validator_voting_power
                    .sub(delegator_voting_power)
                    .sub(delegator_voting_power_two),
                "yay"
            );
            assert_eq!(
                proposal_result.total_nay_power, delegator_voting_power,
                "nay"
            );
            assert_eq!(
                proposal_result.total_abstain_power, delegator_voting_power_two,
                "abstain"
            );
        }
    }

    // should pass
    #[test]
    fn test_proposal_five() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(20);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address,
            delegator_voting_power_two,
            ProposalVote::Abstain.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            );
            assert!(
                matches!(proposal_result.result, TallyResult::Passed),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power, validator_voting_power,
                "total"
            );
            assert_eq!(
                proposal_result.total_yay_power,
                validator_voting_power.sub(delegator_voting_power_two),
                "yay"
            );
            assert_eq!(
                proposal_result.total_nay_power,
                token::Amount::zero(),
                "nay"
            );
            assert_eq!(
                proposal_result.total_abstain_power, delegator_voting_power_two,
                "abstain"
            );
        }
    }

    // should pass
    #[test]
    fn test_proposal_six() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Nay.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power.add(validator_voting_power_two),
                tally_type,
            );
            let _result = if matches!(
                tally_type,
                TallyType::LessOneHalfOverOneThirdNay
            ) {
                TallyResult::Rejected
            } else {
                TallyResult::Passed
            };
            assert!(
                matches!(proposal_result.result, _result),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power,
                validator_voting_power.add(validator_voting_power_two),
                "total"
            );
            assert_eq!(
                proposal_result.total_yay_power, validator_voting_power,
                "yay"
            );
            assert_eq!(
                proposal_result.total_nay_power, validator_voting_power_two,
                "nay"
            );
            assert_eq!(
                proposal_result.total_abstain_power,
                token::Amount::zero(),
                "abstain"
            );
        }
    }

    #[test]
    fn test_proposal_seven() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Nay.into(),
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(50);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Abstain.into(),
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoThirds,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power.add(validator_voting_power_two),
                tally_type,
            );
            let _result =
                if matches!(tally_type, TallyType::OneHalfOverOneThird) {
                    TallyResult::Passed
                } else {
                    TallyResult::Rejected
                };
            assert!(
                matches!(proposal_result.result, _result),
                "{tally_type:?}"
            );
            assert_eq!(
                proposal_result.total_voting_power,
                validator_voting_power
                    .checked_add(validator_voting_power_two)
                    .unwrap(),
                "total"
            );
            assert_eq!(
                proposal_result.total_yay_power, validator_voting_power,
                "yay"
            );
            assert_eq!(
                proposal_result.total_nay_power,
                validator_voting_power_two.sub(delegator_voting_power_two),
                "nay"
            );
            assert_eq!(
                proposal_result.total_abstain_power, delegator_voting_power_two,
                "abstain"
            );
        }
    }

    #[test]
    fn test_proposal_eight() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Yay.into(),
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Abstain.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            validator_voting_power.add(validator_voting_power_two),
            TallyType::TwoThirds,
        );

        assert!(matches!(proposal_result.result, TallyResult::Passed));
        assert_eq!(
            proposal_result.total_voting_power,
            validator_voting_power.add(validator_voting_power_two),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            validator_voting_power
                .add(validator_voting_power_two)
                .sub(delegator_voting_power_two),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power,
            token::Amount::zero(),
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power, delegator_voting_power_two,
            "abstain"
        );
    }

    #[test]
    fn test_proposal_nine() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address,
            validator_voting_power,
            ProposalVote::Yay.into(),
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Yay.into(),
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Abstain.into(),
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(50);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            validator_voting_power.add(validator_voting_power_two),
            TallyType::TwoThirds,
        );

        assert!(matches!(proposal_result.result, TallyResult::Rejected));
        assert_eq!(
            proposal_result.total_voting_power,
            validator_voting_power.add(validator_voting_power_two),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            validator_voting_power
                .add(validator_voting_power_two)
                .sub(delegator_voting_power_two)
                .sub(delegator_voting_power),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power, delegator_voting_power,
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power, delegator_voting_power_two,
            "abstain"
        );
    }

    #[test]
    fn test_proposal_ten() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_address_two = address::testing::established_address_2();

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Abstain.into(),
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(50);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            delegator_voting_power_two.add(delegator_voting_power),
            TallyType::TwoThirds,
        );

        assert!(matches!(proposal_result.result, TallyResult::Rejected));
        assert_eq!(
            proposal_result.total_voting_power,
            delegator_voting_power.add(delegator_voting_power_two),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            token::Amount::zero(),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power, delegator_voting_power,
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power, delegator_voting_power_two,
            "abstain"
        );
    }

    #[test]
    fn test_proposal_eleven() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_address_two = address::testing::established_address_2();

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(34);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Yay.into(),
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(200),
            TallyType::TwoThirds,
        );

        assert!(matches!(proposal_result.result, TallyResult::Passed));
        assert_eq!(
            proposal_result.total_voting_power,
            token::Amount::from(200),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            token::Amount::from(134),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power,
            token::Amount::zero(),
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power,
            token::Amount::zero(),
            "abstain"
        );
    }

    #[test]
    fn test_proposal_twelve() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_address_two = address::testing::established_address_2();

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(34);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Yay.into(),
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(403),
            TallyType::OneHalfOverOneThird,
        );

        assert!(matches!(proposal_result.result, TallyResult::Rejected));
        assert_eq!(
            proposal_result.total_voting_power,
            token::Amount::from(403),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            token::Amount::from(134),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power,
            token::Amount::zero(),
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power,
            token::Amount::zero(),
            "abstain"
        );
    }

    #[test]
    fn test_proposal_thirteen() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_address_two = address::testing::established_address_2();

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(34);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Yay.into(),
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(402),
            TallyType::OneHalfOverOneThird,
        );

        assert!(matches!(proposal_result.result, TallyResult::Passed));
        assert_eq!(
            proposal_result.total_voting_power,
            token::Amount::from(402),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            token::Amount::from(134),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power,
            token::Amount::zero(),
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power,
            token::Amount::zero(),
            "abstain"
        );
    }

    #[test]
    fn test_proposal_fourteen() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_address_two = address::testing::established_address_2();

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(30);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Nay.into(),
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(60);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(100),
            TallyType::LessOneHalfOverOneThirdNay,
        );

        assert!(matches!(proposal_result.result, TallyResult::Rejected));
        assert_eq!(
            proposal_result.total_voting_power,
            token::Amount::from(100),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            token::Amount::from(0),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power,
            token::Amount::from(90),
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power,
            token::Amount::zero(),
            "abstain"
        );

        assert!(proposal_result.two_thirds_nay_over_two_thirds_total())
    }

    #[test]
    fn test_proposal_fifthteen() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_address_two = address::testing::established_address_2();

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(30);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Nay.into(),
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(60);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay.into(),
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(271),
            TallyType::LessOneHalfOverOneThirdNay,
        );

        assert!(matches!(proposal_result.result, TallyResult::Passed));
        assert_eq!(
            proposal_result.total_voting_power,
            token::Amount::from(271),
            "total"
        );
        assert_eq!(
            proposal_result.total_yay_power,
            token::Amount::from(0),
            "yay"
        );
        assert_eq!(
            proposal_result.total_nay_power,
            token::Amount::from(90),
            "nay"
        );
        assert_eq!(
            proposal_result.total_abstain_power,
            token::Amount::zero(),
            "abstain"
        );

        assert!(!proposal_result.two_thirds_nay_over_two_thirds_total())
    }
}
