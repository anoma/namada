use std::fmt::Display;
use std::str::FromStr;

use namada_core::address::Address;
use namada_core::arith::{self, checked};
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::chain::Epoch;
use namada_core::collections::HashMap;
use namada_core::dec::Dec;
use namada_core::token;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;

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
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshDeserializer)]
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

/// Represents a tally type that describes the voting requirements for a
/// proposal to pass.
#[derive(
    Copy, Debug, Clone, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
pub enum TallyType {
    /// The `yay` votes are at least 2/3 of the non-abstain votes, and 2/3 of
    /// the total voting power has voted
    TwoFifths,
    /// There are more `yay` votes than `nay` votes, and at least 1/3 of the
    /// total voting power has voted
    OneHalfOverOneThird,
    /// Either less than 1/3 of the total voting power voted, or there are more
    /// `yay` votes than `nay` votes
    LessOneHalfOverOneThirdNay,
}

impl TallyType {
    /// The type of tally used for each proposal type
    pub fn from(proposal_type: ProposalType, is_steward: bool) -> Self {
        match (proposal_type, is_steward) {
            (ProposalType::Default, _) => TallyType::TwoFifths,
            (ProposalType::DefaultWithWasm(_), _) => TallyType::TwoFifths,
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
#[derive(
    Copy, Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
pub enum TallyResult {
    /// Proposal was accepted with the associated value
    Passed,
    /// Proposal was rejected
    Rejected,
}

impl Display for TallyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TallyResult::Passed => write!(f, "Passed"),
            TallyResult::Rejected => write!(f, "Rejected"),
        }
    }
}

impl FromStr for TallyResult {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "passed" => Ok(Self::Passed),
            "rejected" => Ok(Self::Rejected),
            t => Err(format!(
                "Tally result value of {t:?} does not match \"passed\" nor \
                 \"rejected\""
            )),
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
    ) -> Result<Self, arith::Error> {
        let passed = match tally_type {
            TallyType::TwoFifths => {
                let at_least_two_fifths_voted = Self::get_total_voted_power(
                    yay_voting_power,
                    nay_voting_power,
                    abstain_voting_power,
                )? >= total_voting_power
                    .mul_ceil(Dec::two_fifths())?;

                // yay >= 2/3 * (yay + nay) ---> yay >= 2 * nay
                let at_least_two_third_voted_yay = yay_voting_power
                    >= checked!(nay_voting_power + nay_voting_power)?;

                at_least_two_fifths_voted && at_least_two_third_voted_yay
            }
            TallyType::OneHalfOverOneThird => {
                let at_least_one_third_voted = Self::get_total_voted_power(
                    yay_voting_power,
                    nay_voting_power,
                    abstain_voting_power,
                )? >= total_voting_power
                    .mul_ceil(Dec::one_third())?;

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
                )? < total_voting_power
                    .mul_ceil(Dec::one_third())?;

                // Nay votes must be less than half of the total votes
                let more_than_half_voted_yay =
                    yay_voting_power > nay_voting_power;

                less_than_one_third || more_than_half_voted_yay
            }
        };

        Ok(if passed { Self::Passed } else { Self::Rejected })
    }

    fn get_total_voted_power(
        yay_voting_power: VotePower,
        nay_voting_power: VotePower,
        abstain_voting_power: VotePower,
    ) -> Result<VotePower, arith::Error> {
        checked!(yay_voting_power + nay_voting_power + abstain_voting_power)
    }
}

/// The result with votes of a proposal
#[derive(
    Clone, Debug, Copy, BorshDeserialize, BorshSerialize, BorshDeserializer,
)]
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
    /// two third of the non-abstained voting power voted nay.
    /// Returns `false` if any arithmetic fails.
    pub fn two_thirds_nay_over_two_thirds_total(&self) -> bool {
        (|| {
            let two_thirds_power =
                self.total_voting_power.mul_ceil(Dec::two_thirds())?;
            let at_least_two_third_voted = checked!(
                self.total_yay_power
                    + self.total_nay_power
                    + self.total_abstain_power
                    >= two_thirds_power
            )?;

            // nay >= 2/3 * (yay + nay) ---> nay >= 2 * yay
            let at_least_two_thirds_voted_nay = self.total_nay_power
                >= checked!(self.total_yay_power + self.total_yay_power)?;

            Ok::<bool, arith::Error>(
                at_least_two_third_voted && at_least_two_thirds_voted_nay,
            )
        })()
        .unwrap_or_default()
    }
}

impl Display for ProposalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let threshold = match self.tally_type {
            TallyType::TwoFifths => {
                self.total_voting_power.mul_ceil(Dec::two_fifths())
            }
            TallyType::LessOneHalfOverOneThirdNay => Ok(token::Amount::zero()),
            _ => self.total_voting_power.mul_ceil(Dec::one_third()),
        }
        .unwrap();

        let thresh_frac = Dec::try_from(threshold)
            .unwrap()
            .checked_div(Dec::try_from(self.total_voting_power).unwrap())
            .unwrap();

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

/// Proposal structure holding votes information necessary to compute the
/// outcome
#[derive(Default, Debug, Clone)]
pub struct ProposalVotes {
    /// Map from validator address to vote
    pub validators_vote: HashMap<Address, ProposalVote>,
    /// Map from validator to their voting power
    pub validator_voting_power: HashMap<Address, VotePower>,
    /// Map from delegation address to their vote
    pub delegators_vote: HashMap<Address, ProposalVote>,
    /// Map from delegator address to the corresponding validator voting power
    pub delegator_voting_power: HashMap<Address, HashMap<Address, VotePower>>,
}

impl ProposalVotes {
    /// Add vote corresponding to a validator
    pub fn add_validator(
        &mut self,
        address: &Address,
        voting_power: VotePower,
        vote: ProposalVote,
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
        vote: ProposalVote,
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
) -> Result<ProposalResult, arith::Error> {
    let mut yay_voting_power = VotePower::default();
    let mut nay_voting_power = VotePower::default();
    let mut abstain_voting_power = VotePower::default();

    for (address, vote_power) in votes.validator_voting_power {
        let vote_type = votes.validators_vote.get(&address);
        if let Some(vote) = vote_type {
            if vote.is_yay() {
                checked!(yay_voting_power += vote_power)?;
            } else if vote.is_nay() {
                checked!(nay_voting_power += vote_power)?;
            } else if vote.is_abstain() {
                checked!(abstain_voting_power += vote_power)?;
            }
        }
    }

    for (delegator, delegations) in votes.delegator_voting_power {
        let delegator_vote = match votes.delegators_vote.get(&delegator) {
            Some(vote) => vote,
            None => continue,
        };
        for (validator, vote_power) in delegations {
            let validator_vote = votes.validators_vote.get(&validator);
            if let Some(validator_vote) = validator_vote {
                let validator_vote_is_same_side =
                    validator_vote.is_same_side(delegator_vote);

                if !validator_vote_is_same_side {
                    if delegator_vote.is_yay() {
                        yay_voting_power =
                            checked!(yay_voting_power + vote_power)?;
                        if validator_vote.is_nay() {
                            nay_voting_power =
                                checked!(nay_voting_power - vote_power)?;
                        } else if validator_vote.is_abstain() {
                            abstain_voting_power =
                                checked!(abstain_voting_power - vote_power)?;
                        }
                    } else if delegator_vote.is_nay() {
                        nay_voting_power =
                            checked!(nay_voting_power + vote_power)?;
                        if validator_vote.is_yay() {
                            yay_voting_power =
                                checked!(yay_voting_power - vote_power)?;
                        } else if validator_vote.is_abstain() {
                            abstain_voting_power =
                                checked!(abstain_voting_power - vote_power)?;
                        }
                    } else if delegator_vote.is_abstain() {
                        abstain_voting_power =
                            checked!(abstain_voting_power + vote_power)?;
                        if validator_vote.is_yay() {
                            yay_voting_power =
                                checked!(yay_voting_power - vote_power)?;
                        } else if validator_vote.is_nay() {
                            nay_voting_power =
                                checked!(nay_voting_power - vote_power)?;
                        }
                    }
                }
            } else if delegator_vote.is_yay() {
                checked!(yay_voting_power += vote_power)?;
            } else if delegator_vote.is_nay() {
                checked!(nay_voting_power += vote_power)?;
            } else if delegator_vote.is_abstain() {
                checked!(abstain_voting_power += vote_power)?;
            }
        }
    }

    let tally_result = TallyResult::new(
        &tally_type,
        yay_voting_power,
        nay_voting_power,
        abstain_voting_power,
        total_voting_power,
    )?;

    Ok(ProposalResult {
        result: tally_result,
        tally_type,
        total_voting_power,
        total_yay_power: yay_voting_power,
        total_nay_power: nay_voting_power,
        total_abstain_power: abstain_voting_power,
    })
}

/// Calculate the valid voting window for a validator given proposal epoch
/// details. The valid window is within 2/3 of the voting period.
/// NOTE: technically the window can be more generous than 2/3 since the end
/// epoch is a valid epoch for voting too.
/// Returns `false` if any arithmetic fails.
pub fn is_valid_validator_voting_period(
    current_epoch: Epoch,
    voting_start_epoch: Epoch,
    voting_end_epoch: Epoch,
) -> bool {
    if voting_start_epoch >= voting_end_epoch {
        false
    } else {
        (|| {
            // From e_cur <= e_start + 2/3 * (e_end - e_start)
            let is_within_two_thirds = checked!(
                current_epoch * 3 <= voting_start_epoch + voting_end_epoch * 2
            )
            .ok()?;

            Some(current_epoch >= voting_start_epoch && is_within_two_thirds)
        })()
        .unwrap_or_default()
    }
}

/// Returns the latest epoch in which a validator can vote, given the voting
/// start and end epochs. If the pair of start and end epoch is invalid, then
/// return `None`.
pub fn last_validator_voting_epoch(
    voting_start_epoch: Epoch,
    voting_end_epoch: Epoch,
) -> Result<Option<Epoch>, arith::Error> {
    if voting_start_epoch >= voting_end_epoch {
        Ok(None)
    } else {
        let latest = checked!(
            voting_start_epoch.0
                + 2u64 * (voting_end_epoch.0 - voting_start_epoch.0) / 3u64
        )?;
        Ok(Some(Epoch(latest)))
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
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                token::Amount::from_u64(1),
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(90);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(90);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(90);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay,
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(10);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address,
            delegator_voting_power_two,
            ProposalVote::Abstain,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let delegator_address = address::testing::established_address_2();
        let delegator_voting_power = token::Amount::from_u64(10);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay,
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(20);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address,
            delegator_voting_power_two,
            ProposalVote::Abstain,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(20);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address,
            delegator_voting_power_two,
            ProposalVote::Abstain,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power,
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Nay,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power.add(validator_voting_power_two),
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Nay,
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(50);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Abstain,
        );

        for tally_type in [
            TallyType::OneHalfOverOneThird,
            TallyType::LessOneHalfOverOneThirdNay,
            TallyType::TwoFifths,
        ] {
            let proposal_result = compute_proposal_result(
                proposal_votes.clone(),
                validator_voting_power.add(validator_voting_power_two),
                tally_type,
            )
            .unwrap();
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
            ProposalVote::Yay,
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Yay,
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Abstain,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            validator_voting_power.add(validator_voting_power_two),
            TallyType::TwoFifths,
        )
        .unwrap();

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
            ProposalVote::Yay,
        );

        let validator_address_two = address::testing::established_address_2();
        let validator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_validator(
            &validator_address_two,
            validator_voting_power_two,
            ProposalVote::Yay,
        );

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Abstain,
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(50);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            validator_voting_power.add(validator_voting_power_two),
            TallyType::TwoFifths,
        )
        .unwrap();

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
            ProposalVote::Abstain,
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(50);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            delegator_voting_power_two.add(delegator_voting_power),
            TallyType::TwoFifths,
        )
        .unwrap();

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
            ProposalVote::Yay,
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(200),
            TallyType::TwoFifths,
        )
        .unwrap();

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
            ProposalVote::Yay,
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(403),
            TallyType::OneHalfOverOneThird,
        )
        .unwrap();

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
            ProposalVote::Yay,
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(100);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Yay,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(402),
            TallyType::OneHalfOverOneThird,
        )
        .unwrap();

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
            ProposalVote::Nay,
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(60);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(100),
            TallyType::LessOneHalfOverOneThirdNay,
        )
        .unwrap();

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
    fn test_proposal_fifteen() {
        let mut proposal_votes = ProposalVotes::default();

        let validator_address = address::testing::established_address_1();
        let validator_address_two = address::testing::established_address_2();

        let delegator_address_two = address::testing::established_address_3();
        let delegator_voting_power_two = token::Amount::from_u64(30);
        proposal_votes.add_delegator(
            &delegator_address_two,
            &validator_address_two,
            delegator_voting_power_two,
            ProposalVote::Nay,
        );

        let delegator_address = address::testing::established_address_4();
        let delegator_voting_power = token::Amount::from_u64(60);
        proposal_votes.add_delegator(
            &delegator_address,
            &validator_address,
            delegator_voting_power,
            ProposalVote::Nay,
        );

        let proposal_result = compute_proposal_result(
            proposal_votes.clone(),
            token::Amount::from(271),
            TallyType::LessOneHalfOverOneThirdNay,
        )
        .unwrap();

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

    #[test]
    fn test_validator_voting_period() {
        assert!(!is_valid_validator_voting_period(
            0.into(),
            2.into(),
            4.into()
        ));
        assert!(is_valid_validator_voting_period(
            2.into(),
            2.into(),
            4.into()
        ));
        assert!(is_valid_validator_voting_period(
            3.into(),
            2.into(),
            4.into()
        ));
        assert!(!is_valid_validator_voting_period(
            4.into(),
            2.into(),
            4.into()
        ));
        assert_eq!(
            last_validator_voting_epoch(2.into(), 4.into())
                .unwrap()
                .unwrap(),
            3.into()
        );

        assert!(is_valid_validator_voting_period(
            3.into(),
            2.into(),
            5.into()
        ));
        assert!(is_valid_validator_voting_period(
            4.into(),
            2.into(),
            5.into()
        ));
        assert!(!is_valid_validator_voting_period(
            5.into(),
            2.into(),
            5.into()
        ));
        assert_eq!(
            last_validator_voting_epoch(2.into(), 5.into())
                .unwrap()
                .unwrap(),
            4.into()
        );

        for end_epoch in 1u64..=20 {
            let last = last_validator_voting_epoch(0.into(), end_epoch.into())
                .unwrap()
                .unwrap();
            assert!(is_valid_validator_voting_period(
                last,
                0.into(),
                end_epoch.into()
            ));
            assert!(!is_valid_validator_voting_period(
                last.next(),
                0.into(),
                end_epoch.into()
            ));
        }
    }
}
