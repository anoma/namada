//! PoS rewards distribution.

use namada_controller::PDController;
use namada_core::address::{self, Address};
use namada_core::arith::{self, checked};
use namada_core::collections::{HashMap, HashSet};
use namada_core::dec::Dec;
use namada_core::storage::{BlockHeight, Epoch};
use namada_core::token::{self, Amount};
use namada_core::uint::{Uint, I256};
use namada_parameters::storage as params_storage;
use namada_storage::collections::lazy_map::NestedSubKey;
use namada_storage::{ResultExt, StorageRead, StorageWrite};
use namada_systems::governance;
use namada_trans_token::get_effective_total_native_supply;
use thiserror::Error;

use crate::storage::{
    consensus_validator_set_handle, get_last_reward_claim_epoch,
    read_last_pos_inflation_amount, read_last_staked_ratio, read_pos_params,
    read_total_stake, read_validator_stake, rewards_accumulator_handle,
    validator_commission_rate_handle, validator_rewards_products_handle,
    validator_state_handle, write_last_pos_inflation_amount,
    write_last_staked_ratio,
};
use crate::token::credit_tokens;
use crate::types::{into_tm_voting_power, BondId, ValidatorState, VoteInfo};
use crate::{
    bond_amounts_for_rewards, get_total_consensus_stake, staking_token_address,
    storage, storage_key, InflationError, PosParams,
};

/// This is equal to 0.01.
const MIN_PROPOSER_REWARD: Dec =
    Dec(I256(Uint([10000000000u64, 0u64, 0u64, 0u64])));

/// Errors during rewards calculation
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum RewardsError {
    /// number of votes is less than the threshold of 2/3
    #[error(
        "Insufficient votes. Got {signing_stake}, needed {votes_needed} (at \
         least 2/3 of the total bonded stake)."
    )]
    InsufficientVotes {
        votes_needed: Uint,
        signing_stake: Uint,
    },
    /// rewards coefficients are not set
    #[error("Rewards coefficients are not properly set.")]
    CoeffsNotSet,
    #[error("Arith {0}")]
    Arith(#[from] arith::Error),
    #[error("Dec {0}")]
    Dec(#[from] namada_core::dec::Error),
}

/// Compute PoS inflation amount
#[allow(clippy::too_many_arguments)]
pub fn compute_inflation(
    locked_amount: token::Amount,
    total_native_amount: token::Amount,
    max_reward_rate: Dec,
    last_inflation_amount: token::Amount,
    p_gain_nom: Dec,
    d_gain_nom: Dec,
    epochs_per_year: u64,
    target_ratio: Dec,
    last_ratio: Dec,
) -> namada_storage::Result<token::Amount> {
    let controller = PDController::new(
        total_native_amount.into(),
        max_reward_rate,
        last_inflation_amount.into(),
        p_gain_nom,
        d_gain_nom,
        epochs_per_year,
        target_ratio,
        last_ratio,
    );
    let locked_amount = Dec::try_from(locked_amount).into_storage_result()?;
    let total_native_dec =
        controller.get_total_native_dec().into_storage_result()?;
    let metric = checked!(locked_amount / total_native_dec)?;
    let control_coeff = checked!(
        total_native_dec * max_reward_rate / controller.get_epochs_per_year()
    )?;
    let amount_uint = controller
        .compute_inflation(control_coeff, metric)
        .into_storage_result()?;
    token::Amount::from_uint(amount_uint, 0).into_storage_result()
}

/// Holds coefficients for the three different ways to get PoS rewards
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
pub struct PosRewards {
    pub proposer_coeff: Dec,
    pub signer_coeff: Dec,
    pub active_val_coeff: Dec,
}

/// Holds relevant PoS parameters and is used to calculate the coefficients for
/// the rewards
#[derive(Debug, Copy, Clone)]
pub struct PosRewardsCalculator {
    /// Rewards fraction that goes to the block proposer
    pub proposer_reward: Dec,
    /// Rewards fraction that goes to the block signers
    pub signer_reward: Dec,
    /// Total stake of validators who signed the block
    pub signing_stake: Amount,
    /// Total stake of the whole consensus set
    pub total_stake: Amount,
}

impl PosRewardsCalculator {
    /// Calculate the rewards coefficients. These are used in combination with
    /// the validator's signing behavior and stake to determine the fraction of
    /// the block rewards earned.
    pub fn get_reward_coeffs(&self) -> Result<PosRewards, RewardsError> {
        let votes_needed = self.get_min_required_votes();

        let Self {
            proposer_reward,
            signer_reward,
            signing_stake,
            total_stake,
        } = *self;

        if signing_stake < votes_needed {
            return Err(RewardsError::InsufficientVotes {
                votes_needed: votes_needed.into(),
                signing_stake: signing_stake.into(),
            });
        }

        // Logic for determining the coefficients.
        let proposer_reward_coeff = Dec::try_from(
            checked!(signing_stake - votes_needed)?
                .mul_floor(proposer_reward)?,
        )?;
        let total_stake_dec = Dec::try_from(total_stake)?;
        let proposer_coeff = checked!(
            proposer_reward_coeff / total_stake_dec + MIN_PROPOSER_REWARD
        )?;
        let signer_coeff = signer_reward;
        let active_val_coeff =
            checked!(Dec::one() - proposer_coeff - signer_coeff)?;

        let coeffs = PosRewards {
            proposer_coeff,
            signer_coeff,
            active_val_coeff,
        };

        Ok(coeffs)
    }

    /// Implement as ceiling of (2/3) * validator set stake
    fn get_min_required_votes(&self) -> Amount {
        (self
            .total_stake
            .checked_mul(2_u64)
            .expect("Amount overflow while computing minimum required votes")
            .checked_add((3u64 - 1u64).into())
            .expect("Amount overflow while computing minimum required votes"))
        .checked_div_u64(3u64)
        .expect("Div by non-zero cannot fail")
    }
}

/// Process the proposer and votes in the block to assign their PoS rewards.
pub(crate) fn log_block_rewards<S, Gov>(
    storage: &mut S,
    votes: Vec<VoteInfo>,
    height: BlockHeight,
    current_epoch: Epoch,
    new_epoch: bool,
) -> namada_storage::Result<()>
where
    S: StorageWrite + StorageRead,
    Gov: governance::Read<S>,
{
    // Read the block proposer of the previously committed block in storage
    // (n-1 if we are in the process of finalizing n right now).
    match storage::read_last_block_proposer_address(storage)? {
        Some(proposer_address) => {
            tracing::debug!("Found last block proposer: {proposer_address}");
            log_block_rewards_aux::<S, Gov>(
                storage,
                if new_epoch {
                    current_epoch.prev().expect("New epoch must have prev")
                } else {
                    current_epoch
                },
                &proposer_address,
                votes,
            )?;
        }
        None => {
            if height > BlockHeight::default().next_height() {
                tracing::error!(
                    "Can't find the last block proposer at height {height}"
                );
            } else {
                tracing::debug!("No last block proposer at height {height}");
            }
        }
    }
    Ok(())
}

/// Tally a running sum of the fraction of rewards owed to each validator in
/// the consensus set. This is used to keep track of the rewards due to each
/// consensus validator over the lifetime of an epoch.
pub(crate) fn log_block_rewards_aux<S, Gov>(
    storage: &mut S,
    epoch: impl Into<Epoch>,
    proposer_address: &Address,
    votes: Vec<VoteInfo>,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    // The votes correspond to the last committed block (n-1 if we are
    // finalizing block n)

    let epoch: Epoch = epoch.into();
    let params = read_pos_params::<S, Gov>(storage)?;
    let consensus_validators = consensus_validator_set_handle().at(&epoch);

    // Get total stake of the consensus validator set
    let total_consensus_stake =
        get_total_consensus_stake(storage, epoch, &params)?;

    // Get set of signing validator addresses and the combined stake of
    // these signers
    let mut signer_set: HashSet<Address> = HashSet::new();
    let mut total_signing_stake = token::Amount::zero();
    for VoteInfo {
        validator_address,
        validator_vp,
    } in votes
    {
        if validator_vp == 0 {
            continue;
        }
        // Ensure that the validator is not currently jailed or other
        let state = validator_state_handle(&validator_address)
            .get(storage, epoch, &params)?;
        if state != Some(ValidatorState::Consensus) {
            return Err(InflationError::ExpectedValidatorInConsensus(
                validator_address,
                state,
            ))
            .into_storage_result();
        }

        let stake_from_deltas =
            read_validator_stake(storage, &params, &validator_address, epoch)?;

        // Ensure TM stake updates properly with a debug_assert
        if cfg!(debug_assertions) {
            debug_assert_eq!(
                into_tm_voting_power(
                    params.tm_votes_per_token,
                    stake_from_deltas,
                ),
                i64::try_from(validator_vp).unwrap_or_default(),
            );
        }

        signer_set.insert(validator_address);
        total_signing_stake =
            checked!(total_signing_stake + stake_from_deltas)?;
    }

    // Get the block rewards coefficients (proposing, signing/voting,
    // consensus set status)
    let rewards_calculator = PosRewardsCalculator {
        proposer_reward: params.block_proposer_reward,
        signer_reward: params.block_vote_reward,
        signing_stake: total_signing_stake,
        total_stake: total_consensus_stake,
    };
    let coeffs = rewards_calculator
        .get_reward_coeffs()
        .map_err(InflationError::Rewards)
        .into_storage_result()?;
    tracing::debug!(
        "PoS rewards coefficients {coeffs:?}, inputs: {rewards_calculator:?}."
    );

    // tracing::debug!(
    //     "TOTAL SIGNING STAKE (LOGGING BLOCK REWARDS) = {}",
    //     signing_stake
    // );

    // Compute the fractional block rewards for each consensus validator and
    // update the reward accumulators
    let consensus_stake_unscaled: Dec =
        Dec::try_from(total_consensus_stake).into_storage_result()?;
    let signing_stake_unscaled: Dec =
        Dec::try_from(total_signing_stake).into_storage_result()?;
    let mut values: HashMap<Address, Dec> = HashMap::new();
    for validator in consensus_validators.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: _,
            },
            address,
        ) = validator?;

        if stake.is_zero() {
            continue;
        }

        let mut rewards_frac = Dec::zero();
        let stake_unscaled: Dec = Dec::try_from(stake).into_storage_result()?;
        // tracing::debug!(
        //     "NAMADA VALIDATOR STAKE (LOGGING BLOCK REWARDS) OF EPOCH {} =
        // {}",     epoch, stake
        // );

        // Proposer reward
        if address == *proposer_address {
            checked!(rewards_frac += coeffs.proposer_coeff)?;
        }

        // Signer reward
        if signer_set.contains(&address) {
            let signing_frac =
                checked!(stake_unscaled / signing_stake_unscaled)?;
            checked!(rewards_frac += (coeffs.signer_coeff * signing_frac))?;
        }
        // Consensus validator reward
        checked!(
            rewards_frac += (coeffs.active_val_coeff
                * (stake_unscaled / consensus_stake_unscaled))
        )?;

        // To be added to the rewards accumulator
        values.insert(address, rewards_frac);
    }
    for (address, value) in values.into_iter() {
        // Update the rewards accumulator
        rewards_accumulator_handle().try_update(storage, address, |prev| {
            let prev = prev.unwrap_or_default();
            Ok(checked!(prev + value)?)
        })?;
    }

    Ok(())
}

/// Apply inflation to the Proof of Stake system.
pub fn apply_inflation<S, Gov>(
    storage: &mut S,
    last_epoch: Epoch,
    num_blocks_in_last_epoch: u64,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    // Read from Parameters storage
    let epochs_per_year: u64 = storage
        .read(&params_storage::get_epochs_per_year_key())?
        .expect("Epochs per year should exist in parameters storage");

    let staking_token = staking_token_address(storage);
    let total_tokens = get_effective_total_native_supply(storage)?;

    // Read from PoS storage
    let params = read_pos_params::<S, Gov>(storage)?;
    let locked_amount = read_total_stake(storage, &params, last_epoch)?;

    let last_staked_ratio = read_last_staked_ratio(storage)?
        .expect("Last staked ratio should exist in PoS storage");
    let last_inflation_amount = read_last_pos_inflation_amount(storage)?
        .expect("Last inflation amount should exist in PoS storage");

    let locked_ratio_target = params.target_staked_ratio;
    let max_inflation_rate = params.max_inflation_rate;
    let p_gain_nom = params.rewards_gain_p;
    let d_gain_nom = params.rewards_gain_d;

    // Compute the new inflation
    let inflation = compute_inflation(
        locked_amount,
        total_tokens,
        max_inflation_rate,
        last_inflation_amount,
        p_gain_nom,
        d_gain_nom,
        epochs_per_year,
        locked_ratio_target,
        last_staked_ratio,
    )?;

    // Mint inflation and partition rewards among all accounts that earn a
    // portion of it
    update_rewards_products_and_mint_inflation(
        storage,
        &params,
        last_epoch,
        num_blocks_in_last_epoch,
        inflation,
        &staking_token,
        total_tokens,
    )?;

    // Write new rewards parameters that will be used for the inflation of
    // the current new epoch
    let locked_amount = Dec::try_from(locked_amount).into_storage_result()?;
    let total_amount = Dec::try_from(total_tokens).into_storage_result()?;
    let locked_ratio = checked!(locked_amount / total_amount)?;

    write_last_staked_ratio(storage, locked_ratio)?;
    write_last_pos_inflation_amount(storage, inflation)?;

    Ok(())
}

#[derive(Clone, Debug)]
struct Rewards {
    product: Dec,
    commissions: token::Amount,
}

/// Update validator and delegators rewards products and mint the inflation
/// tokens into the PoS account.
/// Any left-over inflation tokens from rounding error of the sum of the
/// rewards is given to the governance address.
pub fn update_rewards_products_and_mint_inflation<S>(
    storage: &mut S,
    params: &PosParams,
    last_epoch: Epoch,
    num_blocks_in_last_epoch: u64,
    inflation: token::Amount,
    staking_token: &Address,
    total_native_tokens: token::Amount,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // Read the rewards accumulator and calculate the new rewards products
    // for the previous epoch
    let mut reward_tokens_remaining = inflation;
    let mut new_rewards_products: HashMap<Address, Rewards> = HashMap::new();
    let mut accumulators_sum = Dec::zero();
    for acc in rewards_accumulator_handle().iter(storage)? {
        let (validator, value) = acc?;
        accumulators_sum = checked!(accumulators_sum + value)?;

        // Get reward token amount for this validator
        let fractional_claim = checked!(value / num_blocks_in_last_epoch)?;
        let reward_tokens = inflation.mul_floor(fractional_claim)?;

        // Get validator stake at the last epoch
        let stake = Dec::try_from(read_validator_stake(
            storage, params, &validator, last_epoch,
        )?)
        .into_storage_result()?;

        let commission_rate = validator_commission_rate_handle(&validator)
            .get(storage, last_epoch, params)?
            .expect("Should be able to find validator commission rate");

        // Calculate the reward product from the whole validator stake and take
        // out the commissions. Because we're using the whole stake to work with
        // a single product, we're also taking out commission on validator's
        // self-bonds, but it is then included in the rewards claimable by the
        // validator so they get it back.
        let reward_tokens_dec =
            Dec::try_from(reward_tokens).into_storage_result()?;
        let product = checked!(
            (Dec::one() - commission_rate) * reward_tokens_dec / stake
        )?;

        // Tally the commission tokens earned by the validator.
        // TODO: think abt Dec rounding and if `new_product` should be used
        // instead of `reward_tokens`
        let commissions = reward_tokens.mul_floor(commission_rate)?;

        new_rewards_products.insert(
            validator,
            Rewards {
                product,
                commissions,
            },
        );

        reward_tokens_remaining =
            checked!(reward_tokens_remaining - reward_tokens)?;
    }
    for (
        validator,
        Rewards {
            product,
            commissions,
        },
    ) in new_rewards_products
    {
        validator_rewards_products_handle(&validator)
            .insert(storage, last_epoch, product)?;
        // The commissions belong to the validator
        add_rewards_to_counter(storage, &validator, &validator, commissions)?;
    }

    // Mint tokens to the PoS account for the last epoch's inflation
    let pos_reward_tokens = checked!(inflation - reward_tokens_remaining)?;
    tracing::info!(
        "Minting tokens for PoS rewards distribution into the PoS account. \
         Amount: {}. Total inflation: {}. Total native supply: {}. Number of \
         blocks in the last epoch: {num_blocks_in_last_epoch}. Reward \
         accumulators sum: {accumulators_sum}.",
        pos_reward_tokens.to_string_native(),
        inflation.to_string_native(),
        total_native_tokens.to_string_native(),
    );
    credit_tokens(storage, staking_token, &address::POS, pos_reward_tokens)?;

    if reward_tokens_remaining > token::Amount::zero() {
        tracing::info!(
            "Minting tokens remaining from PoS rewards distribution into the \
             Governance account. Amount: {}.",
            reward_tokens_remaining.to_string_native()
        );
        credit_tokens(
            storage,
            staking_token,
            &address::PGF,
            reward_tokens_remaining,
        )?;
    }

    // Clear validator rewards accumulators
    storage.delete_prefix(
        // The prefix of `rewards_accumulator_handle`
        &storage_key::consensus_validator_rewards_accumulator_key(),
    )?;

    Ok(())
}

/// Compute the current available rewards amount due only to existing bonds.
/// This does not include pending rewards held in the rewards counter due to
/// unbonds and redelegations.
pub fn compute_current_rewards_from_bonds<S, Gov>(
    storage: &S,
    source: &Address,
    validator: &Address,
    current_epoch: Epoch,
) -> namada_storage::Result<token::Amount>
where
    S: StorageRead,
    Gov: governance::Read<S>,
{
    if current_epoch == Epoch::default() {
        // Nothing to claim in the first epoch
        return Ok(token::Amount::zero());
    }

    let last_claim_epoch =
        get_last_reward_claim_epoch(storage, source, validator)?;
    if let Some(last_epoch) = last_claim_epoch {
        if last_epoch == current_epoch {
            // Already claimed in this epoch
            return Ok(token::Amount::zero());
        }
    }

    let mut reward_tokens = token::Amount::zero();

    // Want to claim from `last_claim_epoch` to `current_epoch.prev()` since
    // rewards are computed at the end of an epoch
    let (claim_start, claim_end) = (
        last_claim_epoch.unwrap_or_default(),
        current_epoch
            .prev()
            .expect("Safe because of the check above"),
    );
    let bond_amounts = bond_amounts_for_rewards::<S, Gov>(
        storage,
        &BondId {
            source: source.clone(),
            validator: validator.clone(),
        },
        claim_start,
        claim_end,
    )?;

    let rewards_products = validator_rewards_products_handle(validator);
    for (ep, bond_amount) in bond_amounts {
        debug_assert!(ep >= claim_start);
        debug_assert!(ep <= claim_end);
        let rp = rewards_products.get(storage, &ep)?.unwrap_or_default();
        let reward = bond_amount.mul_floor(rp)?;
        checked!(reward_tokens += reward)?;
    }

    Ok(reward_tokens)
}

/// Add tokens to a rewards counter.
pub fn add_rewards_to_counter<S>(
    storage: &mut S,
    source: &Address,
    validator: &Address,
    new_rewards: token::Amount,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::rewards_counter_key(source, validator);
    let current_rewards =
        storage.read::<token::Amount>(&key)?.unwrap_or_default();
    storage.write(&key, checked!(current_rewards + new_rewards)?)
}

/// Take tokens from a rewards counter. Deletes the record after reading.
pub fn take_rewards_from_counter<S>(
    storage: &mut S,
    source: &Address,
    validator: &Address,
) -> namada_storage::Result<token::Amount>
where
    S: StorageRead + StorageWrite,
{
    let key = storage_key::rewards_counter_key(source, validator);
    let current_rewards =
        storage.read::<token::Amount>(&key)?.unwrap_or_default();
    storage.delete(&key)?;
    Ok(current_rewards)
}

/// Read the current token value in the rewards counter.
pub fn read_rewards_counter<S>(
    storage: &S,
    source: &Address,
    validator: &Address,
) -> namada_storage::Result<token::Amount>
where
    S: StorageRead,
{
    let key = storage_key::rewards_counter_key(source, validator);
    Ok(storage.read::<token::Amount>(&key)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_inflation_calc_up() {
        let locked_amount = token::Amount::native_whole(2_000_000_000);
        let total_native_amount =
            token::Amount::native_whole(4_000_000_000_u64);
        let max_reward_rate = Dec::from_str("0.1").unwrap();
        let p_gain_nom = Dec::from_str("0.1").unwrap();
        let d_gain_nom = Dec::from_str("0.1").unwrap();
        let epochs_per_year = 365;
        let target_ratio = Dec::from_str("0.66666666").unwrap();

        let inflation_0 = compute_inflation(
            locked_amount,
            total_native_amount,
            max_reward_rate,
            token::Amount::zero(),
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
            target_ratio,
            Dec::from_str("0.5").unwrap(),
        )
        .unwrap();
        let locked_ratio_0 = Dec::try_from(locked_amount).unwrap()
            / Dec::try_from(total_native_amount).unwrap();

        println!(
            "Round 0: Locked ratio: {locked_ratio_0}, inflation: {inflation_0}"
        );
        assert_eq!(locked_ratio_0, Dec::from_str("0.5").unwrap());
        assert_eq!(inflation_0, token::Amount::from_u64(18264839452));

        let locked_amount = locked_amount + inflation_0;
        let last_inflation_amount = inflation_0;
        let last_locked_ratio = locked_ratio_0;

        let inflation_1 = compute_inflation(
            locked_amount,
            total_native_amount,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
            target_ratio,
            last_locked_ratio,
        )
        .unwrap();

        // BUG: DIDN'T ADD TO TOTAL AMOUNT

        let locked_ratio_1 = Dec::try_from(locked_amount).unwrap()
            / Dec::try_from(total_native_amount).unwrap();

        println!(
            "Round 1: Locked ratio: {locked_ratio_1}, inflation: {inflation_1}"
        );
        assert!(locked_ratio_1 > locked_ratio_0);
        assert!(locked_ratio_1 > Dec::from_str("0.5").unwrap());
        assert!(locked_ratio_1 < Dec::from_str("0.51").unwrap());
        assert_eq!(inflation_1, token::Amount::from_u64(36529678904));

        let locked_amount = locked_amount + inflation_1;
        let last_inflation_amount = inflation_1;
        let last_locked_ratio = locked_ratio_1;

        let inflation_2 = compute_inflation(
            locked_amount,
            total_native_amount,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
            target_ratio,
            last_locked_ratio,
        )
        .unwrap();

        let locked_ratio_2 = Dec::try_from(locked_amount).unwrap()
            / Dec::try_from(total_native_amount).unwrap();
        println!(
            "Round 2: Locked ratio: {locked_ratio_2}, inflation: {inflation_2}",
        );
        assert!(locked_ratio_2 > locked_ratio_1);
        assert!(locked_ratio_2 > Dec::from_str("0.5").unwrap());
        assert!(locked_ratio_2 < Dec::from_str("0.51").unwrap());
        assert_eq!(inflation_2, token::Amount::from_u64(54794017950));
    }

    #[test]
    fn test_inflation_calc_down() {
        let locked_amount = token::Amount::native_whole(900_000_000);
        let total_native_amount =
            token::Amount::native_whole(1_000_000_000_u64);
        let max_reward_rate = Dec::from_str("0.1").unwrap();
        let p_gain_nom = Dec::from_str("0.1").unwrap();
        let d_gain_nom = Dec::from_str("0.1").unwrap();
        let epochs_per_year = 365;
        let target_ratio = Dec::from_str("0.66666666").unwrap();

        let inflation_0 = compute_inflation(
            locked_amount,
            total_native_amount,
            max_reward_rate,
            token::Amount::native_whole(10_000),
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
            target_ratio,
            Dec::from_str("0.9").unwrap(),
        )
        .unwrap();
        let locked_ratio_0 = Dec::try_from(locked_amount).unwrap()
            / Dec::try_from(total_native_amount).unwrap();

        println!(
            "Round 0: Locked ratio: {locked_ratio_0}, inflation: {inflation_0}"
        );
        assert_eq!(locked_ratio_0, Dec::from_str("0.9").unwrap());
        assert_eq!(inflation_0, token::Amount::from_u64(3607305753));

        let locked_amount = locked_amount + inflation_0;
        let last_inflation_amount = inflation_0;
        let last_locked_ratio = locked_ratio_0;

        let inflation_1 = compute_inflation(
            locked_amount,
            total_native_amount,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
            target_ratio,
            last_locked_ratio,
        )
        .unwrap();

        // BUG: DIDN'T ADD TO TOTAL AMOUNT

        let locked_ratio_1 = Dec::try_from(locked_amount).unwrap()
            / Dec::try_from(total_native_amount).unwrap();

        println!(
            "Round 1: Locked ratio: {locked_ratio_1}, inflation: {inflation_1}"
        );
        assert!(locked_ratio_1 > locked_ratio_0);
        assert!(locked_ratio_1 > Dec::from_str("0.9").unwrap());
        assert!(locked_ratio_1 < Dec::from_str("0.91").unwrap());
        assert_eq!(inflation_1, token::Amount::zero());

        let locked_amount = locked_amount + inflation_1;
        let last_inflation_amount = inflation_1;
        let last_locked_ratio = locked_ratio_1;

        let inflation_2 = compute_inflation(
            locked_amount,
            total_native_amount,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
            target_ratio,
            last_locked_ratio,
        )
        .unwrap();

        let locked_ratio_2 = Dec::try_from(locked_amount).unwrap()
            / Dec::try_from(total_native_amount).unwrap();
        println!(
            "Round 2: Locked ratio: {locked_ratio_2}, inflation: {inflation_2}",
        );
        assert_eq!(locked_ratio_2, locked_ratio_1);
        assert_eq!(inflation_2, token::Amount::zero());
    }

    #[test]
    fn test_pos_inflation_playground() {
        let epochs_per_year = 365_u64;

        let init_locked_ratio = Dec::from_str("0.1").unwrap();
        let mut last_locked_ratio = init_locked_ratio;
        let total_native_tokens = 1_000_000_000_u64;
        let locked_amount = u64::try_from(
            (init_locked_ratio * total_native_tokens).to_uint().unwrap(),
        )
        .unwrap();
        let mut locked_amount = token::Amount::native_whole(locked_amount);
        let mut last_inflation_amount = token::Amount::zero();
        let mut total_native_tokens =
            token::Amount::native_whole(total_native_tokens);

        let max_reward_rate = Dec::from_str("0.1").unwrap();
        let target_ratio = Dec::from_str("0.66666666").unwrap();
        let p_gain_nom = Dec::from_str("0.25").unwrap();
        let d_gain_nom = Dec::from_str("0.25").unwrap();

        let staking_growth = Dec::from_str("0.04").unwrap();
        // let mut do_add = true;

        let num_rounds = 50;

        for round in 0..num_rounds {
            let inflation = compute_inflation(
                locked_amount,
                total_native_tokens,
                max_reward_rate,
                last_inflation_amount,
                p_gain_nom,
                d_gain_nom,
                epochs_per_year,
                target_ratio,
                last_locked_ratio,
            )
            .unwrap();
            let locked_ratio = Dec::try_from(locked_amount).unwrap()
                / Dec::try_from(total_native_tokens).unwrap();

            let rate = Dec::try_from(inflation).unwrap()
                * Dec::from(epochs_per_year)
                / Dec::try_from(total_native_tokens).unwrap();
            println!(
                "Round {round}: Locked ratio: {locked_ratio}, inflation rate: \
                 {rate}",
            );

            last_inflation_amount = inflation;
            total_native_tokens += inflation;
            last_locked_ratio = locked_ratio;

            // if rate.abs_diff(&controller.max_reward_rate)
            //     < Dec::from_str("0.01").unwrap()
            // {
            //     controller.locked_tokens = controller.total_tokens;
            // }

            let tot_tokens =
                Dec::try_from(total_native_tokens.raw_amount()).unwrap();
            let change_staked_tokens =
                token::Amount::try_from(staking_growth * tot_tokens).unwrap();

            locked_amount = std::cmp::min(
                total_native_tokens,
                locked_amount + change_staked_tokens,
            );

            // if locked_ratio > Dec::from_str("0.8").unwrap()
            //     && locked_ratio - controller.locked_ratio_last >= Dec::zero()
            // {
            //     do_add = false;
            // } else if locked_ratio < Dec::from_str("0.4").unwrap()
            //     && locked_ratio - controller.locked_ratio_last < Dec::zero()
            // {
            //     do_add = true;
            // }

            // controller.locked_tokens = std::cmp::min(
            //     if do_add {
            //         controller.locked_tokens + change_staked_tokens
            //     } else {
            //         controller.locked_tokens - change_staked_tokens
            //     },
            //     controller.total_tokens,
            // );
        }
    }
}
