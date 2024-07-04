//! Validator set updates

use namada_core::address::Address;
use namada_core::arith::checked;
use namada_core::collections::{HashMap, HashSet};
use namada_core::key::PublicKeyTmRawHash;
use namada_core::storage::Epoch;
use namada_core::token;
use namada_storage::collections::lazy_map::{NestedSubKey, SubKey};
use namada_storage::{StorageRead, StorageWrite};
use namada_systems::governance;
use once_cell::unsync::Lazy;

use crate::storage::{
    below_capacity_validator_set_handle, consensus_validator_set_handle,
    get_num_consensus_validators, read_validator_stake,
    validator_addresses_handle, validator_consensus_key_handle,
    validator_set_positions_handle, validator_state_handle,
};
use crate::types::{
    into_tm_voting_power, BelowCapacityValidatorSet, ConsensusValidator,
    ConsensusValidatorSet, Position, ReverseOrdTokenAmount,
    ValidatorPositionAddresses, ValidatorSetUpdate, ValidatorState,
};
use crate::PosParams;

/// Update validator set at the pipeline epoch when a validator receives a new
/// bond and when its bond is unbonded (self-bond or delegation).
pub fn update_validator_set<S, Gov>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    token_change: token::Change,
    current_epoch: Epoch,
    offset: Option<u64>,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    if token_change.is_zero() {
        return Ok(());
    }
    let offset = offset.unwrap_or(params.pipeline_len);
    let epoch = checked!(current_epoch + offset)?;
    tracing::debug!(
        "Update epoch for validator set: {epoch}, validator: {validator}"
    );
    let consensus_validator_set = consensus_validator_set_handle();
    let below_capacity_validator_set = below_capacity_validator_set_handle();

    // Validator sets at the pipeline offset
    let consensus_val_handle = consensus_validator_set.at(&epoch);
    let below_capacity_val_handle = below_capacity_validator_set.at(&epoch);

    let tokens_pre = read_validator_stake(storage, params, validator, epoch)?;

    let tokens_post = checked!(tokens_pre.change() + token_change)?;
    debug_assert!(tokens_post.non_negative());
    let tokens_post = token::Amount::from_change(tokens_post);

    // If token amounts both before and after the action are below the threshold
    // stake, do nothing
    if tokens_pre < params.validator_stake_threshold
        && tokens_post < params.validator_stake_threshold
    {
        return Ok(());
    }

    // The position is only set when the validator is in consensus or
    // below_capacity set (not in below_threshold set)
    let position =
        read_validator_set_position(storage, validator, epoch, params)?;
    if let Some(position) = position {
        let consensus_vals_pre = consensus_val_handle.at(&tokens_pre);

        let in_consensus = if consensus_vals_pre.contains(storage, &position)? {
            let val_address = consensus_vals_pre.get(storage, &position)?;
            debug_assert!(val_address.is_some());
            val_address == Some(validator.clone())
        } else {
            false
        };

        if in_consensus {
            // It's initially consensus
            tracing::debug!("Target validator is consensus");

            // First remove the consensus validator
            consensus_vals_pre.remove(storage, &position)?;

            let max_below_capacity_validator_amount =
                get_max_below_capacity_validator_amount(
                    &below_capacity_val_handle,
                    storage,
                )?
                .unwrap_or_default();

            if tokens_post < params.validator_stake_threshold {
                tracing::debug!(
                    "Demoting this validator to the below-threshold set"
                );
                // Set the validator state as below-threshold
                validator_state_handle(validator).set::<S, Gov>(
                    storage,
                    ValidatorState::BelowThreshold,
                    current_epoch,
                    offset,
                )?;

                // Remove the validator's position from storage
                validator_set_positions_handle()
                    .at(&epoch)
                    .remove(storage, validator)?;

                // Promote the next below-cap validator if there is one
                if let Some(max_bc_amount) =
                    get_max_below_capacity_validator_amount(
                        &below_capacity_val_handle,
                        storage,
                    )?
                {
                    // Remove the max below-capacity validator first
                    let below_capacity_vals_max =
                        below_capacity_val_handle.at(&max_bc_amount.into());
                    let lowest_position =
                        find_first_position(&below_capacity_vals_max, storage)?
                            .unwrap();
                    let removed_max_below_capacity = below_capacity_vals_max
                        .remove(storage, &lowest_position)?
                        .expect("Must have been removed");

                    // Insert the previous max below-capacity validator into the
                    // consensus set
                    insert_validator_into_set(
                        &consensus_val_handle.at(&max_bc_amount),
                        storage,
                        &epoch,
                        &removed_max_below_capacity,
                    )?;
                    validator_state_handle(&removed_max_below_capacity)
                        .set::<S, Gov>(
                            storage,
                            ValidatorState::Consensus,
                            current_epoch,
                            offset,
                        )?;
                }
            } else if tokens_post < max_below_capacity_validator_amount {
                tracing::debug!(
                    "Demoting this validator to the below-capacity set and \
                     promoting another to the consensus set"
                );
                // Place the validator into the below-capacity set and promote
                // the lowest position max below-capacity
                // validator.

                // Remove the max below-capacity validator first
                let below_capacity_vals_max = below_capacity_val_handle
                    .at(&max_below_capacity_validator_amount.into());
                let lowest_position =
                    find_first_position(&below_capacity_vals_max, storage)?
                        .unwrap();
                let removed_max_below_capacity = below_capacity_vals_max
                    .remove(storage, &lowest_position)?
                    .expect("Must have been removed");

                // Insert the previous max below-capacity validator into the
                // consensus set
                insert_validator_into_set(
                    &consensus_val_handle
                        .at(&max_below_capacity_validator_amount),
                    storage,
                    &epoch,
                    &removed_max_below_capacity,
                )?;
                validator_state_handle(&removed_max_below_capacity)
                    .set::<S, Gov>(
                        storage,
                        ValidatorState::Consensus,
                        current_epoch,
                        offset,
                    )?;

                // Insert the current validator into the below-capacity set
                insert_validator_into_set(
                    &below_capacity_val_handle.at(&tokens_post.into()),
                    storage,
                    &epoch,
                    validator,
                )?;
                validator_state_handle(validator).set::<S, Gov>(
                    storage,
                    ValidatorState::BelowCapacity,
                    current_epoch,
                    offset,
                )?;
            } else {
                tracing::debug!("Validator remains in consensus set");
                // The current validator should remain in the consensus set -
                // place it into a new position
                insert_validator_into_set(
                    &consensus_val_handle.at(&tokens_post),
                    storage,
                    &epoch,
                    validator,
                )?;
            }
        } else {
            // It's initially below-capacity
            tracing::debug!("Target validator is below-capacity");

            let below_capacity_vals_pre =
                below_capacity_val_handle.at(&tokens_pre.into());
            let removed = below_capacity_vals_pre.remove(storage, &position)?;
            debug_assert!(removed.is_some());
            debug_assert_eq!(&removed.unwrap(), validator);

            let min_consensus_validator_amount =
                get_min_consensus_validator_amount(
                    &consensus_val_handle,
                    storage,
                )?;

            if tokens_post > min_consensus_validator_amount {
                // Place the validator into the consensus set and demote the
                // last position min consensus validator to the
                // below-capacity set
                tracing::debug!(
                    "Inserting validator into the consensus set and demoting \
                     a consensus validator to the below-capacity set"
                );

                insert_into_consensus_and_demote_to_below_cap::<S, Gov>(
                    storage,
                    validator,
                    tokens_post,
                    min_consensus_validator_amount,
                    current_epoch,
                    offset,
                    &consensus_val_handle,
                    &below_capacity_val_handle,
                )?;
            } else if tokens_post >= params.validator_stake_threshold {
                tracing::debug!("Validator remains in below-capacity set");
                // The current validator should remain in the below-capacity set
                insert_validator_into_set(
                    &below_capacity_val_handle.at(&tokens_post.into()),
                    storage,
                    &epoch,
                    validator,
                )?;
                validator_state_handle(validator).set::<S, Gov>(
                    storage,
                    ValidatorState::BelowCapacity,
                    current_epoch,
                    offset,
                )?;
            } else {
                // The current validator is demoted to the below-threshold set
                tracing::debug!(
                    "Demoting this validator to the below-threshold set"
                );

                validator_state_handle(validator).set::<S, Gov>(
                    storage,
                    ValidatorState::BelowThreshold,
                    current_epoch,
                    offset,
                )?;

                // Remove the validator's position from storage
                validator_set_positions_handle()
                    .at(&epoch)
                    .remove(storage, validator)?;
            }
        }
    } else {
        // At non-zero offset (0 is genesis only)
        if offset > 0 {
            // If there is no position at pipeline offset, then the validator
            // must be in the below-threshold set
            debug_assert!(tokens_pre < params.validator_stake_threshold);
        }
        tracing::debug!("Target validator is below-threshold");

        // Move the validator into the appropriate set
        let num_consensus_validators =
            get_num_consensus_validators(storage, epoch)?;
        if num_consensus_validators < params.max_validator_slots {
            // Just insert into the consensus set
            tracing::debug!("Inserting validator into the consensus set");

            insert_validator_into_set(
                &consensus_val_handle.at(&tokens_post),
                storage,
                &epoch,
                validator,
            )?;
            validator_state_handle(validator).set::<S, Gov>(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                offset,
            )?;
        } else {
            let min_consensus_validator_amount =
                get_min_consensus_validator_amount(
                    &consensus_val_handle,
                    storage,
                )?;
            if tokens_post > min_consensus_validator_amount {
                // Insert this validator into consensus and demote one into the
                // below-capacity
                tracing::debug!(
                    "Inserting validator into the consensus set and demoting \
                     a consensus validator to the below-capacity set"
                );

                insert_into_consensus_and_demote_to_below_cap::<S, Gov>(
                    storage,
                    validator,
                    tokens_post,
                    min_consensus_validator_amount,
                    current_epoch,
                    offset,
                    &consensus_val_handle,
                    &below_capacity_val_handle,
                )?;
            } else {
                // Insert this validator into below-capacity
                tracing::debug!(
                    "Inserting validator into the below-capacity set"
                );

                insert_validator_into_set(
                    &below_capacity_val_handle.at(&tokens_post.into()),
                    storage,
                    &epoch,
                    validator,
                )?;
                validator_state_handle(validator).set::<S, Gov>(
                    storage,
                    ValidatorState::BelowCapacity,
                    current_epoch,
                    offset,
                )?;
            }
        }
    }

    Ok(())
}

/// Insert the new validator into the right validator set (depending on its
/// stake)
pub fn insert_validator_into_validator_set<S, Gov>(
    storage: &mut S,
    params: &PosParams,
    address: &Address,
    stake: token::Amount,
    current_epoch: Epoch,
    offset: u64,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    let target_epoch = checked!(current_epoch + offset)?;
    let consensus_set = consensus_validator_set_handle().at(&target_epoch);
    let below_cap_set = below_capacity_validator_set_handle().at(&target_epoch);

    let num_consensus_validators =
        get_num_consensus_validators(storage, target_epoch)?;

    if stake < params.validator_stake_threshold {
        validator_state_handle(address).set::<S, Gov>(
            storage,
            ValidatorState::BelowThreshold,
            current_epoch,
            offset,
        )?;
    } else if num_consensus_validators < params.max_validator_slots {
        insert_validator_into_set(
            &consensus_set.at(&stake),
            storage,
            &target_epoch,
            address,
        )?;
        validator_state_handle(address).set::<S, Gov>(
            storage,
            ValidatorState::Consensus,
            current_epoch,
            offset,
        )?;
    } else {
        // Check to see if the current genesis validator should replace one
        // already in the consensus set
        let min_consensus_amount =
            get_min_consensus_validator_amount(&consensus_set, storage)?;
        if stake > min_consensus_amount {
            // Swap this genesis validator in and demote the last min consensus
            // validator
            let min_consensus_handle = consensus_set.at(&min_consensus_amount);
            // Remove last min consensus validator
            let last_min_consensus_position =
                find_last_position(&min_consensus_handle, storage)?.expect(
                    "There must be always be at least 1 consensus validator",
                );
            let removed = min_consensus_handle
                .remove(storage, &last_min_consensus_position)?
                .expect(
                    "There must be always be at least 1 consensus validator",
                );
            // Insert last min consensus validator into the below-capacity set
            insert_validator_into_set(
                &below_cap_set.at(&min_consensus_amount.into()),
                storage,
                &target_epoch,
                &removed,
            )?;
            validator_state_handle(&removed).set::<S, Gov>(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                offset,
            )?;
            // Insert the current genesis validator into the consensus set
            insert_validator_into_set(
                &consensus_set.at(&stake),
                storage,
                &target_epoch,
                address,
            )?;
            // Update and set the validator states
            validator_state_handle(address).set::<S, Gov>(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                offset,
            )?;
        } else {
            // Insert the current genesis validator into the below-capacity set
            insert_validator_into_set(
                &below_cap_set.at(&stake.into()),
                storage,
                &target_epoch,
                address,
            )?;
            validator_state_handle(address).set::<S, Gov>(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                offset,
            )?;
        }
    }
    Ok(())
}

/// Remove a validator from the consensus validator set
pub fn remove_consensus_validator<S>(
    storage: &mut S,
    params: &PosParams,
    epoch: Epoch,
    validator: &Address,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let stake = read_validator_stake(storage, params, validator, epoch)?;
    let consensus_set = consensus_validator_set_handle().at(&epoch).at(&stake);
    let val_position = validator_set_positions_handle()
        .at(&epoch)
        .get(storage, validator)?
        .expect("Could not find validator's position in storage.");

    // Removal
    let removed = consensus_set.remove(storage, &val_position)?;
    debug_assert_eq!(removed, Some(validator.clone()));

    validator_set_positions_handle()
        .at(&epoch)
        .remove(storage, validator)?;

    Ok(())
}

/// Remove a validator from the below-capacity set
pub fn remove_below_capacity_validator<S>(
    storage: &mut S,
    params: &PosParams,
    epoch: Epoch,
    validator: &Address,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let stake = read_validator_stake(storage, params, validator, epoch)?;
    let below_cap_set = below_capacity_validator_set_handle()
        .at(&epoch)
        .at(&stake.into());
    let val_position = validator_set_positions_handle()
        .at(&epoch)
        .get(storage, validator)?
        .expect("Could not find validator's position in storage.");

    // Removal
    let removed = below_cap_set.remove(storage, &val_position)?;
    debug_assert_eq!(removed, Some(validator.clone()));

    validator_set_positions_handle()
        .at(&epoch)
        .remove(storage, validator)?;

    Ok(())
}

/// Promote the next below-capacity validator to the consensus validator set,
/// determined as the validator in the below-capacity set with the largest stake
/// and the lowest `Position`. Assumes that there is adequate space within the
/// consensus set already.
pub fn promote_next_below_capacity_validator_to_consensus<S, Gov>(
    storage: &mut S,
    current_epoch: Epoch,
    offset: u64,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    let epoch = checked!(current_epoch + offset)?;
    let below_cap_set = below_capacity_validator_set_handle().at(&epoch);
    let max_below_capacity_amount =
        get_max_below_capacity_validator_amount(&below_cap_set, storage)?;

    if let Some(max_below_capacity_amount) = max_below_capacity_amount {
        let max_bc_vals = below_cap_set.at(&max_below_capacity_amount.into());
        let position_to_promote = find_first_position(&max_bc_vals, storage)?
            .expect("Should be at least one below-capacity validator");

        let promoted_validator = max_bc_vals
            .remove(storage, &position_to_promote)?
            .expect("Should have returned a removed validator.");

        insert_validator_into_set(
            &consensus_validator_set_handle()
                .at(&epoch)
                .at(&max_below_capacity_amount),
            storage,
            &epoch,
            &promoted_validator,
        )?;
        validator_state_handle(&promoted_validator).set::<S, Gov>(
            storage,
            ValidatorState::Consensus,
            current_epoch,
            offset,
        )?;
    }

    Ok(())
}

/// Communicate imminent validator set updates to Tendermint. This function is
/// called two blocks before the start of a new epoch because Tendermint
/// validator updates become active two blocks after the updates are submitted.
pub fn validator_set_update_comet<S, T>(
    storage: &S,
    params: &PosParams,
    current_epoch: Epoch,
    f: impl FnMut(ValidatorSetUpdate) -> T,
) -> namada_storage::Result<Vec<T>>
where
    S: StorageRead,
{
    tracing::debug!(
        "Communicating post-genesis validator set updates to CometBFT."
    );
    // Because this is called 2 blocks before the start on an epoch, we will
    // give CometBFT the updates for the next epoch
    let next_epoch = current_epoch.next();

    let new_consensus_validator_handle =
        consensus_validator_set_handle().at(&next_epoch);
    let prev_consensus_validator_handle =
        consensus_validator_set_handle().at(&current_epoch);

    tracing::debug!("Iterating over new consensus validators:");
    let new_consensus_validators = new_consensus_validator_handle
        .iter(storage)?
        .map(|validator| {
            let (
                NestedSubKey::Data {
                    key: new_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();

            tracing::debug!(
                "Consensus validator address {address}, stake {}",
                new_stake.to_string_native()
            );

            let prev_tm_voting_power = Lazy::new(|| {
                let prev_validator_stake = read_validator_stake(
                    storage,
                    params,
                    &address,
                    current_epoch,
                )
                .unwrap();
                into_tm_voting_power(
                    params.tm_votes_per_token,
                    prev_validator_stake,
                )
            });
            let new_tm_voting_power = Lazy::new(|| {
                into_tm_voting_power(params.tm_votes_per_token, new_stake)
            });

            // If both previous and current voting powers are 0, and the
            // validator_stake_threshold is 0, skip update
            if params.validator_stake_threshold.is_zero()
                && *prev_tm_voting_power == 0
                && *new_tm_voting_power == 0
            {
                tracing::debug!(
                    "Skipping CometBFT validator set update, {address} is in \
                     consensus set but without voting power"
                );
                return vec![];
            }

            let new_consensus_key = validator_consensus_key_handle(&address)
                .get(storage, next_epoch, params)
                .unwrap()
                .unwrap();

            let prev_consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap();

            let prev_state = validator_state_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap();

            tracing::debug!(
                "{address} new consensus key {}",
                new_consensus_key.tm_raw_hash()
            );

            // If the old state was not Consensus, then just a
            // ConsensusValidator update is required
            if !matches!(prev_state, Some(ValidatorState::Consensus)) {
                return vec![ValidatorSetUpdate::Consensus(
                    ConsensusValidator {
                        consensus_key: new_consensus_key,
                        bonded_stake: *new_tm_voting_power,
                    },
                )];
            }

            // Now we've matched validators that were previously Consensus and
            // remain so, which also implies that an old consensus key exists

            // If the consensus key has changed, then both ConsensusValidator
            // and DeactivatedValidator updates are required
            if prev_consensus_key.as_ref() != Some(&new_consensus_key) {
                vec![
                    ValidatorSetUpdate::Consensus(ConsensusValidator {
                        consensus_key: new_consensus_key,
                        bonded_stake: *new_tm_voting_power,
                    }),
                    ValidatorSetUpdate::Deactivated(
                        prev_consensus_key.unwrap(),
                    ),
                ]
            } else if *prev_tm_voting_power == *new_tm_voting_power {
                tracing::debug!(
                    "Skipping CometBFT validator set update; {address} \
                     remains in consensus set but voting power hasn't changed"
                );
                vec![]
            } else {
                vec![ValidatorSetUpdate::Consensus(ConsensusValidator {
                    consensus_key: new_consensus_key,
                    bonded_stake: *new_tm_voting_power,
                })]
            }
        });

    tracing::debug!("Iterating over previous consensus validators:");
    let prev_consensus_validators = prev_consensus_validator_handle
        .iter(storage)?
        .map(|validator| {
            let (
                NestedSubKey::Data {
                    key: _prev_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();

            let new_state = validator_state_handle(&address)
                .get(storage, next_epoch, params)
                .unwrap();

            let prev_tm_voting_power = Lazy::new(|| {
                let prev_validator_stake = read_validator_stake(
                    storage,
                    params,
                    &address,
                    current_epoch,
                )
                .unwrap();
                into_tm_voting_power(
                    params.tm_votes_per_token,
                    prev_validator_stake,
                )
            });

            let prev_consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap()
                .unwrap();

            // If the validator is still in the Consensus set, we accounted for
            // it in the `new_consensus_validators` iterator above
            if matches!(new_state, Some(ValidatorState::Consensus)) {
                return vec![];
            } else if params.validator_stake_threshold.is_zero()
                && *prev_tm_voting_power == 0
            {
                // If the new state is not Consensus but its prev voting power
                // was 0 and the stake threshold is 0, we can also skip the
                // update
                tracing::debug!(
                    "Skipping CometBFT validator set update, {address} is in \
                     not in consensus set anymore, but it previously had no \
                     voting power"
                );
                return vec![];
            }

            // The remaining validators were previously Consensus but no longer
            // are, so they must be deactivated
            let new_consensus_key = validator_consensus_key_handle(&address)
                .get(storage, next_epoch, params)
                .unwrap()
                .unwrap();
            tracing::debug!(
                "{address} new consensus key {}",
                new_consensus_key.tm_raw_hash()
            );
            vec![ValidatorSetUpdate::Deactivated(prev_consensus_key)]
        });

    Ok(new_consensus_validators
        .chain(prev_consensus_validators)
        .flatten()
        .map(f)
        .collect())
}

/// Copy the consensus and below-capacity validator sets and positions into a
/// future epoch. Also copies the epoched set of all known validators in the
/// network.
pub fn copy_validator_sets_and_positions<S>(
    storage: &mut S,
    params: &PosParams,
    current_epoch: Epoch,
    target_epoch: Epoch,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let prev_epoch = target_epoch.prev().expect("Must have a prev epoch");

    let consensus_validator_set = consensus_validator_set_handle();
    let below_capacity_validator_set = below_capacity_validator_set_handle();

    let (consensus, below_capacity) = (
        consensus_validator_set.at(&prev_epoch),
        below_capacity_validator_set.at(&prev_epoch),
    );
    debug_assert!(!consensus.is_empty(storage)?);

    // Need to copy into memory here to avoid borrowing a ref
    // simultaneously as immutable and mutable
    let mut consensus_in_mem: HashMap<(token::Amount, Position), Address> =
        HashMap::new();
    let mut below_cap_in_mem: HashMap<
        (ReverseOrdTokenAmount, Position),
        Address,
    > = HashMap::new();

    for val in consensus.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: SubKey::Data(position),
            },
            address,
        ) = val?;
        consensus_in_mem.insert((stake, position), address);
    }
    for val in below_capacity.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: SubKey::Data(position),
            },
            address,
        ) = val?;
        below_cap_in_mem.insert((stake, position), address);
    }

    for ((val_stake, val_position), val_address) in consensus_in_mem.into_iter()
    {
        consensus_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }

    for ((val_stake, val_position), val_address) in below_cap_in_mem.into_iter()
    {
        below_capacity_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }

    // Purge consensus and below-capacity validator sets
    consensus_validator_set.update_data(storage, params, current_epoch)?;
    below_capacity_validator_set.update_data(storage, params, current_epoch)?;

    // Copy validator positions
    let mut positions = HashMap::<Address, Position>::default();
    let validator_set_positions_handle = validator_set_positions_handle();
    let positions_handle = validator_set_positions_handle.at(&prev_epoch);

    for result in positions_handle.iter(storage)? {
        let (validator, position) = result?;
        positions.insert(validator, position);
    }

    let new_positions_handle = validator_set_positions_handle.at(&target_epoch);
    for (validator, position) in positions {
        let prev = new_positions_handle.insert(storage, validator, position)?;
        debug_assert!(prev.is_none());
    }

    // Purge old epochs of validator positions
    validator_set_positions_handle.update_data(
        storage,
        params,
        current_epoch,
    )?;

    // Copy set of all validator addresses
    let mut all_validators = HashSet::<Address>::default();
    let validator_addresses_handle = validator_addresses_handle();
    let all_validators_handle = validator_addresses_handle.at(&prev_epoch);
    for result in all_validators_handle.iter(storage)? {
        let validator = result?;
        all_validators.insert(validator);
    }
    let new_all_validators_handle =
        validator_addresses_handle.at(&target_epoch);
    for validator in all_validators {
        let was_in = new_all_validators_handle.insert(storage, validator)?;
        debug_assert!(!was_in);
    }

    // Purge old epochs of all validator addresses
    validator_addresses_handle.update_data(storage, params, current_epoch)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_into_consensus_and_demote_to_below_cap<S, Gov>(
    storage: &mut S,
    validator: &Address,
    tokens_post: token::Amount,
    min_consensus_amount: token::Amount,
    current_epoch: Epoch,
    offset: u64,
    consensus_set: &ConsensusValidatorSet,
    below_capacity_set: &BelowCapacityValidatorSet,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
    Gov: governance::Read<S>,
{
    // First, remove the last position min consensus validator
    let consensus_vals_min = consensus_set.at(&min_consensus_amount);
    let last_position_of_min_consensus_vals =
        find_last_position(&consensus_vals_min, storage)?
            .expect("There must be always be at least 1 consensus validator");
    let removed_min_consensus = consensus_vals_min
        .remove(storage, &last_position_of_min_consensus_vals)?
        .expect("There must be always be at least 1 consensus validator");

    let offset_epoch = checked!(current_epoch + offset)?;

    // Insert the min consensus validator into the below-capacity
    // set
    insert_validator_into_set(
        &below_capacity_set.at(&min_consensus_amount.into()),
        storage,
        &offset_epoch,
        &removed_min_consensus,
    )?;
    validator_state_handle(&removed_min_consensus).set::<S, Gov>(
        storage,
        ValidatorState::BelowCapacity,
        current_epoch,
        offset,
    )?;

    // Insert the current validator into the consensus set
    insert_validator_into_set(
        &consensus_set.at(&tokens_post),
        storage,
        &offset_epoch,
        validator,
    )?;
    validator_state_handle(validator).set::<S, Gov>(
        storage,
        ValidatorState::Consensus,
        current_epoch,
        offset,
    )?;
    Ok(())
}

/// Find the first (lowest) position in a validator set if it is not empty
fn find_first_position<S>(
    handle: &ValidatorPositionAddresses,
    storage: &S,
) -> namada_storage::Result<Option<Position>>
where
    S: StorageRead,
{
    let lowest_position = handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(position, _addr)| position);
    Ok(lowest_position)
}

/// Find the last (greatest) position in a validator set if it is not empty
fn find_last_position<S>(
    handle: &ValidatorPositionAddresses,
    storage: &S,
) -> namada_storage::Result<Option<Position>>
where
    S: StorageRead,
{
    let position = handle
        .iter(storage)?
        .last()
        .transpose()?
        .map(|(position, _addr)| position);
    Ok(position)
}

/// Find next position in a validator set or 0 if empty
fn find_next_position<S>(
    handle: &ValidatorPositionAddresses,
    storage: &S,
) -> namada_storage::Result<Position>
where
    S: StorageRead,
{
    let position_iter = handle.iter(storage)?;
    let next = position_iter
        .last()
        .transpose()?
        .map(|(position, _address)| position.next())
        .unwrap_or_default();
    Ok(next)
}

fn get_min_consensus_validator_amount<S>(
    handle: &ConsensusValidatorSet,
    storage: &S,
) -> namada_storage::Result<token::Amount>
where
    S: StorageRead,
{
    Ok(handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(subkey, _address)| match subkey {
            NestedSubKey::Data {
                key,
                nested_sub_key: _,
            } => key,
        })
        .unwrap_or_default())
}

/// Returns `Ok(None)` when the below capacity set is empty.
fn get_max_below_capacity_validator_amount<S>(
    handle: &BelowCapacityValidatorSet,
    storage: &S,
) -> namada_storage::Result<Option<token::Amount>>
where
    S: StorageRead,
{
    Ok(handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(subkey, _address)| match subkey {
            NestedSubKey::Data {
                key,
                nested_sub_key: _,
            } => token::Amount::from(key),
        }))
}

/// Inserts a validator into the provided `handle` within some validator set at
/// the next position. Also updates the validator set position for the
/// validator.
fn insert_validator_into_set<S>(
    handle: &ValidatorPositionAddresses,
    storage: &mut S,
    epoch: &Epoch,
    address: &Address,
) -> namada_storage::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let next_position = find_next_position(handle, storage)?;
    tracing::debug!(
        "Inserting validator {} into position {:?} at epoch {}",
        address.clone(),
        next_position.clone(),
        epoch.clone()
    );
    handle.insert(storage, next_position, address.clone())?;
    validator_set_positions_handle().at(epoch).insert(
        storage,
        address.clone(),
        next_position,
    )?;
    Ok(())
}

/// Read the position of the validator in the subset of validators that have the
/// same bonded stake. This information is held in its own epoched structure in
/// addition to being inside the validator sets.
fn read_validator_set_position<S>(
    storage: &S,
    validator: &Address,
    epoch: Epoch,
    _params: &PosParams,
) -> namada_storage::Result<Option<Position>>
where
    S: StorageRead,
{
    let handle = validator_set_positions_handle();
    handle.get_data_handler().at(&epoch).get(storage, validator)
}
