This will contain modifications to some functions in the PoS-model.md with Informal Systems that contains the slashing pseudocode:

In `finalize_block()` of the first block of a new epoch, the inflation for the previous epoch is computed along with the rewards for each consensus validator in the previous epoch. The raw reward amount is added to the validator deltas at the pipeline epoch, and the total deltas are appropriately updated. An entry in the validator's `RewardsProducts = LazyMap<Epoch, Decimal>` is computed for the previous epoch using the value from the epoch preceding that one (2 epochs behind the current).


```rust
// Find the most recent rewards product for the bond
fn find_last_reward_product(rp_handle, epoch) -> Decimal {

    while epoch > 0 {
        if let Some(rp) = rp_handle.get(epoch) {
            return rp;
        } else {
            epoch -= 1;
        }
    }
    rp_handle.get(epoch).unwrap_or(1.0)
}

// Get the effective amount of a bond with rewards applied (no slashing)
fn get_bond_amount_with_rewards(bonds, rp_handle, epoch) -> Amount {
    let last_rp = find_last_reward_product(rp_handle, epoch);
    let sum = 0;
    for (start_epoch, delta) in bonds {
        let rp = if start_epoch == 0 {
            1.0
        } else {
            find_last_reward_product(rp_handle, start_epoch - 1)
        };
        sum += delta * (last_rp / rp)
    }
    sum
}

// Unbonding
fn unbond(validator_address, delegator_address, total_amount, current_epoch)
{
    // Ensure that the validator address is actually a validator and that the validator is not jailed
    if state[validator_address] == JAILED { return; }
    if !is_validator(validator_address) { return; }

    let pipeline_epoch = current_epoch + pipeline_len;
    let withdraw_epoch = current_epoch + pipeline_len + unbonding_len;

    let reward_products = if validator_address != delegator_address {
        delegator_rewards_products[validator_address]
    } else {
        validator_reward_products[validator_address]
    };
    // Ensure that the unbond amount is not greater than the bond amount with rewards at pipeline offset
    if total_amount > get_bond_amount_with_rewards(bonds[delegator_address][validator_address], reward_products, pipeline_epoch) {
        return;
    }

    // Get the most recent rewards product
    let last_rp = if current_epoch == 0 {
        1.0
    } else {
        find_last_reward_product(rewards_products, current_epoch - 1)
    };

    // The current epoch and up to the pipeline epoch cannot have rewards yet
    let bonds = bonds[delegator_address][validator_address].map(|start_epoch, amount| {
        let reward_factor = if epoch < current_epoch {
            last_rp / find_last_reward_product(rewards_products, epoch);
        } else {
            1.0
        }
        (start_epoch, amount, reward_factor)
    });
    
    let bond_iter = bonds.iter().rev();

    let remaining = amount;
    let amount_after_slashing = 0;
    while remaining > 0 {
        let (start_epoch, amount, reward_factor) = bond_iter.next();
        let eff_amount = amount * reward_factor;
        let to_unbond = min(eff_bond_amount, remaining);
        let new_raw_amount = amount - (to_unbond / reward_factor);
        remaining -= to_unbond;

        let slashes = slashes[validator_address].filter(|slash| start_epoch <= slash.epoch);
        // Accounts for rewards
        let amount_after_slashing += compute_amount_after_slashing(slashes, to_unbond);

        // Update the bond with a new raw amount
        bond_deltas[delegator_address][validator_address][start_epoch] = new_raw_amount;
        // Update the unbond with an effective amount that accounts for rewards
        unbond_deltas[delegator_address][validator_address][withdraw_epoch][start_epoch] += to_unbond;

        let record = UnbondRecord{ to_unbond, start_epoch };
        valdator_set_unbonds[pipeline_epoch].insert(record);
    }

    // Update validator sets and deltas (voting powers)
    update_validator_sets(validator_address, -amount_after_slashing);
    validator_deltas[validator_address][pipeline_epoch] -= amount_after_slashing;
    total_deltas[pipeline_epoch] -= amount_after_slashing;
}

// Withdrawing tokens
// NOTE: this may not actually need adjusting for rewards, as long as everything can be taken care of in `fn unbond`
fn withdraw(validator_address, delegator_address, current_epoch) {

    for (start_epoch, withdraw_epoch, unbond_amount) in unbonds[delegator_address][validator_address] {
        if withdraw_epoch > current_epoch { continue; }
        let slashes = slashes[validator_address].filter(|slash| start_epoch <= slash.epoch && slash.epoch < withdraw_epoch - unbonding_len);
        // Rewards already accounted for inside of `unbond_amount`
        let amount_after_slashing = compute_amount_after_slashing(slashes, unbond_amount);
        balance[delegator_address] += amount_after_slashing;
        balance[pos] -= amount_after_slashing;

        // Remove the unbond
        unbonds[delegator_address][validator_address].amount([start_epoch, withdraw_epoch]) = 0;
    }
}

// End of epoch
// NOTE: only adjustment may be to properly transfer reward tokens in PoS to the Slash Pool address after slashing is applied
fn end_of_epoch() {
    todo!()
}

```