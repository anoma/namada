# PoS integration

The [PoS system](/explore/design/pos.md) is integrated into Anoma ledger via:
- an account with an internal address and a [native VP](vp.md#native-vps) and that validates any changes applied by transactions to the PoS account
- transaction WASMs to perform various PoS actions, also available as a library code for custom made transactions

All [the data relevant to the PoS system](/explore/design/pos.md#storage) are stored under the PoS account's storage sub-space, with the following key schema (the PoS address prefix is omitted for clarity):

- `parameters`: the system parameters
- `parameters/{parameters_hash}`: the system parameters value with this `parameters_hash `
- `parameters/{parameters_hash}/{validator_address}`: a set of validators who want to switch to parameters with this `parameters_hash` (only keys are needed here, so the value can be a `unit`)
- `validator/{validator_address}/consensus_key`
- `validator/{validator_address}/state`
- `validator/{validator_address}/total_deltas`
- `validator/{validator_address}/voting_power`
- `slash/{validator_address}`: a list of slashes, where each record contains epoch and slash rate
- `bond/{bond_source}/{bond_validator}/delta`
- `unbond/{unbond_source}/{unbond_validator}/deltas`
- `validator_set/active`
- `validator_set/inactive`
- `total_voting_power`

Additionally, only XAN tokens can be staked. The tokens being staked (bonds and unbonds amounts) are kept in the XAN token account under `{xan_address}/balance/{pos_address}`.

## Initialization

The PoS system is initialized via a native VP interface that is given the validator set for the genesis block.

## Transactions

The transactions are assumed to be applied in epoch `n`. Any transaction that modifies [epoched data](/explore/design/pos.md#epoched-data) updates the structure as described in [epoched data storage](/explore/design/pos.md#storage).

### Validator transactions

The validator transactions are assumed to be applied with an account address `validator_address`.

- `become_validator(consensus_key)`:
  - creates a record in `validator/{validator_address}/consensus_key` in epoch `n + pipeline_length`
  - sets `validator/{validator_address}/state` for to `pending` in the current epoch and `candidate` in epoch `n + pipeline_length`
- `deactivate`:
  - sets `validator/{validator_address}/state` for to `inactive` in epoch `n + pipeline_length`
- `reactivate`:
  - sets `validator/{validator_address}/state` for to `pending` in the current epoch and `candidate` in epoch `n + pipeline_length`
- `self_bond(amount)`:
  - let `bond = read(bond/{validator_address}/{validator_address}/delta)`
  - if `bond` exist, update it with the new bond amount in epoch `n + pipeline_length`
  - else, create a new record with bond amount in epoch `n + pipeline_length`
  - debit the token `amount` from the `validator_address` and credit it to the PoS account
  - add the `amount` to `validator/{validator_address}/total_deltas` in epoch `n + pipeline_length`
  - update the `validator/{validator_address}/voting_power` in epoch `n + pipeline_length`
  - update the `total_voting_power` in epoch `n + pipeline_length`
  - update `validator_set` in epoch `n + pipeline_length`
- `unbond(amount)`:
  - let `bond = read(bond/{validator_address}/{validator_address}/delta)`
  - if `bond` doesn't exist, panic
  - let `pre_unbond = read(unbond/{validator_address}/{validator_address}/delta)`
  - if `total(bond) - total(pre_unbond) < amount`, panic
  - decrement the `bond` deltas starting from the rightmost value (a bond in a future-most epoch) until whole `amount` is decremented
  - for each decremented `bond` value write a new `unbond` with the key set to the epoch of the source value
  - decrement the `amount` from `validator/{validator_address}/total_deltas` in epoch `n + unbonding_length`
  - update the `validator/{validator_address}/voting_power` in epoch `n + unbonding_length`
  - update the `total_voting_power` in epoch `n + unbonding_length`
  - update `validator_set` in epoch `n + unbonding_length`
- `withdraw_unbonds`:
  - let `unbond = read(unbond/{validator_address}/{validator_address}/delta)`
  - if `unbond` doesn't exist, panic
  - if no `unbond` value is found for epochs <= `n`, panic
  - for each `((bond_start, bond_end), amount) in unbond where unbond.epoch <= n`:
    - let `amount_after_slash = amount`
    - for each `slash in read(slash/{validator_address})`:
      - if `bond_start <= slash.epoch && slash.epoch <= bond_end)`, `amount_after_slash *= (10_000 - slash.rate) / 10_000`
    - credit the `amount_after_slash` to the `validator_address` and debit the whole `amount` (before slash, if any) from the PoS account
    - burn the slashed tokens (`amount - amount_after_slash`), if not zero
- `change_consensus_key`:
  - creates a record in `validator/{validator_address}/consensus_key` in epoch `n + pipeline_length`
- `change_system_params(params)`:
  - let `params_hash = hash(params)`
  - insert `parameters/{params_hash}/{validator_address}`
  - write the `params` value into `parameters/{params_hash}`
  - let `validators = parameters/{param_hash}`:
    - if the sum of validators' voting power for epoch `n` is > 2/3 of `total_voting_power`:
      - write the `params` value into `parameters` storage for epoch `n + unbonding_length`
      - NOTE: because the validators who wanted this change may be slashed after the change is applied, we have to re-check any queued up parameters change in `submit_slashable_evidence` transaction and validate this in the VP
- `remove_system_params_change(params_hash)`:
  - remove `parameters/{params_hash}/{validator_address}`
  - if the validator set with the prefix `parameters/{params_hash}/` is now empty, remove `parameters/{params_hash}` storage with the parameters value

Additionally, `become_validator` and `change_consensus_key` must sign the transaction and attach the signature in the tx data field with the new consensus key to verify its ownership.

### Delegator transactions

The delegator transactions are assumed to be applied with an account address `delegator_address`.

- `delegate(validator_address, amount)`:
  - let `bond = read(bond/{delegator_address}/{validator_address}/delta)`
  - if `bond` exist, update it with the new bond amount in epoch `n + pipeline_length`
  - else, create a new record with bond amount in epoch `n + pipeline_length`
  - debit the token `amount` from the `delegator_address` and credit it to the PoS account
  - add the `amount` to `validator/{validator_address}/total_deltas` in epoch `n + pipeline_length`
  - update the `validator/{validator_address}/voting_power` in epoch `n + pipeline_length`
  - update the `total_voting_power` in epoch `n + pipeline_length`
  - update `validator_set` in epoch `n + pipeline_length`
- `undelegate(validator_address, amount)`:
  - let `bond = read(bond/{delegator_address}/{validator_address}/delta)`
  - if `bond` doesn't exist, panic
  - let `pre_unbond = read(unbond/{delegator_address}/{validator_address}/delta)`
  - if `total(bond) - total(pre_unbond) < amount`, panic
  - decrement the `bond` deltas starting from the rightmost value (a bond in a future-most epoch) until whole `amount` is decremented
  - for each decremented `bond` value write a new `unbond` with the key set to the epoch of the source value
  - decrement the `amount` from `validator/{validator_address}/total_deltas` in epoch `n + unbonding_length`
  - update the `validator/{validator_address}/voting_power` in epoch `n + unbonding_length`
  - update the `total_voting_power` in epoch `n + unbonding_length`
  - update `validator_set` in epoch `n + unbonding_length`
- `redelegate(src_validator_address, dest_validator_address, amount)`:
  - `undelegate(src_validator_address, amount)`
  - `delegate(dest_validator_address, amount)` but set in epoch `n + unbonding_length` instead of `n + pipeline_length`
- `withdraw_unbonds`:
  - for each `validator_address in iter_prefix(unbond/{delegator_address})`:
    - let `unbond = read(unbond/{validator_address}/{validator_address}/delta)`
    - if no `unbond` value is found for epochs <= `n`, `continue` to the next `validator_address`
    - for each `((bond_start, bond_end), amount)` in epochs <= `n`:
      - let `amount_after_slash = amount`
      - for each `slash in read(slash/{validator_address})`:
        - if `bond_start <= slash.epoch && slash.epoch <= bond_end)`, `amount_after_slash *= (10_000 - slash.rate) / 10_000`
      - credit the `amount_after_slash` to the `delegator_address` and debit the whole `amount` (before slash, if any) from the PoS account
      - burn the slashed tokens (`amount - amount_after_slash`), if not zero

### Other transactions

- `submit_slashable_evidence(evidence)`:
  - if `evidence in slash/{evidence.validator_address}`, panic
  - validate the `evidence`
  - append the `evidence` into `slash/{evidence.validator_address}`
  - reduce the `validator/{validator_address}/total_deltas` for the `evidence.validator_address` by the slash rate in and before the `evidence.epoch`
  - update the `validator/{validator_address}/voting_power` for the `evidence.validator_address` in and after epoch `n`
  - update the `total_voting_power` in and after epoch `n`
  - update `validator_set` in and after epoch `n`
  - if there's a `parameters` change in any epoch after `n`, check that more than 2/3 of validators' voting power agree to the change or remove the queued up change if not

## Validity predicate

In the following description, "pre-state" is the state prior to transaction execution and "post-state" is the state posterior to it.

Any changes to PoS epoched data are checked to update the structure as described in [epoched data storage](/explore/design/pos.md#storage).

Because some key changes are expected to relate to others, the VP also accumulates some values that are checked for validity after key specific logic:
- `validator_total_deltas: HashMap<Address, HashMap<Epoch, token::Change>>`
- `validator_voting_powers: HashMap<Address, <HashMap<Epoch, u64>>`
- `bond_deltas: HashMap<Address, HashMap<Epoch, Bond>>`
- `unbond_deltas: HashMap<Address, HashMap<Epoch, Unbond>>`
- `slashes: HashMap<Address, HashMap<Epoch, u8>>`
- `validator_set_changes: HashSet<Epoch>`

The accumulators are initialized to their default values (empty hash maps and hash set).

All the above are keyed by validator addresses.

The validity predicate triggers a validation logic based on the storage keys modified by a transaction.

- `parameters`:
  - if the `parameters` changed in epoch other than `n + unbonding_length`, panic
  - check that more than 2/3 voting power agreed to the parameters change in `parameters/{parameters_hash}/{any_validator_address}` post-state
- `parameters/{parameters_hash}`:
  - check that the hash of value is equal to the `parameters_hash` in the key
- `parameters/{parameters_hash}/{validator_address}`:
  - check that the `parameters/{parameters_hash}` exists in the pre-state and post-state
- `validator/{validator_address}/consensus_key`:
  ```rust,ignore
  match (pre_state, post_state) {
    (None, Some(post)) => {
      // - verify signature from tx.data against the post consensus key
      // - check that any other sub-keys for this validator address didn't exist
      // in a pre-state
      // - check that the `state` sub-key for this validator address has been set
      // correctly
    },
    (Some(pre), Some(post)) => {
      // - verify signature from tx.data against the post consensus key
      // - check that the new consensus key is different from the old consensus
      // key and that it has been set correctly
    },
    _ => false,
  }
  ```
- `validator/{validator_address}/state`:
  ```rust,ignore
  match (pre_state, post_state) {
    (None, Some(post)) => {
      // - check that any other sub-keys for this validator address didn't exist
      // in a pre-state
      // - check that a consensus key record is also created
      // - check that the `post` state is set correctly
    },
    (Some(pre), Some(post)) => {
      // - check that a validator has been correctly deactivated or reactivated
    },
    _ => false,
  }
  ```
- `validator/{validator_address}/total_deltas`:
  - find the difference between the pre-state and post-state values and add it to the `validator_total_deltas` accumulator
- `validator/{validator_address}/voting_power`:
  - find the post-state value and insert it into the `validator_voting_powers` accumulator
- `slash/{validator_address}`:
  - find the newly evidence(s), ensure that they're not already present in the pre-state, validate them and add them to the `slashes` accumulator
  - check that the validator's total deltas have been slashed correctly
  - check that the validator's voting power has been adjusted correctly
  - check that the total voting power has been adjusted correctly
  - check that the the active and inactive validator sets are correct
  - check that if there's was a `parameters` change in any epoch after `n` in pre-state, more than 2/3 of validators' voting power still agree to the change, otherwise the queued up change must have been removed in the post-state
- `bond/{bond_source}/{bond_validator}/delta`:
  - for each difference between the post-state and pre-state values:
    - if the difference is not in epoch `n` or `n + pipeline_length`, panic
    - add it to the `bond_deltas` accumulator
- `unbond/{unbond_source}/{unbond_validator}/deltas`:
  - for each difference between the post-state and pre-state values:
    - if the difference is not in epoch `n` or `n + unboding_length`, panic
    - add it to the `unbond_deltas` accumulator
- `validator_set/active`:
  - set the accumulator `validator_set_changed` to true in each epoch in which it has changed
- `validator_set/inactive`:
  - set the accumulator `validator_set_changed` to true in each epoch in which it has changed

No other storage key changes are permitted by the VP.

After the storage keys iteration, we check the accumulators:

- the `validator_total_deltas` must be equal to the amounts in `bond_deltas` added with the amounts in `unbond_deltas` with slashes applied where the slash's epoch is in bond's or unbond's epoch range
- the sum of differences between the `validator_total_deltas` in epoch `n + unbonding_length` and epoch `n + pipeline_length` must be equal to the difference in PoS account's token balance between post-state and pre-state
- for each `validator_voting_powers`:
  - find the validator's total bonded tokens from post-state
  - the total bonded tokens divided by `votes_per_token` must be equal to the voting power
- for each slash in `slashes`, the `validator_total_deltas` must be reduced by the slash rate
- for each epoch in `validator_set_changes`, the `validator_set/active.first().voting_power` (the lowest active voting power) must be greater than or equal to `validator_set/inactive.last().voting_power` (the greatest inactive voting power)
- for each `validator_total_deltas`, check that the validator's voting power has been adjusted correctly
- if `validator_total_deltas` is not empty:
  - check that the total voting power has been adjusted correctly
  - check that the the active and inactive validator sets are correct
