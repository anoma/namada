# PoS integration

The [PoS system](/explore/design/pos.md) is integrated into Anoma ledger via:
- an account with an internal address and a [native VP](vp.md#native-vps) and that validates any changes applied by transactions to the PoS account
- transaction WASMs to perform various PoS actions, also available as a library code for custom made transactions

All [the data relevant to the PoS system](/explore/design/pos.md#storage) are stored under the PoS account's storage sub-space, with the following key schema (the PoS address prefix is omitted for clarity):

- `parameters`: the system parameters
- `validator/{validator_address}/consensus_key`
- `validator/{validator_address}/state`
- `validator/{validator_address}/total_deltas`
- `validator/{validator_address}/voting_power`
- `slash/{validator_address}`: a list of slashes, where each record contains epoch and slash rate
- `bond/{bond_source}/{bond_validator}/delta`
- `unbond/{unbond_source}/{unbond_validator}/deltas`
- `validator_set/active`
- `validator_set/inactive`

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
  - debit the token `amount` from the `validator_address` and credit them to the `pos` account
  - add the `amount` to `validator/{validator_address}/total_deltas` in epoch `n + pipeline_length`
  - update the `validator/{validator_address}/voting_power`
  - update `validator_set`
- `unbond(amount)`:
  - let `bond = read(bond/{validator_address}/{validator_address}/delta)`
  - if `bond` doesn't exist, panic
  - let `pre_unbond = read(unbond/{validator_address}/{validator_address}/delta)`
  - if `total(bond) - total(pre_unbond) < amount`, panic
  - decrement the `bond` deltas starting from the rightmost value (a bond in a future-most epoch) until whole `amount` is decremented
  - for each decremented `bond` value write a new `unbond` with the key set to the epoch of the source value
  - decrement the `amount` from `validator/{validator_address}/total_deltas` in epoch `n + unbonding_length`
  - update the `validator/{validator_address}/voting_power`
  - update `validator_set`
- `withdraw_unbonds`:
  - let `unbond = read(unbond/{validator_address}/{validator_address}/delta)`
  - if `unbond` doesn't exist, panic
  - if no `unbond` value is found for epochs <= `n`, panic
  - for each `((bond_start, bond_end), amount) in unbond where unbond.epoch <= n`
    - let `slashed_amount = amount`
    - for each `slash in read(slash/{validator_address})`:
      - if `bond_start <= slash.epoch && slash.epoch <= bond_end)`, `slashed_amount *= (10_000 - slash.rate) / 10_000`
    - credit the `slashed_amount` to the `validator_address` and debit the whole `amount` (before slash, if any) from the `pos` account
    - TODO burn the slashed tokens, if any
- `change_consensus_key`:
  - creates a record in `validator/{validator_address}/consensus_key` in epoch `n + pipeline_length`

Additionally, `become_validator` and `change_consensus_key` must sign the transaction and attach the signature in the tx data field with the new consensus key to verify its ownership.

### Delegator transactions

The delegator transactions are assumed to be applied with an account address `delegator_address`.

- `delegate(validator_address, amount)`:
  - let `bond = read(bond/{delegator_address}/{validator_address}/delta)`
  - if `bond` exist, update it with the new bond amount in epoch `n + pipeline_length`
  - else, create a new record with bond amount in epoch `n + pipeline_length`
  - debit the token `amount` from the `delegator_address`
  - add the `amount` to `validator/{validator_address}/total_deltas` in epoch `n + pipeline_length`
  - update the `validator/{validator_address}/voting_power`
  - update `validator_set`
- `undelegate(validator_address, amount)`:
  - let `bond = read(bond/{delegator_address}/{validator_address}/delta)`
  - if `bond` doesn't exist, panic
  - let `pre_unbond = read(unbond/{delegator_address}/{validator_address}/delta)`
  - if `total(bond) - total(pre_unbond) < amount`, panic
  - decrement the `bond` deltas starting from the rightmost value (a bond in a future-most epoch) until whole `amount` is decremented
  - for each decremented `bond` value write a new `unbond` with the key set to the epoch of the source value
  - decrement the `amount` from `validator/{validator_address}/total_deltas` in epoch `n + unbonding_length`
  - update the `validator/{validator_address}/voting_power`
  - update `validator_set`
- `redelegate(src_validator_address, dest_validator_address, amount)`:
  - `undelegate(src_validator_address, amount)`
  - `delegate(dest_validator_address, amount)` but set in epoch `n + unbonding_length` instead of `n + pipeline_length`
- `withdraw_unbonds`:
  - for each `validator_address in iter_prefix(unbond/{delegator_address})`:
    - let `unbond = read(unbond/{validator_address}/{validator_address}/delta)`
    - if no `unbond` value is found for epochs <= `n`, `continue` to the next `validator_address`
    - for each `((bond_start, bond_end), amount)` in epochs <= `n`
      - let `slashed_amount = amount`
      - for each `slash in read(slash/{validator_address})`:
        - if `bond_start <= slash.epoch && slash.epoch <= bond_end)`, `slashed_amount *= (10_000 - slash.rate) / 10_000`
      - credit the `slashed_amount` to the `delegator_address` and debit the whole `amount` (before slash, if any) from the `pos` account
      - TODO burn the slashed tokens, if any

### Other transactions

- `submit_slashable_evidence(evidence)`:
  - if `evidence in slash/{evidence.validator_address}`, panic
  - validate the `evidence`
  - append the `evidence` into `slash/{evidence.validator_address}`
  - reduce the `validator/{validator_address}/total_deltas` for the `evidence.validator_address` by the slash rate in and before the `evidence.epoch`
  - update the `validator/{validator_address}/voting_power` for the `evidence.validator_address`

## Validity predicate

In the following description, "pre-state" is the state prior to transaction execution and "post-state" is the state posterior to it.

Any changes to PoS epoched data are checked to update the structure as described in [epoched data storage](/explore/design/pos.md#storage).

Because some key changes are expected to relate to others, the VP also accumulates some values that are checked for validity after key specific logic:
- `validator_total_deltas: HashMap<Address, HashMap<Epoch, token::Amount>>`
- `validator_voting_power_deltas: HashMap<Address, <HashMap<Epoch, i64>>`
- `bond_deltas: HashMap<Address, HashMap<Epoch, token::Amount>>`
- `unbond_deltas: HashMap<Address, HashMap<Epoch, token::Amount>>`
- `slashes: HashMap<Address, HashMap<Epoch, u8>>`
- `validator_set_changes: HashSet<Epoch>`

The accumulators are initialized to their default values (empty hash maps and hash set).

All the above are keyed by validator addresses.

The validity predicate triggers a validation logic based on the storage keys modified by a transaction.

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
  - find the difference between the pre-state and post-state values and add it to the `validator_voting_power_deltas` accumulator
- `slash/{validator_address}`:
  - find the newly evidence(s), validate them and add them to the `slashes` accumulator
- `bond/{bond_source}/{bond_validator}/delta`:
  - find the difference between the pre-state and post-state values and add it to the `bond_deltas` accumulator
- `unbond/{unbond_source}/{unbond_validator}/deltas`:
  - find the difference between the pre-state and post-state values and add it to the `unbond_deltas` accumulator
- `validator_set/active`:
  - set the accumulator `validator_set_changed` to true in each epoch in which it has changed
- `validator_set/inactive`:
  - set the accumulator `validator_set_changed` to true in each epoch in which it has changed

No other storage key changes are permitted by the VP.

After the storage keys iteration, we check the accumulators:

- the `validator_total_deltas` with `slashes` applied must be equal to the amounts in `bond_deltas` added with the amounts in `unbond_deltas`
- the `validator_voting_power_deltas` must be equal to `validator_total_deltas` amounts divided by `votes_per_token`
  - TODO this isn't correct, we need to check the total bonds not just the deltas because of the division
- for each slash in `slashes`, the `validator_total_deltas` must be reduced by the slash rate
- for each epoch in `validator_set_changes`, the `validator_set/active.first().voting_power` (the lowest active voting power) must be greater than or equal to `validator_set/inactive.last().voting_power` (the greatest inactive voting power)
- TODO check unbonds withdrawals and slashes, if any
