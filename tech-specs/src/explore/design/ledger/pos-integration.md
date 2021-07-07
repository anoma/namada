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
- `bond/{bond_source}/{bond_validator}/delta`
- `unbond/{unbond_source}/{unbond_validator}/bond_epoch`
- `unbond/{unbond_source}/{unbond_validator}/delta`
- `validator_set/active`
- `validator_set/inactive`

## Initialization

The PoS system is initialized via a native VP interface that is given the validator set for the genesis block.

## Validator transactions

The following transactions modifications have been applied on address `validator_address`.

- *become validator*: 
  - creates a record in `validator/{validator_address}/consensus_key`
  - sets `validator/{validator_address}/state` for to `pending` in the current epoch and `candidate` in epoch `n + pipeline_length`
- *deactivate*:
  - sets `validator/{validator_address}/state` for to `inactive` in epoch `n + pipeline_length`
- *reactivate*:
  - sets `validator/{validator_address}/state` for to `pending` in the current epoch and `candidate` in epoch `n + pipeline_length`
- *self-bond*: TODO
- *unbond*: TODO
- *withdraw unbond*: TODO

## Delegator transactions

- *delegate*: TODO
- *undelegate*: TODO
- *withdraw unbond*: TODO

## Other transactions

- *submit fault evidence*: TODO

## Validity predicate

In the following description, "pre-state" is the state prior to transaction execution and "post-state" is the state posterior to it.

The validity predicate triggers a validation logic based on the storage keys modified by a transaction:

- `validator/{validator_address}/consensus_key`:
  ```rust,ignore
  match (pre_state, post_state) {
    (None, Some(post)) => {
      // - check that any other sub-keys for this validator address didn't exist
      // in a pre-state
      // - check that the `state` sub-key for this validator address has been set
      // correctly
    },
    (Some(pre), Some(post)) => {
      // - check that a validator has been correctly deactivated or reactivated
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
    _ => false,
  }
  ```
