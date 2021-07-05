# Proof of Stake (PoS) system

## Epoch

An epoch is a range of blocks, whose length is set by the `epoch_duration` [parameter](#system-parameters). Epochs are identified by consecutive integers starting at 0. For each epoch, we set the [relevant data](#epoched-data) in advance by the `pipeline_length` [parameter](#system-parameters).

An epoch starts at the beginning of block height `n` and end at the end of block height `n + epoch_duration - 1`. Then the following epoch starts at the beginning of block height `epoch_duration`, etc.

### Epoched data

The data relevant to the PoS system in the ledger's state are epoched. Each data can be uniquely identified. These are:
- [Active validator set](#active-validator-set). A single value for each epoch.
- [Validators' consensus key, state and total bonded tokens](#validator). Identified by the validator's address.
- [Bonds](#bonds) are created by self-bonding and delegations. They are identified by the pair of delegator's address and the validator's address.

Changes to the epoched data do not take effect immediately. Instead, changes in epoch `n` are queued to take effect in the epoch `n + pipeline_length`. Should the same validator's data or same bonds (i.e. with the same identity) be updated more than once in the same epoch, the later update overrides the previously queued-up update. For bonds, the token amounts are added up. Once the epoch `n` has ended, the queued-up updates for epoch `n + pipeline_length` become immutable.

## Entities

- [Validator](#validator): An account with a public consensus key, which may participate in producing blocks and governance activities. A validator may not also be a delegator.
- [Delegator](#delegator): An account that delegates some tokens to a validator. A delegator may not also be a validator.

Additionally, any account may submit evidence for [a slashable misbehaviour](#slashing).

### Validator

A validator must have a public consensus key. Additionally, it may also specify optional metadata fields (TBA).

A validator may be in one of the following states:
- *inactive*:
  A validator is not being considered for block creation and cannot receive any new delegations.
- *pending*:
  A validator has requested to become a *candidate*.
- *candidate*:
  A validator is considered for block creation and can receive delegations.

For each validator (in any state), the system also tracks total bonded tokens as a sum of the tokens in their self-bonds and delegated bonds, less any unbonded tokens. The total bonded tokens determine their voting voting power by division by the `votes_per_token` [parameter](#system-parameters). The voting power is used for validator selection for block creation and is used in governance related activities.

#### Validator actions

- *become validator*:
  Any account that is not a validator already and that doesn't have any delegations may request to become a validator. It is required to only provide a public consensus key. For the action applied in epoch `n`, the validator's state will be immediately set to *pending* and it will be set to *candidate* for epoch `n + pipeline_length`.
- *deactivate*:
  Only a *pending* or *candidate* validator account may *deactivate*. For this action applied in epoch `n`, the validator's account is set to become *inactive* in the epoch `n + pipeline_length`.
- *reactivate*:
  Only an *inactive* validator may *reactivate*. Similarly to *become validator* action, for this action applied in epoch `n`, the validator's state will be immediately set to *pending* and it will be set to *candidate* for epoch `n + pipeline_length`.
- *self-bond*:
  A validator may lock-up tokens into a [bond](#bonds) only for its own validator's address.
- *unbond*:
  Any self-bonded tokens may be partially or fully [unbonded](#unbond).
- *withdraw unbond*:
  Unbonded tokens may be withdrawn in or after the [unbond's epoch](#unbond).

#### Active validator set

From all the *candidate* validators, in each epoch the ones with the most voting power limited up to the `max_active_validators` [parameter](#system-parameters) are selected for the active validator set. The active validator set selected in epoch `n` is set for epoch `n + pipeline_length`.

### Delegator

A delegator may have any number number of delegations. Delegations are stored in [bonds](#bonds).

#### Delegator actions

- *delegate*:
  An account which is not a validator may delegate tokens to any number of validators. This will lock-up tokens into a [bond](#bonds).
- *undelegate*
  Any delegated tokens may be partially or fully [unbonded](#unbond).
- *withdraw unbond*:
  Unbonded tokens may be withdrawn in or after the [unbond's epoch](#unbond).

## Bonds

A bond locks-up tokens from validators' self-bonding and delegators' delegations. For self-bonding, the delegator's address is equal to the validator's address and the source of the bond is the validator's account. Only validators can self-bond. For a bond created from a delegation, the delegator's account is the bond's source.

For each epoch, bonds are uniquely identified by the pair of delegator's and validator's addresses. A bond created in epoch `n` is written into epoch `n + pipeline_length`. If there already is a bond in the epoch `n + pipeline_length` for this pair of delegator's and validator's addresses, its tokens are incremented by the newly bonded amount.

Any bonds created in epoch `n` increment the bond's validator's total bonded tokens by the bond's token amount for epoch `n + pipeline_length`.

The tokens put into a bond are immediately deducted from the source account.

### Unbond

An unbonding action (validator *unbond* or delegator *undelegate*) requested by the bond's source account in epoch `n` creates an "unbond" with epoch set to `n + unbounding_length`. We also store the epoch of the bond(s) from which the unbond is created in order to determine if the unbond should be slashed if a fault occurred within the range of bond epoch (inclusive) and unbond epoch (exclusive).

Any unbonds created in epoch `n` decrements the bond's validator's total bonded tokens by the bond's token amount for epoch `n + unbonding_length`.

An "unbond" with epoch set to `n` may be withdrawn by the bond's source address in or any time after the epoch `n`. Once withdrawn, the unbond is deleted and the tokens are credited to the source account.

### Staking rewards

TODO

### Slashing

Instead of absolute values, validators' total bonded token amounts and bonds' and unbonds' token amounts are stored as their deltas (i.e. the change of quantity from a previous epoch) to allow distinguishing changes for different epoch, which is essential for determining whether tokens be slashed. However, because slashes for a fault that occurred in epoch `n` may only be applied before the beginning of epoch `n + unbonding_length`, in epoch `m` we can sum all the deltas of total bonded token amounts and bonds and unbond with the same delegator and validator for epoch equal or less than `m - unboding_length` into a single total bonded token amount, single bond and single unbond record. This is to keep the total number of total bonded token amounts for a unique validator and bonds and unbonds for a unique pair of delegator and validator bound to a maximum number (equal to `unboding_length`).

To disincentivize validators misbehaviour in the PoS system a validator may be slashed for any fault that it has done. An evidence of misbehaviour may be submitted by any account for a fault that occurred in epoch `n` anytime before the beginning of epoch `n + unbonding_length`.

Actions that count as validator misbehaviour are:
- double signing two or more blocks at the same height
- going offline for a longer period (i.e. not producing signatures when available)

A valid evidence reduces the validator's total bonded token amount by the slash rate in and before the epoch in which the fault occurred. Additionally, a slash is stored with the misbehaving validator's address and the relevant epoch in which the fault occurred. When a bond is being unbonded or unbond withdrawn, we first look-up if any slash occurred within the range of epochs in which these were active and if so, reduce its token amount by the slash rate.

The invariant is that the sum of amounts that may be withdrawn from a misbehaving validator must always add up to the total bonded token amount.

## System parameters

- `epoch_duration`: Epoch duration in number of block, default `8640` (24 hours per epoch at the rate of 1 block every 10 secs)
- `max_active_validators`: Maximum active validators, default `128`
- `pipeline_length`: Pipeline length in number of epochs, default `2`
- `unboding_length`: Unbonding duration in number of epochs, default `6`
- `votes_per_token`: Used in validators' voting power calculation

## Storage

TODO

## Initialization

An initial validator set with self-bonded token amounts must be given on system initialization.

This set is used to pre-compute epochs in the genesis block from epoch `0` to epoch `pipeline_length - 1`.
