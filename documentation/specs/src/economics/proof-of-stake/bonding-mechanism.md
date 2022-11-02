# Bonding mechanism

### Epoched data

Epoched data is data associated with a specific epoch that is set in advance.
The data relevant to the PoS system in the ledger's state are epoched. Each data can be uniquely identified. These are:

- [System parameters](#system-parameters). Discrete values for each epoch in which the parameters have changed.
- [Validator sets](#validator-sets). Discrete values for each epoch.
- Total voting power. A sum of all validators' voting power, excluding jailed validators. A delta value for each epoch.
- [Validators' consensus key, state and total bonded tokens](#validator). Identified by the validator's address.
- [Bonds](#bonds) are created by self-bonding and delegations. They are identified by the pair of source address and the validator's address.

Changes to the epoched data do not take effect immediately. Instead, changes in epoch `n` are queued to take effect in the epoch `n + pipeline_length` for most cases and `n + pipeline_length + unboding_length` for [unbonding](#unbond) actions. Should the same validator's data or same bonds (i.e. with the same identity) be updated more than once in the same epoch, the later update overrides the previously queued-up update. For bonds, the token amounts are added up. Once the epoch `n` has ended, the queued-up updates for epoch `n + pipeline_length` are final and the values become immutable.

Additionally, any account may submit evidence for [a slashable misbehaviour](#slashing).

### Validator

A validator must have a public consensus key.

A validator may be in one of the following states:

- *inactive*:
  A validator is not being considered for block creation and cannot receive any new delegations.
- *candidate*:
  A validator is considered for block creation and can receive delegations.

For each validator (in any state), the system also tracks total bonded tokens as a sum of the tokens in their self-bonds and delegated bonds. The total bonded tokens determine their voting voting power by multiplication by the `votes_per_token` [parameter](#system-parameters). The voting power is used for validator selection for block creation and is used in governance related activities.

#### Validator actions

- *become validator*:
  Any account that is not a validator already and that doesn't have any delegations may request to become a validator. It is required to provide a public consensus key. For the action applied in epoch `n`, the validator's state will be set to *candidate* for epoch `n + pipeline_length` and the consensus key is set for epoch `n + pipeline_length`.
- *deactivate*:
  Only a validator whose state at or before the `pipeline_length` offset is *candidate* account may *deactivate*. For this action applied in epoch `n`, the validator's account is set to become *inactive* in the epoch `n + pipeline_length`.
- *reactivate*:
  Only an *inactive* validator may *reactivate*. Similarly to *become validator* action, for this action applied in epoch `n`, the validator's state will be set to *candidate* for epoch `n + pipeline_length`.
- *self-bond*:
  A validator may lock-up tokens into a [bond](#bonds) only for its own validator's address.
- *unbond*:
  Any self-bonded tokens may be partially or fully [unbonded](#unbond).
- *withdraw unbonds*:
  Unbonded tokens may be withdrawn in or after the [unbond's epoch](#unbond).
- *change consensus key*:
  Set the new consensus key. When applied in epoch `n`, the key is set for epoch `n + pipeline_length`.
- *change commission rate*:
  Set the new commission rate. When applied in epoch `n`, the new value will be set for epoch `n + pipeline_length`. The commission rate change must be within the `max_commission_rate_change` limit set by the validator.

#### Validator sets

A *candidate* validator that is not jailed (see [slashing](#slashing)) can be in one of the three sets:

- `consensus` - consensus validator set, capacity limited by the `max_validator_slots` [parameter](#system-parameters)
- `below_capacity` - validators below consensus capacity, but above the threshold  set by `min_validator_stake` [parameter](#system-parameters)
- `below_threshold` - validators with stake below `min_validator_stake` [parameter](#system-parameters)

From all the *candidate* validators, in each epoch the ones with the most voting power limited up to the `max_validator_slots` [parameter](#system-parameters) are selected for the `consensus` validator set. Whenever stake of a validator is changed, the validator sets must be updated at the appropriate offset matching the stake update.

The limit on `min_validator_stake` [parameter](#system-parameters) is introduced, because the protocol needs to iterate through the validator sets in order to copy the last known state into a new epoch when epoch changes (to avoid offloading this cost to a transaction that is unlucky enough to be the first one to update the validator set(s) in some new epoch) and also to [distribute rewards](./reward-distribution.md) to `consensus` validators and to record unchanged validator products for validators `below_capacity`, who do not receive rewards in the current epoch.

### Delegator

A delegator may have any number of delegations to any number of validators. Delegations are stored in [bonds](#bonds).

#### Delegator actions

- *delegate*:
  An account which is not a validator may delegate tokens to any number of validators. This will lock-up tokens into a [bond](#bonds).
- *undelegate*:
  Any delegated tokens may be partially or fully [unbonded](#unbond).
- *withdraw unbonds*:
  Unbonded tokens may be withdrawn in or after the [unbond's epoch](#unbond).

## Bonds

A bond locks-up tokens from validators' self-bonding and delegators' delegations. For self-bonding, the source address is equal to the validator's address. Only validators can self-bond. For a bond created from a delegation, the bond's source is the delegator's account.

For each epoch, bonds are uniquely identified by the pair of source and validator's addresses. A bond created in epoch `n` is written into epoch `n + pipeline_length`. If there already is a bond in the epoch `n + pipeline_length` for this pair of source and validator's addresses, its tokens are incremented by the newly bonded amount.

Any bonds created in epoch `n` increment the bond's validator's total bonded tokens by the bond's token amount and update the voting power for epoch `n + pipeline_length`.

The tokens put into a bond are immediately deducted from the source account.

### Unbond

An unbonding action (validator *unbond* or delegator *undelegate*) requested by the bond's source account in epoch `n` creates an "unbond" with epoch set to `n + pipeline_length + unbounding_length`. We also store the epoch of the bond(s) from which the unbond is created in order to determine if the unbond should be slashed if a fault occurred within the range of bond epoch (inclusive) and unbond epoch (exclusive). The "bond" from which the tokens are being unbonded is decremented in-place (in whatever epoch it was created in).

Any unbonds created in epoch `n` decrements the bond's validator's total bonded tokens by the bond's token amount and update the voting power for epoch `n + pipeline_length`.

An "unbond" with epoch set to `n` may be withdrawn by the bond's source address in or any time after the epoch `n`. Once withdrawn, the unbond is deleted and the tokens are credited to the source account.

Note that unlike bonding and unbonding where token changes are delayed to some future epochs (pipeline or unbonding offset), the token withdrawal applies immediately. This because when the tokens are withdrawable, they are already "unlocked" from the PoS system and do not contribute to voting power.

### Slashing

An important part of the security model of Namada is based on making attacking the system very expensive. To this end, the validator who has bonded stake will be slashed once an offense has been detected.

These are the types of offenses:

- Equivocation in consensus
  - voting: meaning that a validator has submitted two votes that are conflicting
  - block production: a block producer has created two different blocks for the same height
- Invalidity:
  - block production: a block producer has produced invalid block
  - voting: validators have voted on invalid block

Unavailability is not considered an offense, but a validator who hasn't voted will not receive rewards.

Once an offense has been reported:

1. Kicking out
2. Slashing

- Individual: Once someone has reported an offense it is reviewed by validators and if confirmed the offender is slashed.
- [cubic slashing](./cubic-slashing.md): escalated slashing

Instead of absolute values, validators' total bonded token amounts and bonds' and unbonds' token amounts are stored as their deltas (i.e. the change of quantity from a previous epoch) to allow distinguishing changes for different epoch, which is essential for determining whether tokens should be slashed. Slashes for a fault that occurred in epoch `n` may only be applied before the beginning of epoch `n + unbonding_length`. For this reason, in epoch `m` we can sum all the deltas of total bonded token amounts and bonds and unbond with the same source and validator for epoch equal or less than `m - unboding_length` into a single total bonded token amount, single bond and single unbond record. This is to keep the total number of total bonded token amounts for a unique validator and bonds and unbonds for a unique pair of source and validator bound to a maximum number (equal to `unbonding_length`).

To disincentivize validators misbehaviour in the PoS system a validator may be slashed for any fault that it has done. An evidence of misbehaviour may be submitted by any account for a fault that occurred in epoch `n` anytime before the beginning of epoch `n + unbonding_length`.

A valid evidence reduces the validator's total bonded token amount by the slash rate in and before the epoch in which the fault occurred. The validator's voting power must also be adjusted to the slashed total bonded token amount. Additionally, a slash is stored with the misbehaving validator's address and the relevant epoch in which the fault occurred. When an unbond is being withdrawn, we first look-up if any slash occurred within the range of epochs in which these were active and if so, reduce its token amount by the slash rate. Note that bonds and unbonds amounts are not slashed until their tokens are withdrawn.

The invariant is that the sum of amounts that may be withdrawn from a misbehaving validator must always add up to the total bonded token amount.

## Initialization

An initial validator set with self-bonded token amounts must be given on system initialization.

This set is used to initialize the genesis state with epoched data active immediately (from the first epoch).

## System parameters

The default values that are relative to epoch duration assume that an epoch last about 24 hours.

- `max_validator_slots`: Maximum consensus validators, default `128`
- `min_validator_stake`: Minimum stake of a validator that allows the validator to enter the `consensus` or `below_capacity` [sets](#validator-sets), in number of native tokens. Because the [inflation system](../inflation-system.md#proof-of-stake-rewards) targets a bonding ratio of 2/3, the minimum should be somewhere around `total_supply * 2/3 / max_validator_slots`, but it can and should be much lower to lower the entry cost, as long as it's enough to prevent validation account creation spam that could slow down PoS system update on epoch change
- `pipeline_len`: Pipeline length in number of epochs, default `2` (see <https://github.com/cosmos/cosmos-sdk/blob/019444ae4328beaca32f2f8416ee5edbac2ef30b/docs/architecture/adr-039-epoched-staking.md#pipelining-the-epochs>)
- `unboding_len`: Unbonding duration in number of epochs, default `6`
- `votes_per_token`: Used in validators' voting power calculation, default 100‱ (1 voting power unit per 1000 tokens)
- `duplicate_vote_slash_rate`: Portion of validator's stake that should be slashed on a duplicate vote
- `light_client_attack_slash_rate`: Portion of validator's stake that should be slashed on a light client attack

## Storage

The [system parameters](#system-parameters) are written into the storage to allow for their changes. Additionally, each validator may record a new parameters value under their sub-key that they wish to change to, which would override the systems parameters when more than 2/3 voting power are in agreement on all the parameters values.

The validators' data are keyed by the their addresses, conceptually:

```rust,ignore
type Validators = HashMap<Address, Validator>;
```

Epoched data are stored in a structure, conceptually looking like this:

```rust,ignore
struct Epoched<Data> {
  /// The epoch in which this data was last updated
  last_update: Epoch,
  /// How many epochs of historical data to keep, this is `0` in most cases
  /// except for validator `total_deltas` and `total_unbonded`, in which 
  /// historical data for up to `pipeline_length + unbonding_length - 1` is 
  /// needed to be able to apply any slashes that may occur.
  /// The value is not actually stored with the data, it's either constant 
  /// value or resolved from PoS parameters on which it may depends.
  past_epochs_to_store: u64,
  /// An ordered map in which the head is the data for epoch in which 
  /// the `last_update - past_epochs_to_store` was performed and every
  /// consecutive epoch up to a required length. For system parameters, 
  /// and all the epoched data 
  /// `LENGTH = past_epochs_to_store + pipeline_length + 1`, 
  /// with exception of unbonds, for which 
  /// `LENGTH = past_epochs_to_store + pipeline_length + unbonding_length + 1`.
  data: Map<Epoch, Option<Data>>
}
```

Note that not all epochs will have data set, only the ones in which some changes occurred. The only exception to this are the `consensus` and `below_capacity` validator sets, which are written on a new epoch from the latest state into the new epoch by the protocol. This is so that a transaction never has to update the whole validator set when it hasn't changed yet in the current epoch, which would require a copy of the last epoch data and that copy would additionally have to be verified by the PoS validity predicate.

To try to look-up a value for `Epoched` data with discrete values in each epoch (such as the consensus validator set) in the current epoch `n`:

1. read the `data` field at epoch `n`:
   1. if there's a value at `n` return it
   1. else if `n == last_update - past_epochs_to_store`, return `None`
   1. else decrement `n` and repeat this sub-step from 1.

To look-up a value for `Epoched` data with delta values in the current epoch `n`:

1. sum all the values that are not `None` in the `last_update - past_epochs_to_store .. n` epoch range bounded inclusively below and above

To update a value in `Epoched` data with discrete values in epoch `n` with value `new` for epoch `m`:

1. let `epochs_to_clear = min(n - last_update, LENGTH)`
1. if `epochs_to_clear == 0`:
   1. `data[m] = new`
1. else:
   1. for `i in last_update - past_epochs_to_store .. last_update - past_epochs_to_store + epochs_to_clear` range bounded inclusively below and exclusively above, set `data[i] = None`
   1. set `data[m] = new`
   1. set `last_update` to the current epoch

To update a value in `Epoched` data with delta values in epoch `n` with value `delta` for epoch `m`:

1. let `epochs_to_sum = min(n - last_update, LENGTH)`
1. if `epochs_to_sum == 0`:
   1. set `data[m] = data[m].map_or_else(delta, |last_delta| last_delta + delta)` (add the `delta` to the previous value, if any, otherwise use the `delta` as the value)
1. else:
   1. let `sum` to be equal to the sum of all delta values in the `last_update - past_epochs_to_store .. last_update - past_epochs_to_store + epochs_to_sum` range bounded inclusively below and exclusively above and set `data[i] = None`
   1. set `data[n - past_epochs_to_store] = data[n - past_epochs_to_store].map_or_else(sum, |last_delta| last_delta + sum)` to add the sum to the last epoch that will be stored
   1. set `data[m] = data[m].map_or_else(delta, |last_delta| last_delta + delta)` to add the new delta
   1. set `last_update` to the current epoch

The invariants for updates in both cases are that `m >= n` (epoched data cannot be updated in an epoch lower than the current epoch) and `m - n <= LENGTH - past_epochs_to_store` (epoched data can only be updated at the future-most epoch set by the `LENGTH - past_epochs_to_store` of the data).

We store the `consensus` validators and validators `below_capacity` in two set, ordered by their voting power. We don't have to store the validators `below_threshold` in a set, because we don't need to know their order.

Note that we still need to store `below_capacity` set in order of their voting power, because when e.g. one of the `consensus` validator's voting power drops below that of a maximum `below_capacity` validator, we need to know which validator to swap in into the `consensus` set. The protocol new epoch update just disregards validators who are not in `consensus` or `below_capacity` sets as `below_threshold` validators and so iteration on unbounded size is avoided. Instead the size of the validator set that is regarded for PoS rewards can be adjusted by the `min_validator_stake` parameter via governance.

Conceptually, this may look like this:

```rust,ignore
type VotingPower = u64;

/// Validator's address with its voting power.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct WeightedValidator {
  /// The `voting_power` field must be on top, because lexicographic ordering is
  /// based on the top-to-bottom declaration order and in the `ValidatorSet`
  /// the `WeighedValidator`s these need to be sorted by the `voting_power`.
  voting_power: VotingPower,
  address: Address,
}

struct ValidatorSet {
  /// Active validator set with maximum size equal to `max_validator_slots`
  consensus: BTreeSet<WeightedValidator>,
  /// Other validators that are not in `consensus`, but have stake above `min_validator_stake`
  below_threshold: BTreeSet<WeightedValidator>,
}

type ValidatorSets = Epoched<ValidatorSet>;

/// The sum of all validators voting power (including `below_threshold`)
type TotalVotingPower = Epoched<VotingPower>;
```

When any validator's voting power changes, we attempt to perform the following update on the `ValidatorSet`:

1. let `validator` be the validator's address, `power_before` and `power_after` be the voting power before and after the change, respectively
1. find if the `power_before` and `power_after` are above the `min_validator_stake` threshold
   1. if they're both below the threshold, nothing else needs to be done
1. let `power_delta = power_after - power_before`
1. let `min_consensus = consensus.first()` (consensus validator with lowest voting power)
1. let `max_below_capacity = below_capacity.last()` (below_capacity validator with greatest voting power)
1. find whether the validator was in consensus set, let `was_in_consensus = power_before >= max_below_capacity.voting_power`
1. find whether the validator was in below capacity set, let `was_below_capacity = power_before > min_validator_stake`
   1. if `was_in_consensus`:
      1. if `power_after >= max_below_capacity.voting_power`, update the validator in `consensus` set with `voting_power = power_after`
      1. else if `power_after < min_validator_stake`, remove the validator from `consensus`, insert the `max_below_capacity.address` validator into `consensus` and remove `max_below_capacity.address` from `below_capacity`
      1. else, remove the validator from `consensus`, insert it into `below_capacity` and remove `max_below_capacity.address` from `below_capacity` and insert it into `consensus`
   1. else if `was_below_capacity`:
      1. if `power_after <= min_consensus.voting_power`, update the validator in `below_capacity` set with `voting_power = power_after`
      1. else if `power_after < min_validator_stake`, remove the validator from `below_capacity`
      1. else, remove the validator from `below_capacity`, insert it into `consensus` and remove `min_consensus.address` from `consensus` and insert it into `below_capacity`
   1. else (if validator was below minimum stake):
      1. if `power_after > min_consensus.voting_power`, remove the `min_consensus.address` from `consensus`, insert the `min_consensus.address` into `below_capacity` and insert the validator in `consensus` set with `voting_power = power_after`
      1. else if `power_after >= min_validator_stake`, insert the validator into `below_capacity` set with `voting_power = power_after`
      1. else, do nothing

Additionally, for [rewards distribution](./reward-distribution.md):

- When a validator moves from `below_threshold` set to either `below_capacity` or `consensus` set, the transaction must also fill in the validator's reward products from its last known value, if any, in all epochs starting from their `last_known_product_epoch` (exclusive) up to the `current_epoch + pipeline_len - 1` (inclusive) in order to make their look-up cost constant (assuming that validator's stake can only be increased at `pipeline_len` offset).
- And on the opposite side, when a stake of a validator from `consensus` or `below_capacity` drops below `min_validator_stake`, we record their `last_known_product_epoch`, so that it can be used if and when the validator's stake goes above `min_validator_stake`.

Within each validator's address space, we store public consensus key, state, total bonded token amount, total unbonded token amount (needed for applying of slashes) and voting power calculated from the total bonded token amount (even though the voting power is stored in the `ValidatorSet`, we also need to have the `voting_power` here because we cannot look it up in the `ValidatorSet` without iterating the whole set):

```rust,ignore
struct Validator {
  consensus_key: Epoched<PublicKey>,
  state: Epoched<ValidatorState>,
  total_deltas: Epoched<token::Amount>,
  total_unbonded: Epoched<token::Amount>,
  voting_power: Epoched<VotingPower>,
}

enum ValidatorState {
  Inactive,
  Candidate,
}
```

The bonds and unbonds are keyed by their identifier:

```rust,ignore
type Bonds = HashMap<BondId, Epoched<Bond>>;
type Unbonds = HashMap<BondId, Epoched<Unbond>>;

struct BondId {
  validator: Address,
  /// The delegator adddress for delegations, or the same as the `validator`
  /// address for self-bonds.
  source: Address,
}

struct Bond {
  /// A key is a the epoch set for the bond. This is used in unbonding, where
  // it's needed for slash epoch range check.
  deltas: HashMap<Epoch, token::Amount>,
}

struct Unbond {
  /// A key is a pair of the epoch of the bond from which a unbond was created
  /// the epoch of unboding. This is needed for slash epoch range check.
  deltas: HashMap<(Epoch, Epoch), token::Amount>
}
```

For slashes, we store the epoch and block height at which the fault occurred, slash rate and the slash type:

```rust,ignore
struct Slash {
  epoch: Epoch,
  block_height: u64,
  /// slash token amount ‱ (per ten thousand)
  rate: u8,
  r#type: SlashType,
}
```

