# Cubic slashing

Namada implements a slashing scheme that is called cubic slashing: the amount of a slash is proportional to the cube of the voting power committing infractions within a particular interval. This is designed to make it riskier to operate larger or similarly configured validators, and thus the scheme encourages network resilience. To further deter misbehavior from such correlated validators, the amount slashed for a given misbehavior increases with the existence of other misbehaviors committed in the same or nearby epochs by any validator.

Because the cubic slash rate is a function of all infractions in a given epoch and its neighboring epochs, the cubic slash rate is the same for any infraction within a given epoch. The slash rate is determined as follows: 
1. Collect all known infractions committed within a range of `[- window_width, + window_width]` epochs around the infraction in question. By default, `window_width = 1`.
2. Sum the fractional voting powers (relative to the total PoS voting power) of the misbehaving validator for each of the collected infractions. <!-- The total voting powers include all validators in one of the validator sets and all jailed validators (more on this later). -->
3. The cubic slash rate is then proportional to this sum. Using $\text{vp}$ to indicate voting power, the cubic rate is expressed as:

$$  9*\big(\sum_{i \in \text{infractions}}\frac{\text{vp}_i}{\text{vp}_{\text{tot}}}\big)^2. $$

For each individual slash, the rate is ultimately determined as the maximum of the cubic slash rate and some nominal minimum rate that is dependent on the infraction type (light client attack v. duplicate vote, reference Tendermint) and is capped at 1.0. The amount of slashed tokens is the rate multiplied by the stake (voting power) used to commit the infraction. The "cubic" in cubic slashing thus comes from the product of the rate, which is quadratic in the voting power, and the voting power itself.

Expressed in pseudocode:
<!-- I want to make these two code blocks toggleable as in  https://rdmd.readme.io/docs/code-blocks#tabbed-code-blocks but can't seem to get it to work-->
<!-- ```haskell =
calculateSlashRate :: [Slash] -> Float

calculateSlashRate slashes = 
    let votingPowerFraction = sum [ votingPowerFraction (validator slash) | slash <- slashes]
	in max 0.01 (min 1 (votingPowerFraction**2)*9)
  -- minimum slash rate is 1%
  -- then exponential between 0 & 1/3 voting power
  -- we can make this a more complex function later
``` -->

<!-- ```python
class PoS:
    def __init__(self, genesis_validators : list):
        self.update_validators(genesis_validators)
    
    def update_validators(self, new_validators):
        self.validators = new_validators
        self.total_voting_power = sum(validator.voting_power for validator in self.validators)
    
    def slash(self, slashed_validators : list):
        for slashed_validator in slashed_validators: 
            voting_power_fraction = slashed_validator.voting_power / self.total_voting_power
            slash_rate = calc_slash_rate(voting_power_fraction)
            slashed_validator.voting_power *= (1 - slash_rate)

    def get_voting_power(self):
        for i in range(min(10, len(self.validators))):
            print(self.validators[i])
    
    @staticmethod
    def calc_slash_rate(voting_power_fraction):
        slash_rate = max(0.01, (voting_power_fraction ** 2) * 9)
        return slash_rate
``` -->
```rust
// Infraction type, where inner field is the slash rate for the type
enum Infraction {
    DuplicateVote(Decimal),
    LightClientAttack(Decimal)
}

// Generic validator with an address and voting power
struct Validator {
    address: Vec<u8>,
    voting_power: u64,
}

// Generic slash object with the misbehaving validator and infraction type
struct Slash {
    validator: Validator,
    infraction_type: Infraction,
}

// Calculate the cubic slash rate for a slash in the current epoch
fn calculate_cubic_slash_rate(
    current_epoch: u64,
    nominal_slash_rate: Decimal,
    cubic_window_width: u64,
    slashes: Map<u64, Vec<Slash>>,
    total_voting_power: u64
) -> Decimal {
    let mut vp_frac_sum = Decimal::ZERO;

    let start_epoch = current_epoch - cubic_window_width;
    let end_epoch = current_epoch + cubic_window_width;

    for epoch in start_epoch..=end_epoch {
        let cur_slashes = slashes.get(epoch);
        let vp_frac_this_epoch = cur_slashes.iter.fold(0, |sum, Slash{validator, _}|
            { sum + validator.voting_power / total_voting_power}
        );
        vp_frac_sum += vp_frac_this_epoch;
    }
    let rate = cmp::min(
        Decimal::ONE,
        cmp::max(
            slash.infraction_type.0,
            9 * vp_frac_sum * vp_frac_sum,
        ),
    );
    rate
}
```

As a function, it can be drawn as (assuming $r_{\text{min}} = 1\%$):

[<img src="../images/cubic_slash.png" width="500"/>](../images/cubic_slash.png)

> Note: The voting power associated with a slash is the voting power of the validator **when they violated the protocol**. This does mean that these voting powers may not sum to 1, but this method should still be close to the desired incentives and cannot really be changed without making the system easier to game.


# Slashing procedure

With the aspects of cubic slashing defined above, this section walks through the overall Namada slashing procedure. In general, slashes are recorded and enqueued immediately upon detection, but their rates are not determined until some fixed number of epochs later. While building the first block of a new epoch, each slash from a specific past epoch is processed: its rate is determined and then it is applied to appropriate validators. Slashing occurs at a delay relative to the infraction epoch to allow for sufficient time to detect any other validator misbehaviors while still processing the slash before the stake used to commit an infraction can be unbonded and withdrawn. Thus, the withdrawable epoch of a given unbond is chosen with this procedure in mind.

When a misbehavior is detected, the validator is immediately *frozen*: no unbonds from this validator are allowed. The validator is also *jailed* by removing it from the validator set indefinitely, starting at the next epoch following the discovery. We do not change the validator set in the current epoch, and this is the only instance wherein the protocol changes the validator set without waiting for the pipeline offset. Ultimately, a validator is *unfrozen* automatically after its last known slash has been processed, but a transaction is required to *unjail* a validator and reinstate it into the validator set. 

We walk through the overall procedure in some more detail here. When a misbehavior is detected:
1. Compute the infraction epoch from its height. If the infraction epoch is earlier than `unbonding_len` epochs before the current epoch, then do not accept it.
2. Enqueue the slash to be processed in the epoch `infraction_epoch + unbonding_len + window_width + 1`. The `unbonding_len` is used to prevent stake used to misbehave from being fully unbonded and withdrawn. The `window_width` is needed to ensure that all slashes that would contribute to the cubic slash rate can be considered, and the additional `1` is needed for processing at the very beginning of an epoch.
3. Jail (and freeze) the misbehaving validator and remove it from the validator set, effective at the beginning of the next epoch. Bonds can still be made to validators while frozen. Unbonds can be made from validators while they are jailed, but not while frozen. At the pipeline offset only, if the misbehaving validator was removed from the consensus set, replace it with the appropriate below-capacity validator.

Now, at the beginning of each new epoch, if there are slashes enqueued for this epoch, then:
1. Compute the cubic slash rate for slashes in this epoch.
For each validator that has enqueued slashes,
2. Compute the rate for each of the validator slashes. The total rate by which this validator is slashed is the sum of these rates, capped at `1.0`. Slash the validator voting powers with the total rate, enforcing that the slashed voting power be 0 if it would otherwise become negative.
3. Send the slashed token amount from the proof-of-stake address to the slash pool address. These can ultimately be used by governance to refund validators from wrongful slashes (among other things?).

Once a jailed validator is no longer frozen and all of its slashes have been processed, it can submit a transaction to unjail themselves. When the transaction is accepted and applied, the validator is inserted back into the validator set (depending on its new voting power) starting at the pipeline offset relative to the epoch of transaction submission.

