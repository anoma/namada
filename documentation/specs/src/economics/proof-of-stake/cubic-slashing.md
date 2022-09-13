# Cubic slashing

Namada implements cubic slashing, meaning that the amount of a slash is proportional to the cube of the voting power committing infractions within a particular interval. This is designed to make it riskier to operate larger or similarly configured validators, and thus encourage network resilience.

When a slash is detected:
1. Using the height of the infraction, calculate the epoch just after which stake bonded at the time of infraction could have been fully unbonded. Enqueue the slash for processing at the end of that epoch (so that it will be processed before unbonding could have completed, and hopefully long enough for any other misbehaviour from around the same height as this misbehaviour to also be detected).
2. Jail the validator in question (this will apply at the end of the current epoch). While the validator is jailed, it should be removed from the validator set (also being effective from the end of the current epoch). Note that this is the only instance in our proof-of-stake model when the validator set is updated without waiting for the pipeline offset.
3. Prevent the delegators to this validator from altering their delegations in any way until the enqueued slash is processed.

At the end of each epoch, in order to process any slashes scheduled for processing at the end of that epoch:
1. Iterate over all slashes for infractions committed within a range of (-1, +1) epochs worth of block heights (this may need to be a protocol parameter) of the infraction in question.
2. Calculate the slash rate according to the following function:


```haskell =
calculateSlashRate :: [Slash] -> Float

calculateSlashRate slashes = 
    let votingPowerFraction = sum [ votingPowerFraction (validator slash) | slash <- slashes]
	in max 0.01 (min 1 (votingPowerFraction**2)*9)
  -- minimum slash rate is 1%
  -- then exponential between 0 & 1/3 voting power
  -- we can make this a more complex function later
```

> Note: The voting power of a slash is the voting power of the validator **when they violated the protocol**, not the voting power now or at the time of any of the other infractions. This does mean that these voting powers may not sum to 1, but this method should still be close to the incentives we want, and can't really be changed without making the system easier to game.

3. Set the slash rate on the now "finalised" slash in storage.
4. Update the validators' stored voting power appropriately.
5. Delegations to the validator can now be redelegated / start unbonding / etc.

Validator can later submit a transaction to unjail themselves after a configurable period. When the transaction is applied and accepted, the validator updates its state to "candidate" and is added back to the validator set starting at the epoch at pipeline offset (into `consensus`, `below_capacity` or `below_threshold` set, depending on its voting power).

At present, funds slashed are sent to the governance treasury. In the future we could potentially reward the slash discoverer with part of the slash, for which some sort of commit-reveal mechanism will be required to prevent front-running.
