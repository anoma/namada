# Reward distribution

Namada uses the automatically-compounding variant of [F1 fee distribution](https://drops.dagstuhl.de/opus/volltexte/2020/11974/pdf/OASIcs-Tokenomics-2019-10.pdf).

Rewards are given to validators for proposing blocks, for voting on finalizing blocks, and for being in the [consensus validator set](bonding-mechanism.md#validator-sets): the funds for these rewards can come from **minting** (creating new tokens). The amount that is minted depends on how many staking tokens are locked (staked) and some maximum annual inflation rate. The rewards mechanism is implemented as a [PD controller](../inflation-system.md#detailed-inflation-calculation-model) that dynamically adjusts the inflation rate to achieve a target staking token ratio. When the total fraction of tokens staked is very low, the return rate per validator needs to increase, but as the total fraction of stake rises, validators will receive fewer rewards. Once the desired staking fraction is achieved, the amount minted will just be the desired annual inflation.

Each delegation to a validator is initiated at an agreed-upon commission rate charged by the validator. Validators pay out rewards to delegators based on this mutually-determined commission rate. The minted rewards are auto-bonded and only transferred when the funds are unbonded. Once the protocol determines the total amount of tokens to mint at the end of the epoch, the minted tokens are effectively divided among the relevant validators and delegators according to their proportional stake. In practice, the reward products, which are the fractional increases in staked tokens claimed, are stored for the validators and delegators, and the reward tokens are only transferred to the validator’s or delegator’s account upon withdrawal. This is described in the following sections. The general system is similar to what Cosmos does.

## Basic algorithm

Consider a system with

- a canonical singular staking unit of account.
- a set of validators $\{V_i\}$.
- a set of delegations $\{D_{i, j}\}$, where $i$ indicates the associated validator, each with a particular initial amount.
- epoched proof-of-stake, where changes are applied as follows:
  - bonding is processed after the pipeline length
  - unbonding is processed after the pipeline + unbonding length
  - rewards are paid out at the end of each epoch, i.e., in each epoch $e$, a reward $R_{e,i}$ is paid out to validator $V_i$
  - slashing is applied as described in [slashing](cubic-slashing.md).

We wish to approximate as exactly as possible the following ideal delegator reward distribution system:

- At each epoch, for a validator $V$, iterate over all of the delegations to that validator. Update each delegation $D$, as follows.
$$
D \rightarrow D( 1 + r_V(e)/s_V(e))
$$
where $r_V(e)$ and $s_V(e)$ respectively denote the reward and stake of validator $V$ at epoch $e$.
- Similarly, multiply the validator's voting power by the same factor $(1 + r_V(e)/s_V(e))$, which should now equal the sum of their revised-amount delegations.

In this system, rewards are automatically rebonded to delegations, increasing the delegation amounts and validator voting powers accordingly.

However, we wish to implement this without actually needing to iterate over all delegations each block, since this is too computationally expensive. We can exploit this constant multiplicative factor $(1  + r_V(e) / s_V(e))$, which does not vary per delegation, to perform this calculation lazily. In this lazy method, only a constant amount of data per validator per epoch is stored, and revised amounts are calculated for each individual delegation only when a delegation changes.

We will demonstrate this for a delegation $D$ to a validator $V$. Let $s_D(e)$ denote the stake of $D$ at epoch $e$.

For two epochs $m$ and $n$ with $m < n$, define the function $p(n,m)$ as

$$
p(n, m) = \prod_{e = m}^{n} \Big(1 + \frac{r_V(e)} {s_V(e)}\Big).
$$

Denote $p(n, 0)$ as $p_n$. The function $p(n,m)$ has a useful property.

$$
p(n,m) = \frac{p_n}{p_m}\tag{1}
$$

One may calculate the accumulated changes upto epoch $n$ as

$$
s_D(n) = s_D(0) * p_n.
$$

If we know the delegation upto epoch $m$, the delegation at epoch $n$ is obtained by the following formula,
$$
s_D(n) =  s_D(m) * p(n,m).
$$

Using property $(1)$,

$$
s_D(n) =  s_D(m) * \frac{p_n}{p_m}.
$$

Clearly, the quantity $p_n/p_m$ does not depend on the delegation $D$. Thus, for a given validator, we only need to store this product $p_e$ at each epoch $e$, from which the updated amounts for all delegations can be calculated.

The product $p_e$ at the end of each epoch $e$ is updated as follows.

```haskell=

updateProducts 
:: HashMap<Address, HashMap<Epoch, Float>> 
-> HashSet<Address> 
-> Epoch 
-> HashMap<BondId, Token::amount>>

updateProducts validatorProducts activeSet currentEpoch = 
 let stake = PoS.readValidatorTotalDeltas validator currentEpoch
     reward = PoS.reward stake currentEpoch
     rsratio = reward / stake
     entries = lookup validatorProducts validator
     lastProduct = lookup entries (Epoch (currentEpoch - 1))
 in insert currentEpoch (lastProduct*(1+rsratio)) entries
```

<!--
```rust=
	pub update_products (validator_products: HashMap<Address, HashMap <Epoch, Product>>, active_set: HashSet<Address>, current_epoch: Epoch ) ->  HashMap<Epoch, HashMap<BondId, Token::amount>> {
	    for validator in active_set {
		let stake = pos::read_validator_total_deltas(validator, current_epoch);
		let reward = pos::reward(stake, current_epoch);
		let last_product = validator_products.entry(validator).entry(Epoch {current_epoch.0 - 1});
		validator_products.entry(validator)
		    .or_default()
		    .and_modify(|rsratio| rsratio.insert(current_epoch, product(last_product, RewardStakeRatio{ reward, stake})));
	    }
	    bonds
	}
	pub fn product (product: Product, rsratio: RewardStakeRatio) -> Product {
	    product*(1+ rsratio.reward/rsratio.stake)
	}
```
-->

In case a delegator wishes to withdraw delegation(s), then the proportionate rewards are appropriated using the aforementioned scheme, which is implemented by the following function.

```haskell=
withdrawalAmount 
:: HashMap<Address, HashMap <Epoch, Product>> 
-> BondId 
->  [(Epoch, Delegation)] 
-> Token::amount

withdrawalAmount validatorProducts bondId unbonds = 
 sum [stake * endp/startp | (endEpoch, unbond) <- unbonds, 
                            let epochProducts = lookup (validator bondId)
                           validatorProducts, 
                            let startp = lookup (startEpoch unbond) 
                       epochProducts, 
                            let endp = lookup endEpoch epochProducts, 
                            let stake =  delegation unbond]
 
```
<!-- ```rust=
  pub fn withdrawal_amount (validator_products: HashMap<Address, HashMap <Epoch, Product>>,  bond_id: BondId, unbonds: Iterator<(Epoch, Delegation)>) -> Token::amount {
	let mut withdrawn = 0;
	for (end_epoch, unbond) in unbonds {
	    let pstart = validator_products.get_product(unbond.start_epoch, bond_id.validator);
	    let pend = validator_products.get_product(end_epoch, bond_id.validator);
	    let stake = unbond.delegation;
	    withdrawn += stake * pend/pstart;
	}
	withdrawn
    }
```
-->

## Commission

Commission is charged by a validator on the rewards coming from delegations. These are set as percentages by the validator, who may charge any commission they wish between 0-100%.

Let $c_V(e)$ be the commission rate for a delegation $D$ to a validator $V$ at epoch $e$. The expression for the product $p_n$ that was introduced earlier can be modified for a delegator in particular as

$$ p_n = \prod_{e = 0}^{n} \Big(1 + (1-c_V(e))\frac{r_V(e)} {s_V(e)} \Big) $$

in order to calculate the new rewards given out to the delegator during withdrawal. Thus the commission charged per epoch is retained by the validator and remains untouched upon withdrawal by the delegator.

The commission rate $c_V(e)$ is the same for all delegations to a validator $V$ in a given epoch $e$, including for self-bonds. The validator can change the commission rate at any point, subject to a maximum rate of change per epoch, which is a constant specified when the validator is created and immutable once validator creation has been accepted.

While rewards are given out at the end of every epoch, voting power is only updated after the pipeline offset. According to the [proof-of-stake system](bonding-mechanism.md#epoched-data),  at the current epoch `e`, the validator sets can only be updated for epoch `e + pipeline_offset`, and it should remain unchanged from epoch `e` to `e + pipeline_offset - 1`. Updating voting power in the current epoch would violate this rule.


## Distribution of block rewards to validators

A validator can earn a portion of the block rewards in three different ways: 

- Proposing the block
- Providing a signature on the constructed block (voting)
- Being a member of the consensus validator set

The reward mechanism calculates fractions of the total block reward that are given for the above-mentioned three behaviors, such that

$$ R_p + R_s + R_b = 1, $$

where $R_p$ is the proposer reward fraction, $R_s$ is the reward fraction for the set of signers, and $R_b$ is the reward fraction for the whole active validator set.

The reward for proposing a block is dependent on the combined voting power of all validators whose signatures are included in the block. This is to incentivize the block proposer to maximize the inclusion of signatures, as blocks with more signatures are (JUSTIFY THIS POINT HERE).

The block proposer reward is parameterized as

$$ R_p = r_p\Big(f - \frac{2}{3}\Big) + 0.01, $$

where $f$ is the ratio of the combined stake of all block signers to the combined stake of all consensus validators:

$$ f = \frac{s_{sign}}{s_{cons}}. $$

The value of $f$ is bounded from below at 2/3, since a block requires this amount of signing stake to be verified. We currently enforce that the block proposer reward is a minimum of 1%.

The block signer reward for a validator $V_i$ is parameterized as

$$ R_s^i = r_s \frac{s_i}{s_{sign}} = r_s \frac{s_i}{fs_{cons}}, $$

where $s_i$ is the stake of validator $V_i$, $s_{sign}$ is the combined stake of all signers, and $s_{cons}$ is the combined stake of all consensus validators.

Finally, the remaining reward just for being in the consensus validator set is parameterized as

$$ R_b^i = (1 - R_p - R_s) \frac{s_i}{s_{cons}}. $$

Thus, as an example, the total fraction of the block reward for the proposer (assuming they include their own signature in the block) would be:

$$ R_{prop} = r_p\Big(f - \frac{2}{3}\Big) + 0.01 + r_s \frac{s_i}{fs_{cons}} + \Big(1 - r_p\Big(f - \frac{2}{3}\Big) -0.01 - r_s\Big) \frac{s_i}{s_{cons}}. $$

The values of the parameters $r_p$ and $r_s$ are set in the proof-of-stake storage and can only change via governance. The values are chosen relative to each other such that a block proposer is always incentivized to include as much signing stake as possible. These values at genesis are currently:

- $r_s = 0.1$
- $r_p = 0.125$

These rewards must be determined for every single block, but the inflationary token rewards are only minted at the end of an epoch. Thus, the rewards products are only updated at the end of an epoch as well.

In order to maintain a record of the block rewards over the course of an epoch, a reward fraction accumulator is implemented as a `Map<Address, Decimal>` and held in the storage key `#{PoS}/validator_set/consensus/rewards_accumulator`. When finalizing each block, the accumulator value for each consensus validator is incremented with the fraction of that block's reward owed to the validator. At the end of the epoch when the rewards products are updated, the accumulator value is divided by the number of blocks in that epoch, which yields the fraction of the newly minted inflation tokens owed to the validator. The next entry of the rewards products for each validator can then be created. The map is then reset to be empty in preparation for the next epoch and consensus validator set.