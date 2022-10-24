# Reward distribution

Namada uses the automatically-compounding variant of [F1 fee distribution](https://drops.dagstuhl.de/opus/volltexte/2020/11974/pdf/OASIcs-Tokenomics-2019-10.pdf).

Rewards are given to validators for voting on finalizing blocks: the fund for these rewards can come from **minting** (creating new tokens). The amount that is minted depends on how much is staked and our desired yearly inflation. When the total of the tokens staked is very low, the return rate per validator needs to increase, but as the total amount of stake rises, validators will receive less rewards. Once we have acquired the desired stake percentage, the amount minted will just be the desired yearly inflation. 

The validator and the delegator must have agreed on a commission rate between themselves. Delegators pay out rewards to validators based on a mutually-determined commission rate that both parties must have agreed upon beforehand. The minted rewards are auto-bonded and only transferred when the funds are unbonded. Once we have calculated the total that needs to be minted at the end of the epoch, we split the minted tokens according to the stake the relevant validators and delegators contributed and distribute them to validators and their delegators. This is similar to what Cosmos does. 

## Basic algorithm

Consider a system with

- a canonical singular staking unit of account.
- a set of validators $V_i$.
- a set of delegations $D_{i, j}$, each to a particular validator and in a particular (initial) amount.
- epoched proof-of-stake, where changes are applied as follows:
	- bonding after the pipeline length
	- unbonding after the unbonding length
	- rewards are paid out at the end of each epoch, to wit, in each epoch $e$, $R_{e,i}$ is paid out to validator $V_i$
	- slashing is applied as described in [slashing](cubic-slashing.md).

We wish to approximate as exactly as possible the following ideal delegator reward distribution system:

- At each epoch, for a validator $V$, iterate over all of the delegations to that validator. Update each delegation $D$, as follows.
$$
D \rightarrow D( 1 + r_V(e)/s_V(e))
$$
where $r_V(e)$ and $s_V(e)$ respectively denote the reward and stake of validator $V$ at epoch $e$.
- Similarly, multiply the validator's voting power by the same factor $(1 + r_V(e)/s_V(e))$, which should now equal the sum of their revised-amount delegations.

In this system, rewards are automatically rebonded to delegations, increasing the delegation amounts and validator voting powers accordingly.

However, we wish to implement this without actually needing to iterate over all delegations each block, since this is too computationally expensive. We can exploit this constant multiplicative factor $(1  + r_V(e) / s_V(e))$ which does not vary per delegation to perform this calculation lazily, storing only a constant amount of data per validator per epoch, and calculate revised amounts for each individual delegation only when a delegation changes. 

We will demonstrate this for a delegation $D$ to a validator $V$. Let $s_D(e)$ denote the stake of $D$ at epoch $e$.

For two epochs $m$ and $n$ with $m<n$, define the function $p$ as

$$
p(n, m) = \prod_{e = m}^{n} \Big(1 + \frac{r_V(e)} {s_V(e)}\Big).
$$

Denote $p(n, 0)$ as $p_n$. The function $p$ has a useful property. 

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


Clearly, the quantity $p_n/p_m$ does not depend on the delegation $D$. Thus, for a given validator, we need only store this product $p_e$ at each epoch $e$, with which updated amounts for all delegations can be calculated.

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
		entries = lookup validatorProducts validator
	    lastProduct = lookup entries (Epoch (currentEpoch - 1))
	in insert currentEpoch (product*(1+rsratio)) entries
	
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

Let $c_V(e)$ be the commission rate for a delegation $D$ to a validator $V$ at epoch $e$. The expression for the product $p_n$ we have introduced earlier can be modified as

$$ p_n = \prod_{e = 0}^{n} \Big(1 + (1-c_V(e))\frac{r_V(e)} {s_V(e)} \Big). $$

in order to calculate the new rewards given out to delegators during withdrawal. Thus the commission charged per epoch is retained by the validator and remains untouched upon withdrawal by the delegator. 

The commission rate $c_V(e)$ is the same for all delegations to a validator $V$ in a given epoch $e$, including for self-bonds. The validator can change the commission rate at any point, subject to a maximum rate of change per epoch, which is a constant specified when the validator is created and immutable once validator creation has been accepted.

While rewards are given out at the end of every epoch, voting power is only updated after the pipeline offset. According to the [proof-of-stake system](bonding-mechanism.md#epoched-data),  at the current epoch `e`, the validator sets an only be updated for epoch `e + pipeline_offset`, and it should remain unchanged from epoch `e` to `e + pipeline_offset - 1`. Updating voting power in the current epoch would violate this rule.




