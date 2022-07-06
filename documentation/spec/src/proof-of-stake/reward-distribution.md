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
- Similarly, multiply the validator's voting power by the same factor $( 1 + r_V(e)/s_V(e))$, which should now equal the sum of their revised-amount delegations.

In this system, rewards are automatically rebonded to delegations, increasing the delegation amounts and validator voting powers accordingly.

However, we wish to implement this without actually needing to iterate over all delegations each block, since this is too computationally expensive. We can exploit this constant multiplicative factor $(1  + r_V(e) / s_V(e))$ which does not vary per delegation to perform this calculation lazily, storing only a constant amount of data per validator per epoch, and calculate revised amounts for each individual delegation only when a delegation changes. 

We will demonstrate this for a delegation $D$ to a validator $V$.Let $s_D(e)$ denote the stake of $D$ at epoch $e$.




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

## Commission

Commission is implemented as a change to $R_{e, i}$. Validators can charge any commission they wish (in $[0, 1]$). The commission is paid directly to the account indicated by the validator.

## Slashes

Slashes should lead to punishment for delegators who were contributing voting power to the validator at the height of the infraction, _as if_ the delegations were iterated over and slashed individually.

This can be implemented as a negative inflation rate for a particular block.

Instant redelegation is not supported. Redelegations must wait the unbonding period.

## State management

Each $entry_{v,i}$ can be reference-counted by the number of delegations created during that epoch which might need to reference it. As soon as the number of delegations drops to zero, the entry can be deleted.
