# Inflation system

## Token flow

The protocol controls Namada token NAM (the native staking token) sourced from two locations:

- Fees paid for transactions per the description in [fee system](../ledger/fee-system.md), 50 % goes to block production and 50 % goes to treasury.  
- Inflation (described below), as in tokens directly printed by the protocol (which we can do arbitrarily), where these tokens then flow to many different sinks:

1. Proof-of-stake rewards, which are paid into the reward distribution mechanism in order to distribute them to validators and delegators.
2. Shielded pool rewards, which are locked in a way such that they can be eventually paid to users who kept tokens in the shielded pool.
3. A governance pool - aka treasury.
    - These tokens are slowly burned at a fixed fraction per epoch.
4. A set of configurable custom sinks, which can be addresses on Namada, addresses on Ethereum (over the Ethereum bridge), or addresses on other chains connected over IBC.
    - These can be paid fixed amounts per epoch.
    - Initial recipients will be configured at genesis, and recipients can be added, removed, or altered by Namada governance.

## Token Inflation
In general, inflation refers to the process of a currency losing its purchasing power over time. While this is a classical economic phenomenon, the way cryptocurrencies are produced permits great control over money supply, and doing so cleverly can have positive effects such as increasing incentives. The Namada inflation model depends on several factors, such as ratio between locked and liquid tokens (described below), the multi-asset shielded pool, and funds for treasury. 

When validators are selected they need to be backed by funds. These funds are locked for the duration of an epoch and 21 days after the epoch has ended. Locked tokens help secure the system while liquidity supports its activity and liveness. We need to choose the ratio between locked and liquid tokens carefully. Liquid tokens make sure the price of the token is not increasing out of scarcity and users have access to tokens to pay transaction fees, while locked tokens are the guarantee that attacking the system is expensive for an adversary. 

Here are some numbers from other projects

| Blockchain platform | Approximate locking %       |
|--------------------------------------------------|------|
| Cosmos                                           | 66.7 |
| Polkadot                                         | 50   |
| Ethereum                                         | 47   |
| Solana                                           | 77   |


Our desired percentage for Namada is 33%-66%: Locked for validating and the rest %33-%66 is liquid. When the price of the token is low we can aim for a higher % of locked tokens and reduce this as the price and demand for liquid tokens increases. For example, we can set a range, in the beginning have 50 % and later aim for 1/3. I don't think we should go lower than that. The staking reward should be ideally set. 


<!--## Inflation rates for popular platforms
_insert table here_
Solana has the following model where the inflation that is produced for rewards is independent of the staking ratio:
1. Define a starting inflation rate for year 1.
2. The inflation rate decreases thereon at a fixed pace until it reaches a desired rate.
3. Once this desired rate is attained, the inflation rate remains constant.

In Polkadot and Cosmos the total inflation rate that is paid as rewards to validators depends on the staking ratio. This is to incentivize validators and delegators to invest in the staking pool. We will follow the same idea and have inflation vary depending on our target staking ratio. Here is how we achieve that. -->

The privacy that MASP is providing depends on the asset in the shielded pool. A transaction can only be private if it can hide among other transactions, hence more funds and activity in the shielded pool increase privacy for transactions. 

The Treasury is a pool of native tokens that can be appropriated for funding public-good products for Namada. The decision on spending these funds will be assigned to governance. 

### Related work
Ethereum 2.0, Solana, and Near protocols inflation rate are independent of how much tokens are staked. Near protocol and Ethereum 2.0 have fixed inflation rates, while Solana start with a high inflation rate that decreases over time, as less transaction fees are burned. 

In Polkadot and Cosmos the total inflation rate that is paid as rewards to validators depends on the staking ratio. This is to incentivize validators and delegators to invest in the staking pool. We will follow the same idea and have inflation vary depending on our target staking ratio. Here is how we achieve that. 

For funds going to treasury Near protocol where 5 % goes to treasury and Polkadot sends the difference between inflation for PoS and the total constant inflation to treasury.

###  Model

Let us assume $T$ is the total token supply and $I$ is the total inflation of Namada. 

$$I=\frac{T_\textrm{end of year}-T_\textrm{beginning of year}}{T_\textrm{beginning of year}}$$

The total inflation consists of several components as follows. 

$I=I_{PoS}+I_L+I_T-D_T$

where $I_T$ is our inflation that goes to treasury, $I_{PoS}$ is inflation that is paid as PoS rewards, and $I_L$ is the inflation for locking that is paid to accounts in shielded pool. We can extend the $I_L$ be extended to be for many other types of $I_L1,...,I_Ln$. For simplicity we only assume to have one $I_L$. $D_T$ is the constant deflation of the treasury. This is applied to incentivize governance voters to spend treasury funds. 

These components are each varying depending on independent factors as follows. The $I_{PoS}$ depends on the staking ratio $R_t$. The locking inflation $I_L$ depends on the locking ratio $L_t$. Ideally we want the total token supply to consist of tokens locked for staking and shielded pool and the rest are liquid tokens $Y$. 

$T=T*R_t+T*L_t+Y$

where $R_t$ is the target staking ratio and $L_t$ is the target locking of assets in the shielded pool.
  
We assume further assume $I_{target}$ is our target total inflation that we want to achieve on the long term. 

We define $I_{PoS}$ as follows. 

$$ I_{PoS} =
  \begin{cases}
   (max(I_{PoS})/2) (1 + \frac{R}{R_{target} })      & \quad R< R_{target}\\
   \\
   max(I_{PoS})  * 2 ^{-\frac{R-R_{target}}{1-R_{target}}} & \quad R>=R_{target}
  \end{cases}
$$

As an example, we plot the inflation of locked assets $I_L$ with respect to the locking ratio $R_t$ where we assume $R_{target} = 0.5$ and $max(I_{PoS}) = 12%$. 
<p align="center">
<img src="https://hackmd.io/_uploads/Hk49PAvZc.png" height="300" />
</p>

We define $I_{L}$ as follows. 


$$ I_{L} =
  \begin{cases}
   max(I_L)(\frac{L_{target}-L_t}{L_{target}})      & \quad L< L_{target}\\
   \\
   0 & \quad L>=L_{target}
  \end{cases}
$$

As an example, we plot the inflation of locked assets $I_L$ with respect to the locking ratio $L_t$ with the assumed $L_{target} = 0.5$.
<p align="center">
<img src="https://hackmd.io/_uploads/SJDN_0wbq.png" height="300" />
</p>
The ratio between staking and locking in the shielded pool is a trade off between security and privacy. A higher staking ratio means more security, a higher locking ratio means more privacy. It would be easier to consider these separately, for example, setting the target staking ratio to 50 % and the target locking ratio to 25 %. 

The funds going to the treasury is a constant %, for example 1 %. Same goes for $D_T$. 

We need to define $max(I_{PoS})$, $max(I_L)$, and $I_T$ to bound total inflation. 

$max(I_{PoS})+max(I_L)+I_T=< max(I)$ 

The sum of $I_L$ and other $I_L1,...,I_Ln$ will also be limited. If their sum would exceed the limit, then we need to scale them down to stay within the limit. 

These bounds on $I_{PoS}$ and $I_L$ give us a min and max bound on the total inflation, where the total inflation depends on $L_t$ and $R_t$ independently. 


