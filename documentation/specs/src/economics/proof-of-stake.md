# Proof-of-stake (PoS)

This section of the specification describes the proof-of-stake mechanism of Namada, which is largely modeled after [Cosmos bonded proof-of-stake](https://github.com/cosmos/cosmos-sdk/blob/master/x/staking/spec/README.md), but makes significant changes to bond storage representation, validator set change handling, reward distribution, and slashing, with the general aims of increased precision in reasoning about security, validator decentralisation, and avoiding unnecessary proof-of-stake-related transactions.

This section is split into three subcomponents: the [bonding mechanism](./proof-of-stake/bonding-mechanism.md), [reward distribution](./proof-of-stake/reward-distribution.md), and [cubic slashing](./proof-of-stake/cubic-slashing.md).

## Introduction

Blockchain systems rely on economic security (directly or indirectly) to 
prevent 
abuse and 
for actors 
to behave according to protocol. The aim is that economic incentives promote 
correct long-term operation of the system and economic punishments 
discourage diverging from correct protocol execution either by mistake or 
with the intent of carrying out attacks. Many PoS blockcains rely on the 1/3 Byzantine rule, where they make the assumption the adversary cannot control more 2/3 of the total stake or 2/3 of the actors. 

## Goals of Rewards and Slashing: Liveness and Security

* **Security: Delegation and Slashing**: we want to make sure validators are 
  backed by enough funds to make misbehaviour very expensive. Security is 
  achieved by punishing (slashing) if they do. *Slashing* locked funds (stake)
  intends to disincentivize diverging from correct execution of protocol, 
  which in this case is voting to finalize valid blocks. 
* **Liveness: Paying Rewards**. For continued operation of Namada we want to incentivize participating in consensus and delegation, which helps security.

### Security 

In blockchain systems we do not rely on altruistic behavior but rather economic
security. We expect the validators to execute the protocol correctly. They get rewarded for doing so and punished otherwise. Each validator has some self-stake and some stake that is delegated to it by other token holders. The validator and delegators share the reward and risk of slashing impact with each other. 

The total stake behind consensus should be taken into account when value is transferred via a transaction. For example, if we have 1 billion tokens, we aim that 300 Million of these tokens is backing validators. This means that users should not transfer more than 200 million of this token within a block. 
