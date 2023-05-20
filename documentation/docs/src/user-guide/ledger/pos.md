# 🔏 Interacting with the Cubic Proof-of-Stake system

The Namada Proof of Stake system uses the NAM token as the staking token. It features delegation to any number of validators and customizable validator validity predicates.

## PoS Validity Predicate

The PoS system is implemented as an account with the [PoS Validity Predicate](https://github.com/anoma/namada/blob/main/shared/src/ledger/pos/vp.rs) that governs the rules of the system. You can find its address in your wallet:

```shell
namada wallet address find --alias PoS
```

## Epochs

The system relies on the concept of epochs. An epoch is a range of consecutive blocks identified by consecutive natural numbers. Each epoch lasts a minimum duration and includes a minimum number of blocks since the beginning of the last epoch. These are defined by protocol parameters.

To query the current epoch, the following command can be run:

```shell
namadac query-protocol-parameters
```

In order to query the current epoch, the following command can be run:

```shell
```shell
namada client epoch
```