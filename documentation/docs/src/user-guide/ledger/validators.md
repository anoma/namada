# 📒 PoS Validators

## Generate a validator account

To register a new validator account, run:

```shell
namada client init-validator \
  --alias my-validator \
  --source my-new-acc \
  --commission-rate <commission-rate>
  --max-commission-rate-change <max-commission-rate-change>
```

The commission rate charged by the validator for delegation rewards and the maximum change per epoch in the commission rate charged by the validator for delegation rewards. Both are expressed as a decimal between 0 and 1. *Staking rewards are not yet implemented*.

This command will generate the keys required for running a validator:

- Consensus key, which is used in [signing blocks in Tendermint](https://docs.tendermint.com/master/nodes/validators.html#validator-keys).
- Validator account key for signing transactions on the validator account, such as token self-bonding, unbonding and withdrawal, validator keys, validity predicate, state and metadata updates.

Then, it submits a transaction to the ledger that generates the new validator account with established address, which can be used to receive new delegations.

The keys and the alias of the address will be saved in your wallet. Your local ledger node will also be setup to run this validator, you just have to shut it down with e.g. `Ctrl + C`, then start it again with the same command:

```shell
namada ledger
```

The ledger will then use the validator consensus key to sign blocks, should your validator account acquire enough voting power to be included in the active validator set. The size of the active validator set is limited to `128` (the limit is set by the PoS `max_validator_slots` parameter).

Note that the balance of NAM tokens that is in your validator account does not count towards your validator's stake and voting power:

```shell
namada client balance --owner my-validator --token NAM
```

That is, the balance of your account's address is a regular liquid balance that you can transfer using your validator account key, depending on the rules of the validator account's validity predicate. The default validity predicate allows you to transfer it with a signed transaction and/or stake it in the PoS system.

## Self-bonding

You can submit a self-bonding transaction of tokens from a validator account to the PoS system with:

```shell
namada client bond \
  --validator my-validator \
  --amount 3.3
```

## Determine your voting power

A validator's voting power is determined by the sum of all their active self-bonds and delegations of tokens, with slashes applied, if any.

The same rules apply to delegations. When you self-bond tokens, the bonded amount won't count towards your validator's stake (which in turn determines your power) until the beginning of epoch `n + 2` in the current epoch `n`. The bonded amount of tokens will be deducted from the validator's account immediately and will be credited to the PoS system's account.

While your tokens are being self-bonded, they are locked-in the PoS system and hence are not liquid until you withdraw them. To do that, you first need to send a transaction to “unbond” your tokens. You can unbond any amount, up to the sum of all your self-bonds, even before they become active.

## Self-unbonding

To submit an unbonding of self-bonded tokens from your validator:

```shell
namada client unbond \
  --validator my-validator \
  --amount 0.3
```

Again, when you unbond tokens, you won't be able to withdraw them immediately. Instead, tokens unbonded in the epoch `n` will be withdrawable starting from the epoch `n + 6`. After you unbond some tokens, you will be able to see when you can withdraw them via `bonds` query:

```shell
namada client bonds --validator my-validator
```

When the chain reaches the epoch in which you can withdraw the tokens (or anytime after), you can submit a withdrawal of unbonded tokens back to your validator account:

```shell
namada client withdraw --validator my-validator
```
