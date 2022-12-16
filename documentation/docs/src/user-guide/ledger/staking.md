# Delegating (Staking)

You can delegate to any number of validators at any time. When you delegate tokens, the delegation won't count towards the validator's stake (which in turn determines its voting power) until the beginning of epoch `n + 2` in the current epoch `n` (the literal `2` is set by PoS parameter `pipeline_len`). The delegated amount of tokens will be deducted from your account immediately, and will be credited to the PoS system's account.

To submit a delegation that bonds tokens from the source address to a validator with alias `validator-1`:

```shell
namada client bond \
  --source my-new-acc \
  --validator validator-1 \
  --amount 12.34
```

You can query your delegations:

```shell
namada client bonds --owner my-new-acc
```

The result of this query will inform the epoch from which your delegations will be active.

Because the PoS system is just an account, you can query its balance, which is the sum of all staked tokens:

```shell
namada client balance --owner PoS
```

## Slashes

Should a validator exhibit punishable behavior, the delegations towards this validator are also liable for slashing. Only the delegations that were active in the epoch in which the fault occurred will be slashed by the slash rate of the fault type. If any of your delegations have been slashed, this will be displayed in the `bonds` query. You can also find all the slashes applied with:

```shell
namada client slashes
```

## Unbonding

While your tokens are being delegated, they are locked-in the PoS system and hence are not liquid until you withdraw them. To do that, you first need to send a transaction to “unbond” your tokens. You can unbond any amount, up to the sum of all your delegations to the given validator, even before they become active.

To submit an unbonding of a delegation of tokens from a source address to the validator:

```shell
namada client unbond \
  --source my-new-acc \
  --validator validator-1 \
  --amount 1.2
```

When you unbond tokens, you won't be able to withdraw them immediately. Instead, tokens unbonded in the epoch `n` will be withdrawable starting from the epoch `n + 6` (the literal `6` is set by PoS parameter `unbonding_len`). After you unbond some tokens, you will be able to see when you can withdraw them via `bonds` query:

```shell
namada client bonds --owner my-new-acc
```

When the chain reaches the epoch in which you can withdraw the tokens (or anytime after), you can submit a withdrawal of unbonded delegation of tokens back to your account:

```shell
namada client withdraw \
  --source my-new-acc \
  --validator validator-1
```

Upon success, the withdrawn tokens will be credited back your account and debited from the PoS system.

## Validators' Voting Power

To see all validators and their voting power, which is exactly equal to the amount of staked NAM tokens from their self-bonds and delegations, you can query:

```shell
namada client bonded-stake
```

With this command, you can specify `--epoch` to find the voting powers at some future epoch. Note that only the voting powers for the current and the next epoch are final.