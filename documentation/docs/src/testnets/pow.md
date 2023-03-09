# The PoW Solution on Namada

In order to combat the "costlessness of blockspace" problem with a testnet, and hence prevent DOS attacks as a result, when a Namada account does not have the required fees to pay for a transaction, the user must complete a Proof of Work challenge. The difficulty of this challenge is a parameter set by governance, and will dictate the (average) computational expenditure needed in order to complete the challenge.

In order to avoid having to complete endless Proof of Work challenges, we recommend using the faucet to fund the implicit account as one of a user's first transactions:

```shell
namada client transfer \
  --source faucet \
  --target my-key \
  --token NAM \
  --amount 1000 \
  --signer my-key
```
which will allow `my-key` to sign future transactions and pay for any further fees.


# The PoW Faucet

The Faucet on Namada will always require users to complete a PoW challenge, regardless of the balance of the implicit account.
