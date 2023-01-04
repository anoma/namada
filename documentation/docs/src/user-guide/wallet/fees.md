# Fees on Namada

In order to settle the market for Namada blockspace demand, fees are coupled with transactions. In order for any namada transaction to be considered valid, the correct corresponding fee must be paid. All fees are paid in the native token NAM. The exact fee is set by governance.

## How fees are paid

Fees on Namada are paid by the implicit address corresponding to the `--signer` of the transaction. This means that in the transaction 
```shell
namada client transfer \
  --source my-new-acc \
  --target validator-1 \
  --token NAM \
  --amount 10 \
  --signer my-key
```

the account associated with `my-key` will be required to pay the fee. This means that even though `my-new-account` may have a positive NAM balance, `my-key` will need to have the associated NAM in order to pay the transaction fee.

For testnet purposes, we recommend [using the faucet](../../testnets/pow.md) to source NAM for transaction fees.
