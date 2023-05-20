# Established accounts

This assumes that you already have a key or an implicit account that can sign transactions. 

## Create your transparent account

Generate an implicit account:

```shell
namadaw address gen --alias [your-implicit-account-alias]
```

Then, create an established account on-chain using the implicit account you've just generated:

```shell
namadac init-account \
    --source [your-implicit-account-alias] \
    --public-key [your-implicit-account-alias] \
    --alias [your-established-account-alias]
```



## Get tokens from the testnet faucet (optional)

```admonish info "Testnet Faucet Tokens"
The testnet tokens which the faucet can provide you have the aliases `NAM`,
`BTC`, `ETH`, `DOT`, `Schnitzel`, `Apfel`, and `Kartoffel`. The faucet
will transfer these in increments of 1000 maximum at a time.
```

```shell
namadac transfer \
    --token btc \
    --amount 1000 \
    --source faucet \
    --target [your-established-account-alias] \
    --signer [your-implicit-account-alias]
```

Now that you have a transparent account with some tokens, you can generate a Spending Key to hold your shielded balances.