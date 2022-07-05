# MASP
The  Multi-Asset Shielded Pool (MASP) is a zero-knowledge circuit - aka zk-SNARK - that enables shielded (private) transfers where all assets share one anonymity set private. The MASP is an extension of the Zcash Sapling circuit that adds support for sending arbitrary assets.

## Using MASP

If you are familiar to Zcash, the set of interactions you can execute with the MASP are similar:
- [**Shielding transfers:** transparent to shielded addresses](#shielding-transfers)
- [**Shielded transfers:** shielded to shielded addresses](#shielded-transfers)
- [**Deshielding transfers:** shielded to transparent addresses](#deshielding-tranfers)

```admonish info "Lexicon"
- A **Spending Key** is a type of private key that allows any user in possession of it to spend the balance of the associated address. For shielded addresses, possessing the Spending Key also allows the user to view the address’ balance and transaction data.
- A **Viewing Key** allows any user in possession of it to view and disclose transaction details. It is derived from the Spending Key and hold the same alias. 
```

### Shielding transfers

To try out shielded transfers, first you need to be in possession of a
transparent account with some token balance.

#### Create your transparent account

Generate an implicit account:
```shell
anomaw address gen --alias [your-implicit-account-alias]
```
Then, create an established account on chain using the implicit account you've just generated:
```shell
anomac init-account \
    --source [your-implicit-account-alias] \
    --public-key [your-implicit-account-alias] \
    --alias [your-established-account-alias]
```
#### Get tokens from the Testnet Faucet

```admonish info "Testnet Faucet Tokens"
The testnet tokens which the faucet can provide you are named `XAN`,
`BTC`, `ETH`, `DOT`, `Schnitzel`, `Apfel`, and `Kartoffel`. The faucet
will transfer these in increments of 1000 maximum at a time.
```

```shell
anomac transfer \
    --token btc \
    --amount 1000 \
    --source faucet \
    --target [your-established-account-alias] \
    --signer [your-established-account-alias]
```

Now that you have a transparent account with some tokens, you can generate a Spending Key to hold your shielded balances.

#### Generate your Spending Key

You can randomly generate a new Spending Key with:
```shell 
anomaw masp gen-key --alias [your-spending-key-alias]
```

```admonish info
This command will also generate a corresponding Viewing Key sharing
the same alias.
```

#### Create a new payment address

To create a payment address from your Spending key, use:

```shell
anomaw masp gen-addr \
    --key [your-spending-key-alias] \
    --alias [your-payment-address-alias]
```

```admonish note
This will generate a different payment address each time you run it.
Payment addresses can be reused or discarded as you like, and cannot be
correlated with one another.
```

#### Send your shielding transfer

Once you have a payment address, transfer a balance from your
transparent account to your shielded account with something like:

```shell
anomac transfer \
    --source [your-established-account-alias] \
    --target [your-payment-address-alias] \
    --token btc \
    --amount 100
```

#### View your balance

Once this transfer goes through, you can view your Spending Key's
balance:

```shell
anomac balance --owner [your-spending-key-alias]
```

### Shielded transfers

Now that you have a shielded balance, it can be transferred to a
another shielded address:

```shell
anomac transfer \
    --source [your-spending-key-alias] \
    --target [some-payment-address] \
    --token btc \
    --amount 50 \
    --signer [your-established-account-alias]
```

### Deshielding tranfers

You can also transfer back your balance to some transparent account:

```shell
anomac transfer \
    --source [your-spending-key-alias] \
    --target [some-transparent-address] \
    --token btc \
    --amount 50 \
    --signer [your-established-account-alias]
```