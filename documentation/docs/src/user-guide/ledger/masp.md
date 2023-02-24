# Shielded transfers

In Namada, shielded transfers are enabled by the Multi-Asset Shielded Pool (MASP). The MASP is a zero-knowledge circuit (zk-SNARK) that extends the Zcash Sapling circuit to add support for sending arbitrary assets. All assets in the pool share the same anonymity set, this means that the more transactions are issued to MASP, the stronger are the privacity guarantees.

## Using MASP

If you are familiar with Zcash, the set of interactions you can execute with the MASP are similar:

- [**Shielding transfers:** transparent to shielded addresses](#shielding-transfers)
- [**Shielded transfers:** shielded to shielded addresses](#shielded-transfers)
- [**Deshielding transfers:** shielded to transparent addresses](#deshielding-tranfers)

```admonish info "Lexicon"
- A **Spending Key** is a type of private key that allows any user in possession of it to spend the balance of the associated address. For shielded addresses, possessing the Spending Key also allows the user to view the address’ balance and transaction data.
- A **Viewing Key** allows any user in possession of it to view and disclose transaction details. It is derived from the Spending Key and hold the same alias. 
```

### Shielding transfers

To try out shielded transfers, you first need to be in possession of a
transparent account with some token balance.

#### Create your transparent account

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

#### Get tokens from the Testnet Faucet

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

#### Generate your Spending Key

You can randomly generate a new Spending Key with:

```shell
namadaw masp gen-key --alias [your-spending-key-alias]
```

```admonish info
This command will also generate a corresponding Viewing Key sharing
the same alias.
```

#### Create a new payment address

To create a payment address from your Spending key, use:

```shell
namadaw masp gen-addr \
    --key [your-spending-key-alias] \
    --alias [your-payment-address-alias]
```

```admonish note
This command will generate a different payment address each time you run it. Payment addresses can be reused or discarded as you like, and any relationship between addresses cannot be deciphered by any user without the spending key.
```

#### Send your shielding transfer

Once you have a payment address, transfer a balance from your
transparent account to your shielded account with something like:

```shell
namadac transfer \
    --source [your-established-account-alias] \
    --target [your-payment-address-alias] \
    --token btc \
    --amount 100
```

#### View your balance

Once this transfer has been broadcasted, validated, and executed on the blockchain, you can view your Spending Key's
balance:

```shell
namadac balance --owner [your-spending-key-alias]
```

### Shielded transfers

Now that you have a shielded balance, it can be transferred to a
another shielded address:

```shell
namadac transfer \
    --source [your-spending-key-alias] \
    --target [some-payment-address] \
    --token btc \
    --amount 50 \
    --signer [your-implicit-account-alias]
```

### Deshielding tranfers

You can also transfer back your balance to a transparent account:

```shell
namadac transfer \
    --source [your-spending-key-alias] \
    --target [some-transparent-address-alias] \
    --token btc \
    --amount 50 \
    --signer [your-implicit-account-alias]
```

### Shielded Address/Key Generation

#### Spending Key Generation

When the client generates a spending key, it automatically derives a viewing key for it. The spending key acts as the "source" of any transfer from any shielded address derived from it. The viewing key is able to determine the total unspent notes that the spending key is authorized to spend. 


#### Payment Address Generation

Payment addresses can be derived from both spending keys as well as viewing keys. The payment address acts as a destination address in which any tokens received by this address is spendable by the corresponding spending key. Only the payment address's spending key and viewing key are able to spend and view the payment address's balance, respectively. Below are examples of how payment addresses can be
generated:

```
namadaw masp gen-addr --alias my-pa1 --key my-sk
namadaw masp gen-addr --alias my-pa2 --key my-vk
```

#### Manual Key/Address Addition

It is also possible to manually add spending keys, viewining keys, and payment addresses in their raw form. This is demonstrated by the commands below.

```
namadaw masp add --alias my-sk --value xsktest1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu69au6gn3su5ewneas486hdccyayx32hxvt64p3d0hfuprpgcgv2q9gdx3jvxrn02f0nnp3jtdd6f5vwscfuyum083cvfv4jun75ak5sdgrm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcvedhsv
namadaw masp add --alias my-vk --value xfvktest1qqqqqqqqqqqqqqpagte43rsza46v55dlz8cffahv0fnr6eqacvnrkyuf9lmndgal7erg38awgq60r259csg3lxeeyy5355f5nj3ywpeqgd2guqd73uxz46645d0ayt9em88wflka0vsrq29u47x55psw93ly80lvftzdr5ccrzuuedtf6fala4r4nnazm9y9hq5yu6pq24arjskmpv4mdgfn3spffxxv8ugvym36kmnj45jcvvmm227vqjm5fq8882yhjsq97p7xrwqt7n63v
namadaw masp add --alias my-pa --value patest10qy6fuwef9leccl6dfm7wwlyd336x4y32hz62cnrvlrl6r5yk0jnw80kus33x34a5peg2xc4csn
```

### Making Shielded Transactions

#### Shielding Transactions

In order to shield tokens from a transparent address, the user must first generate a shielded payment address in which the user holds the spending key for. It is then possible to make a transfer from the transparent address to the newly created shielded payment address. Once this process is completed, the new tokens are now considered "shielded". The
gas fee is charged to the source address that makes the transfer to the shielded payment address. Shielding tokens can be done as following:

```
namadac transfer --source Bertha --amount 50 --token BTC --target my-pa
```

#### Unshielding Transactions

"Unshielding" is the process of transferring token balances from the shielded set to the transparent one. When the user makes a transfer from a shielded account (using the corresponding spending key) to a transparent account, the newly transferred funds are considered "unshielded". The gas fee is charged to the signer's address (which should default to the target
address). Once the transaction is complete, the spending key will no
longer be able to spend the transferred amount. Below is an example of
how an unshielding transaction is performed:

```
namadac transfer --target Bertha --amount 45 --token BTC --source my-sk
```

#### Shielded Transactions

Shielded transfers are made from one shielded account to another. From a user perspective, this is almost equivalent to a transparent-transparent token transfer, except the gas fee is paid by the signer of the transaction. The command for performing a shielded transfer is given below:

```
namadac transfer --source my-sk --amount 5 --token BTC --target your-pa
```

### Viewing Shielded Balances

The viewing key that is derived from a spending key allows any user holding that key to view the balances attached to corresponding spending key. It is possible to use this viewing key to either decipher the full balance of the corresponding viewing key or query a subset of them.

```
namadac balance
namadac balance --owner my-key
namadac balance --owner my-key --token BTC
namadac balance --token BTC
```

### Listing Shielded Keys/Addresses

The wallet is able to list all the spending keys, viewing keys,
and payment addresses that it stores. Below are examples of how the
wallet's storage can be queried:

```
namadaw masp list-keys
namadaw masp list-keys --unsafe-show-secret
namadaw masp list-keys --unsafe-show-secret --decrypt
namadaw masp list-addrs
```

### Finding Shielded Keys/Addresses

The wallet is able to find any spending key, viewing key or
payment address when given its alias. Below are examples of how the
wallet's storage can be queried:

```
namadaw masp find --alias my-alias
namadaw masp find --alias my-alias --unsafe-show-secret
```
