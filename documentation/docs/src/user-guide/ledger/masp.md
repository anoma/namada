# Shielded transfers

In Namada, shielded transfers are enabled by the Multi-Asset Shielded Pool (MASP). The MASP is a zero-knowledge circuit (zk-SNARK) that extends the Zcash Sapling circuit to add support for sending arbitrary assets. All assets in the pool share the same anonymity set, this means that the more transactions are issued to MASP, the stronger are the privacity guarantees.

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
namadaw address gen --alias [your-implicit-account-alias]
```

Then, create an established account on chain using the implicit account you've just generated:

```shell
namadac init-account \
    --source [your-implicit-account-alias] \
    --public-key [your-implicit-account-alias] \
    --alias [your-established-account-alias]
```

#### Get tokens from the Testnet Faucet

```admonish info "Testnet Faucet Tokens"
The testnet tokens which the faucet can provide you are named `NAM`,
`BTC`, `ETH`, `DOT`, `Schnitzel`, `Apfel`, and `Kartoffel`. The faucet
will transfer these in increments of 1000 maximum at a time.
```

```shell
namadac transfer \
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
This will generate a different payment address each time you run it.
Payment addresses can be reused or discarded as you like, and cannot be
correlated with one another.
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

Once this transfer goes through, you can view your Spending Key's
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
    --signer [your-established-account-alias]
```

### Deshielding tranfers

You can also transfer back your balance to some transparent account:

```shell
namadac transfer \
    --source [your-spending-key-alias] \
    --target [some-transparent-address] \
    --token btc \
    --amount 50 \
    --signer [your-established-account-alias]
```

### Shielded Address/Key Generation

#### Spending Key Generation

The client should be able to generate a spending key and automatically
derive a viewing key for it. The spending key should be usable as the
source of a transfer. The viewing key should be usable to determine the
total unspent notes that the spending key is authorized to spend. It
should not be possible to directly or indirectly use the viewing key to
spend funds. Below is an example of how spending keys should be
generated:

```
namadaw --masp gen-key --alias my-sk
```

#### Payment Address Generation

The client should be able to generate a payment address from a
spending key or viewing key. This payment address should be usable
to send notes to the originating spending key. It should not be
directly or indirectly usable to either spend notes or view shielded
balances. Below are examples of how payment addresses should be
generated:

```
namadaw masp gen-addr --alias my-pa1 --key my-sk
namadaw masp gen-addr --alias my-pa2 --key my-vk
```

#### Manual Key/Address Addition

The client should be able to directly add raw spending keys, viewing
keys, and payment addresses. Below are examples of how these objects
should be added:

```
namadaw masp add --alias my-sk --value xsktest1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu69au6gn3su5ewneas486hdccyayx32hxvt64p3d0hfuprpgcgv2q9gdx3jvxrn02f0nnp3jtdd6f5vwscfuyum083cvfv4jun75ak5sdgrm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcvedhsv
namadaw masp add --alias my-vk --value xfvktest1qqqqqqqqqqqqqqpagte43rsza46v55dlz8cffahv0fnr6eqacvnrkyuf9lmndgal7erg38awgq60r259csg3lxeeyy5355f5nj3ywpeqgd2guqd73uxz46645d0ayt9em88wflka0vsrq29u47x55psw93ly80lvftzdr5ccrzuuedtf6fala4r4nnazm9y9hq5yu6pq24arjskmpv4mdgfn3spffxxv8ugvym36kmnj45jcvvmm227vqjm5fq8882yhjsq97p7xrwqt7n63v
namadaw masp add --alias my-pa --value patest10qy6fuwef9leccl6dfm7wwlyd336x4y32hz62cnrvlrl6r5yk0jnw80kus33x34a5peg2xc4csn
```

### Making Shielded Transactions

#### Shielding Transactions

The client should be able to make shielding transactions by providing a
transparent source address and a shielded payment address. The
main transparent effect of such a transaction should be a deduction of
the specified amount from the source address, and a corresponding
increase in the balance of the MASP validity predicate's address. The
gas fee is charged to the source address. Once the transaction is
completed, the spending key that was used to generate the payment address
will have the authority to spend the amount that was send. Below is an
example of how a shielding transacion should be made:

```
namadac transfer --source Bertha --amount 50 --token BTC --target my-pa
```

#### Unshielding Transactions

The client should be able to make unshielding transactions by providing
a shielded spending key and a transparent target address. The main
transparent effect of such a transaction should be a deduction of the
specified amount from the MASP validity predicate's address and a
corresponding increase in the transparent target address. The gas fee
is charged to the signer's address (which should default to the target
address). Once the transaction is complete, the spending key will no
longer be able to spend the transferred amount. Below is an example of
how an unshielding transaction should be made:

```
namadac transfer --target Bertha --amount 45 --token BTC --source my-sk
```

#### Shielded Transactions

The client should be able to make shielded transactions by providing a
shielded spending key and a shielded payment address. There should be
no change in the transparent balance of the MASP validity predicate's
address. The gas fee is charged to the signer's address. Once the
transaction is complete, the spending key will no longer be able to
spend the transferred amount, but the spending key that was used to
(directly or indirectly) generate the payment address will. Below is
an example of how a shielded transaction should be made:

```
namadac transfer --source my-sk --amount 5 --token BTC --target your-pa
```

### Viewing Shielded Balances

The client should be able to view shielded balances. The most
general output should be a list of pairs, each denoting a token
type and the unspent amount of that token present at each shielded
address whose viewing key is represented in the wallet. Note that
it should be possible to restrict the balance query to check only
a specific viewing key or for a specific token type. Below are
examples of how balance queries should be made:

```
namadac balance
namadac balance --owner my-key
namadac balance --owner my-key --token BTC
namadac balance --token BTC
```

### Listing Shielded Keys/Addresses

The wallet should be able to list all the spending keys, viewing keys,
and payment addresses that it stores. Below are examples of how the
wallet's storage should be queried:

```
namadaw masp list-keys
namadaw masp list-keys --unsafe-show-secret
namadaw masp list-keys --unsafe-show-secret --decrypt
namadaw masp list-addrs
```

### Finding Shielded Keys/Addresses

The wallet should be able to find any spending key, viewing key or
payment address when given its alias. Below are examples of how the
wallet's storage should be queried:

```
namadaw masp find --alias my-alias
namadaw masp find --alias my-alias --unsafe-show-secret
```
