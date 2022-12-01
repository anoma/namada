# Transparent Transactions

#### Table of Contents

- [Transfer Transactions](#part-1---token-transfer-transactions)
- [Initialize Account Transactions](#part-2---initialize-account-transaction)
- [Submitting Transactions](#submitting-transparent-transactions)

## Constructing Transparent Transactions

The web-wallet will need to support many transactions. As the data that gets submitted to the ledger is most easily constructed from `namada` types, we perform the assembly of the transaction with in WebAssembly using Rust so that we may natively interact with `namada`. The role of wasm in this scenario is to provide two pieces of data to the client (which will handle the broadcasting of the transaction), which are:

1. `hash` - the hash of the transaction
2. `data` - A byte array of the final wrapped and signed transaction

The following outlines how we can construct these transactions before returning them to the client.

## Part 1 - Token Transfer Transactions

There are a few steps involved in creating and signing a transaction:

1. Create an `namada::proto::Tx struct` and sign it with a keypair
2. Wrap Tx with a `namada::types::transaction::WrapperTx` struct which encrypts the transaction
3. Create a new `namada::proto::Tx` with the new `WrapperTx` as data, and sign it with a keypair (this will be broadcast to the ledger)

### 1.1 - Creating the `namada::proto::Tx` struct

The requirements for creating this struct are as follow:

- A pre-built wasm in the form of a byte array (this is loaded in the client as a `Uint8Array` type to pass to the wasm)
- A serialized `namada::types::token::Transfer` object which contains the following:
  - `source` - source address derived from keypair
  - `target` - target address
  - `token` - token address
  - `amount` - amount to transfer
- A UTC timestamp. _NOTE_ this is created when calling `proto::Tx::new()`, however, this is incompatible with the wasm in runtime (`time` is undefined). Therefore, we need to get a valid timestamp from `js_sys`:

```rust
// namada-lib/src/util.rs

pub fn get_timestamp() -> DateTimeUtc {
    let now = js_sys::Date::new_0();

    let year = now.get_utc_full_year() as i32;
    let month: u32 = now.get_utc_month() + 1;
    let day: u32 = now.get_utc_date();
    let hour: u32 = now.get_utc_hours();
    let min: u32 = now.get_utc_minutes();
    let sec: u32 = now.get_utc_seconds();

    let utc = Utc.ymd(year, month, day).and_hms(hour, min, sec);
    DateTimeUtc(utc)
}
```

#### Creating the `types::token::Transfer` struct to pass in as data:

_In wasm:_

```rust
// namada-lib/src/transfer.rs

let transfer = token::Transfer {
    source: source.0,
    target: target.0,
    token: token.0.clone(),
    amount,
};

// The data we pass to proto::Tx::new
let data = transfer
    .try_to_vec()
    .expect("Encoding unsigned transfer shouldn't fail");
```

_In Namada CLI:_
https://github.com/anoma/namada/blob/f6e78278608aaef253617885bb7ef95a50057268/apps/src/lib/client/tx.rs#L406-L411


#### Creating and signing the `proto::Tx` struct

_In wasm:_

```rust
// namada-lib/src/types/tx.rs

impl Tx {
    pub fn new(tx_code: Vec<u8>, data: Vec<u8>) -> proto::Tx {
        proto::Tx {
            code: tx_code,
            data: Some(data),
            timestamp: utils::get_timestamp(),
        }
    }
}
```

**NOTE** Here we provide a work around to an issue with `proto::Tx::new()` in wasm - instead of calling the method directly on `Tx`, we create a new implementation that returns a `proto::Tx`, with the timestamp being set using `js_sys` in order to make this wasm-compatible.

_In Namada CLI:_
https://github.com/anoma/namada/blob/f6e78278608aaef253617885bb7ef95a50057268/apps/src/lib/client/tx.rs#L417-L419


### 1.2 - Creating the `namada::types::transaction::WrapperTx` struct

The requirements for creating this struct are as follows:

- A `transaction::Fee` type, which contains:
  - `amount` - the Fee amount
  - `token` - the address of the token
- `epoch` - The ID of the epoch from query
- `gas_limit` - This contains a `u64` value representing the gas limit
- `tx` - the `proto::Tx` type we created earlier.

_In wasm:_

```rust
// namada-lib/src/types/wrapper.rs

transaction::WrapperTx::new(
    transaction::Fee {
        amount,
        token: token.0,
    },
    &keypair,
    storage::Epoch(u64::from(epoch)),
    transaction::GasLimit::from(gas_limit),
    tx,
)
```

**NOTE** Here we can directly invoke `WrapperTx::new`, so we only need to concern ourselves with convering the JavaScript-provided values into the appropriate types.

_In Namada CLI:_
https://github.com/anoma/namada/blob/f6e78278608aaef253617885bb7ef95a50057268/apps/src/lib/client/tx.rs#L687-L696

#### 1.3 - Create a new `Tx` with `WrapperTx` and sign it

Here we create a `WrapperTx` type, and with that we create a new `Tx` type (our _wrapped_ `Tx` type) with the `WrapperTx` as the `data`, and empty `vec![]` for `code`, and a new `timestamp`, and then we sign it.

_In wasm:_

```rust
// namada-lib/src/types/wrapper.rs -> sign()

(Tx::new(
    vec![],
    transaction::TxType::Wrapper(wrapper_tx)
        .clone()
        .try_to_vec().expect("Could not serialize WrapperTx")
)).sign(&keypair)
```

We can summarize a high-level overview of the entire process from the `namada-lib/src/types/transaction.rs` implementation:

```rust
let source_keypair = Keypair::deserialize(serialized_keypair)?;
let keypair = key::ed25519::Keypair::from_bytes(&source_keypair.to_bytes())
    .expect("Could not create keypair from bytes");

let tx = Tx::new(
    tx_code,
    data,
).sign(&keypair);

let wrapper_tx = WrapperTx::new(
    token,
    fee_amount,
    &keypair,
    epoch,
    gas_limit,
    tx,
);

let hash = wrapper_tx.tx_hash.to_string();
let wrapper_tx = WrapperTx::sign(wrapper_tx, &keypair);
let bytes = wrapper_tx.to_bytes();

// Return serialized wrapped & signed transaction as bytes with hash
// in a tuple:
Ok(Transaction {
    hash,
    bytes,
})
```

_In Namada CLI:_
https://github.com/anoma/namada/blob/f6e78278608aaef253617885bb7ef95a50057268/apps/src/lib/client/tx.rs#L810-L814


## Part 2 - Initialize Account Transaction

Constructing an Initialize Account transaction follows a similar process to a transfer, however, in addition to providing a `tx_init_account` wasm, we need to provide the `vp_user` wasm as well, as this is required when constructing the transaction:

```rust
// namada-lib/src/account.rs

let vp_code: Vec<u8> = vp_code.to_vec();
let keypair = &Keypair::deserialize(serialized_keypair.clone())
    .expect("Keypair could not be deserialized");
let public_key = PublicKey::from(keypair.0.public.clone());

let data = InitAccount {
    public_key,
    vp_code: vp_code.clone(),
};
```

Following this, we will pass `data` into to our new transaction as before, along with `tx_code` and required values for `WrapperTx`, returning the final result in a `JsValue` containing the transaction hash and returned byte array.

## Submitting Transparent Transactions

See [RPC](./rpc.md) for more information on HTTP and WebSocket RPC interaction with ledger.
