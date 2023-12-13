# Storage API

To facilitate code reuse, the core's crate `storage_api` module was designed to unify interface for reading from and writing to the storage from:

1. Protocol (typically `InitChain` and `FinalizeBlock` handlers; and read-only `Query` handler)
2. Transactions
3. Validity predicates (read-only - there are actually two instances of `StorageRead` in VPs, more on this below)

This module comes with two main traits, `StorageRead` and `StorageWrite` together with `storage_api::Result` and `storage_api::Error` types that you can use to implement your custom logic.

~~~admonish example title="Token balance example"
Token balance read and write may look something like this (the [real thing is here](https://github.com/anoma/namada/blob/main/core/src/ledger/storage_api/token.rs)):
```rust
fn read_balance<S>(
    s: &S,
    token: &Address,
    owner: &Address
  ) -> storage_api::Result<token::Amount>
    where S: StorageRead;

fn write_balance<S>(
    s: &mut S,
    token: &Address,
    owner: &Address,
    balance: token::Amount
  ) -> storage_api::Result<()>
    where S: StorageRead + StorageWrite;
```
~~~

```admonish info title="Data encoding"
Note that the `StorageRead::read` and `StorageWrite::write` methods use Borsh encoding. If you want custom encoding, use `read_bytes` and `write_bytes`.
```

## Error handling

All the methods in the `StorageRead` and `StorageWrite` return `storage_api::Result`  so you can simply use the try operator `?` in your implementation to handle any potential errors.

A custom `storage_api::Error` can be constructed from a static str with `new_const`, or from another Error type with `new`. Furthermore, you can wrap your custom `Result` with `into_storage_result` using the `trait ResultExt`.

```admonish warning
In library code written over `storage_api`, it is critical to propagate errors correctly (no `unwrap/expect`) to be able to reuse these in native environment.
```

In native VPs the `storage_api` methods may return an error when we run out of gas in the current execution and a panic would crash the node. This is a good motivation to document error conditions of your functions. Furthermore, adding new error conditions to existing functions should be considered a breaking change and reviewed carefully!

In protocol code, the traits' methods will never fail under normal operation and so if you're absolutely sure that there are no other error conditions, you're safe to call `expect` on these.

We don't yet have a good story for error matching and on related note, we should consider using `std::io::Error` in place of `storage_api::Error`. (<https://github.com/anoma/namada/issues/1214>)

## Transactions

For transactions specific functionality, you can use `trait TxEnv` that inherits both the `StorageRead` and `StorageWrite`.

## Validity predicates

Similarly, for VP specific functionality, there's `trait VpEnv`, which is implemented for both the native and WASM VPs.

To access `StorageRead` from a VP, you can pick between `pre` and `post` view functions to read the state prior and posterior to the transaction execution, respectively.

```admonish warning
If you expect that the value you're reading must not change, prefer to use the `pre` view function so that the validation may not be affected by any storage change applied in the transaction.
```

## Testing

To test code written over `storage_api` traits, look for `TestWlStorage`, which you can instantiate with `default()` and you're good to go.

For transactions and VPs, there are `TestTxEnv` and `TestVpEnv` in the `tests` crate together with respective `Ctx` types that implement the `storage_api` traits. You can find examples of how these are used across the codebase.

## Lazy collections

For dynamically sized collections, there is `LazyVec`, `LazyMap` and `LazySet` with APIs similar to that of standard in-memory collections. The data for these can be read on demand and they don't need to be fully read to write into or delete from them, which is also useful for validation.

~~~admonish example title="LazyMap usage example"
To use lazy collections, call `open` on them with some storage key prefix, typically starting with the address that will store the data. This will give you a "handle" that you can use to access and manipulate the data. In a `LazyMap` keys and in `LazySet` value are turned into storage key segments via `impl KeySeg`:

```rust
let mut storage = TestWlStorage::default();
let address = todo!();

// Storage prefix "/#{address}/map"
let prefix = Key::from(address.to_db_key())
          .push(&"map".to_owned())
          .expect("Cannot obtain a storage key");

let handle = LazyMap::<u32, String>::open(prefix);

// Storage key "/#{address}/map/data/0000000" will point to value "zero"
handle.insert(&mut storage, 0_u32, "zero".to_owned());
assert_eq!(handle.get(&storage, &0)?.unwrap(), Some("zero".to_owned()));

handle.remove(&mut storage, &0);
assert_eq!(handle.get(&storage, &0)?.unwrap().is_none());
```
~~~
