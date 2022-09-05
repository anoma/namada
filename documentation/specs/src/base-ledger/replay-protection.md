# Replay Protection

Namada supports a replay protection mechanism to prevent the execution of already processed transactions.

## Tendermint

[Tendermint]((https://docs.tendermint.com/v0.33/app-dev/app-development.html#replay-protection)) provides a first layer of protection against replay attacks in its mempool. The mechanism is based on a cache of previously seen transactions. This check though, like all the checks performed in `CheckTx`, is weak, since a malicious validator could always propose a block containing invalid transactions. There's therefore the need for a more robust replay protection mechanism implemented directly in the application.

## WrapperTx

`WrapperTx` is the only type of transaction currently accepted by the ledger. It must be protected from replay attacks because, if it wasn't, a malicious user could replay the transaction as is. Even if the inner transaction implemented replay protection or, for any reason, wasn't accepted, the signer of the wrapper would still pay for gas and fees, effectively suffering economic damage.

To protect this transaction we can implement an in-protocol mechanism that requires us to expand the current definition of the struct to include a transaction counter:

```rust
pub struct WrapperTx {
    /// The fee to be payed for including the tx
    pub fee: Fee,
    /// Used to determine an implicit account of the fee payer
    pub pk: common::PublicKey,
    /// The epoch in which the tx is to be submitted. This determines
    /// which decryption key will be used
    pub epoch: Epoch,
    /// Max amount of gas that can be used when executing the inner tx
    pub gas_limit: GasLimit,
    /// Transaction counter for replay-protection
    pub tx_counter: u32,
    /// the encrypted payload
    pub inner_tx: EncryptedTx,
    /// sha-2 hash of the inner transaction acting as a commitment
    /// the contents of the encrypted payload
    pub tx_hash: Hash,
}
``` 

In addition, we need a counter in the storage subspace of every implict address:

```
/$Address/tx_counter: u32
```

In `process_proposal` we check that `tx_counter` field in `WrapperTx` is greater or equal to the value currently in storage; if this doesn't hold, the transaction is considered invalid.

At last, in `finalize_block`, the protocol updates the counter key in storage, increasing its value by one. Now, if a malicious user tried to replay this transaction, the `tx_counter` in the struct would no longer be greater or equal to the one in storage and the transaction would be deemed invalid. 

Note that the address whose counter is involved in this process is the one signing the transaction (the same as the `pk` field of the struct).

## InnerTx

The `EncryptedTx` incapsulated inside `WrapperTx` should be protected too. That's because, if it wasn't, an attacker could extract the inner tx, rewrap it, and replay it.\
To simplify this check we will perform it entirely in Wasm: the check of the counter will be carryed out by the validity predicates while the actual writing of the counter in storage will be done by the transactions themselves. 

To do so, the `SignedTxData` attached to the transaction will hold the current value of the counter in storage. The transaction will simply read the value from storage and increase its value by one. The VP will then check the validity of the signature and, if it's deemed valid, will proceed to checking if the pre value of the counter in storage was less or equal than the one contained in the transaction data and if the post value of the key in storage has been incremented by one.

In the specific case of a transfer, since MASP already comes with replay protection as part of the Zcash design (see the [MASP specs](https://specs.namada.net/masp.html) and [Zcash protocol specs](https://zips.z.cash/protocol/protocol.pdf)), the counter in `SignedTxData` should be optional.

An alternative implementation could place the protection for the inner tx in protocol, just like the wrapper one. In this case we would need to extend the `Tx` struct to hold an additional optional field (again, because of MASP) for the transaction counter and the address involved in replay protection, like so:

```rust
pub struct Tx {
    pub code: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTimeUtc,
    pub tx_counter: Option<(Address, u32)>
}
```

The check would run in `process_proposal` and the update in `finalize_block`, just like for the wrapper transaction. The drawback of this implementation is that it implies the need for an hard fork in case of a modification of the replay protection mechanism.

### VPs and Txs

To implement replay protection for the inner transaction we will need to update all the VPs checking the transaction's signature to include the check on the transaction counter: at the moment the `vp_user` validity predicate is the only one to update.

In addition, all the transactions involving `SignedTxData` should increment the counter.

## Single counter

The mechanisms to prevent replay attacks for both transactions (wrapper and inner) will share the same `tx_counter` key in storage.

This could be an issue when the signer of the `WrapperTx` is the same of the `InnerTx` (default behaviour of the client): in this case, if both transactions expect the same counter in storage, the wrapper transaction will pass validation but the inner one will fail. To cope with this, the client will be responsible for producing a valid `WrapperTx` in which `tx_counter` will be set to the current value of the counter in storage, call it `storage_ctr`, while the inner transaction will have `storage_ctr + 1` in its data.

## Storage Interface

Replay protection will require interaction with the storage from both the protocol and Wasm. To do so we can take advantage of the `StorageRead` and `StorageWrite` traits to work with a single interface.

## Batching

The implementation proposed in this document doesn't support batching of multiple transactions from a same address in a single block. This is because the order in which transactions will be included in the block by the proposer is not guarateed. An out of order execution of multiple transaction would lead to the failure of some of them (in the worst case, the failure of all of them but the first one executed, in the best case, the failure of only the last transaction). This problem will be amplified by the introduction of Ferveo for DKG which will be able to reorder transactions.

The Wasm implementation of replay protection can't cope with this problem because every wasm run (of either a transaction or a validity predicate) is only aware of its context, meaning the wasm bytecode and the serialized transaction data. The lack of awareness of the other transactions makes it impossible to develop a replay protection mechanism supporting batching in wasm.

To address this issue there could be two ways:

- Keep the proposed replay protection in Wasm and implement a batching mechanism in both the client and the ledger to embed more than one transaction in a single `Tx` struct
- Implement replay protection in protocol for the inner transaction (as discolsed in section [InnerTx](#InnerTx))

Following the second option, the ledger would be able to analyze the validity of the counters, of all the transcations relating to a single address, against the value in storage at the beginning of the block.
Finally, it could increment the counter in storage a single time by the correct amount (given by the amount of transactions that were executed with success).

The first option, though, seems to have more benefits. In addition to allowing batching, it's more flexible and it also enables the in-order execution of the transactions included in the batch, which may come in handy in certain cases.
