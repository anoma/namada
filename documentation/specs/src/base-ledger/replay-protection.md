# Replay Protection

Replay protection is a mechanism to prevent _replay attacks_, which consist of a malicious user resubmitting an already executed transaction (also mentioned as tx in this document) to the ledger.

A replay attack causes the state of the machine to deviate from the intended one (from the perspective of the parties involved in the original transaction) and causes economic damage to the fee payer of the original transaction, who finds himself paying more than once. Further economic damage is caused if the transaction involved the moving of value in some form (e.g. a transfer of tokens) with the sender being deprived of more value than intended.

Since the original transaction was already well formatted for the protocol's rules, the attacker doesn't need to rework it, making this attack relatively easy.

Of course, a replay attack makes sense only if the attacker differs from the _source_ of the original transaction, as a user will always be able to generate another semantically identical transaction to submit without the need to replay the same one.

To prevent this scenario, Namada supports a replay protection mechanism to prevent the execution of already processed transactions.
 
## Context

This section will illustrate the pre-existing context in which we are going to implement the replay protection mechanism.

### Encryption-Authentication

The current implementation of Namada is built on top of Tendermint which provides an encrypted and authenticated communication channel between every two nodes to prevent a _man-in-the-middle_ attack (see the detailed [spec](https://github.com/tendermint/tendermint/blob/29e5fbcc648510e4763bd0af0b461aed92c21f30/spec/p2p/peer.md)).

The Namada protocol relies on this substrate to exchange transactions (messages) that will define the state transition of the ledger. More specifically, a transaction is composed of two parts: a `WrapperTx` and an inner `Tx`

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
    /// the encrypted payload
    pub inner_tx: EncryptedTx,
    /// sha-2 hash of the inner transaction acting as a commitment
    /// the contents of the encrypted payload
    pub tx_hash: Hash,
}

pub struct Tx {
    pub code: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTimeUtc,
}
``` 

The wrapper transaction is composed of some metadata, the encrypted inner transaction itself and the hash of this. The inner `Tx` transaction carries the Wasm code to be executed and the associated data.

A transaction is constructed as follows:

1. The struct `Tx` is produced
2. The hash of this transaction gets signed by the author, producing another `Tx` where the data field holds the concatenation of the original data and the signature (`SignedTxData`)
3. The produced transaction is encrypted and embedded in a `WrapperTx`. The encryption step is there for a future implementation of DKG (see [Ferveo](https://github.com/anoma/ferveo))
4. Finally, the `WrapperTx` gets converted to a `Tx` struct, signed over its hash (same as step 2, relying on `SignedTxData`), and submitted to the network

Note that the signer of the `WrapperTx` and that of the inner one don't need to coincide, but the signer of the wrapper will be charged with gas and fees.
In the execution steps:

1. The `WrapperTx` signature is verified and, only if valid, the tx is processed
2. In the following height the proposer decrypts the inner tx, checks that the hash matches that of the `tx_hash` field and, if everything went well, includes the decrypted tx in the proposed block
3. The inner tx will then be executed by the Wasm runtime
4. After the execution, the affected validity predicates (also mentioned as VP in this document) will check the storage changes and (if relevant) the signature of the transaction: if the signature is not valid, the VP will deem the transaction invalid and the changes won't be applied to the storage

The signature checks effectively prevent any tampering with the transaction data because that would cause the checks to fail and the transaction to be rejected.
For a more in-depth view, please refer to the [Namada execution spec](https://specs.namada.net/base-ledger/execution.html).

### Tendermint replay protection

The underlying consensus engine, [Tendermint](https://github.com/tendermint/tendermint/blob/29e5fbcc648510e4763bd0af0b461aed92c21f30/spec/abci/apps.md), provides a first layer of protection in its mempool which is based on a cache of previously seen transactions. This mechanism is actually aimed at preventing a block proposer from including an already processed transaction in the next block, which can happen when the transaction has been received late. Of course, this also acts as a countermeasure against intentional replay attacks. This check though, like all the checks performed in `CheckTx`, is weak, since a malicious validator could always propose a block containing invalid transactions. There's therefore the need for a more robust replay protection mechanism implemented directly in the application.

## Implementation

Namada replay protection consists of three parts: the in-Wasm solution for `EncryptedTx` (also called the `InnerTx`), an in-protocol mechanism for `WrapperTx` and a way to mitigate replay attacks in case of a fork.

### InnerTx

The actual Wasm code and data for the transaction are encapsulated inside a struct `Tx`, which gets encrypted as an `EncryptedTx` and wrapped inside a `WrapperTx` (see the [relative](#encryption-authentication) section). This inner transaction must be protected from replay attacks because it carries the actual semantics of the state transition. Moreover, even if the wrapper transaction was protected from replay attacks, an attacker could extract the inner transaction, rewrap it, and replay it. Note that for this attack to work, the attacker will need to sign the outer transaction himself and pay gas and fees for that, but this could still cause much greater damage to the parties involved in the inner transaction.

We will implement the protection entirely in Wasm: the check of the counter will be carried out by the validity predicates while the actual writing of the counter in storage will be done by the transactions themselves.

To do so, the `SignedTxData` attached to the transaction will hold the current value of the counter in storage:

```rust
pub struct SignedTxData {
    /// The original tx data bytes, if any
    pub data: Option<Vec<u8>>,
    /// The optional transaction counter for replay protection
    pub tx_counter: Option<u64>,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: common::Signature,
}
```

The counter must reside in `SignedTxData` and not in the data itself because this must be checked by the validity predicate which is not aware of the specific transaction that took place but only of the changes in the storage; therefore, the VP is not able to correctly deserialize the data of the transactions since it doesn't know what type of data the bytes represent.

The counter will be signed as well to protect it from tampering and grant it the same guarantees explained at the [beginning](#encryption-authentication) of this document.

The wasm transaction will simply read the value from storage and increase its value by one. The target key in storage will be the following:

```
/$Address/inner_tx_counter: u64
```

The VP of the _source_ address will then check the validity of the signature and, if it's deemed valid, will proceed to check if the pre-value of the counter in storage was equal to the one contained in the `SignedTxData` struct and if the post-value of the key in storage has been incremented by one: if any of these conditions doesn't hold the VP will discard the transactions and prevent the changes from being applied to the storage.

In the specific case of a transfer, since MASP already comes with replay protection as part of the Zcash design (see the [MASP specs](https://specs.namada.net/masp.html) and [Zcash protocol specs](https://zips.z.cash/protocol/protocol.pdf)), the counter in `SignedTxData` is not required and therefore should be optional.

To implement replay protection for the inner transaction we will need to update all the VPs checking the transaction's signature to include the check on the transaction counter: at the moment the `vp_user` validity predicate is the only one to update. In addition, all the transactions involving `SignedTxData` should increment the counter.

### WrapperTx

`WrapperTx` is the only type of transaction currently accepted by the ledger. It must be protected from replay attacks because, if it wasn't, a malicious user could replay the transaction as is. Even if the inner transaction implemented replay protection (as explained in the [previous](#innertx) section) or, for any reason, wasn't accepted, the signer of the wrapper would still pay for gas and fees, effectively suffering economic damage.

To protect this transaction we can implement an in-protocol mechanism. Since the wrapper transaction gets signed before being submitted to the network, we can leverage the `tx_counter` field of the `SignedTxData` already introduced for the inner tx.

In addition, we need another counter in the storage subspace of every address:

```
/$Address/wrapper_tx_counter: u64
```

where `$Address` is the one signing the transaction (the same implied by the `pk` field of the `WrapperTx` struct).

The check will consist of a signature check first followed by a check on the counter that will make sure that the counter attached to the transaction matches the one in storage for the signing address. This will be done in the `process_proposal` function so that validators can decide whether the transaction is valid or not; if it's not, then they will discard the transaction and skip to the following one.

At last, in `finalize_block`, the ledger will update the counter key in storage, increasing its value by one. This will happen when the following conditions are met:

- `process_proposal` has accepted the tx by validating its signature and transaction counter
- The tx was correctly applied in `finalize_block` (for `WrapperTx` this simply means inclusion in the block and gas accounting)

Now, if a malicious user tried to replay this transaction, the `tx_counter` in the struct would no longer be equal to the one in storage and the transaction would be deemed invalid.

### Forks

In the case of a fork, the transaction counters are not enough to prevent replay attacks. Transactions, in fact, could still be replayed on the other branch as long as their format is kept unchanged and the counters in storage match.

To mitigate this problem, transactions will need to carry a `ChainId` identifier to tie them to a specific fork. This field needs to be added to the `Tx` struct so that it applies to both `WrapperTx` and `EncryptedTx` (for the same reason explained in [InnerTx](#InnerTx) about the double transaction counter):

```rust
pub struct Tx {
    pub code: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTimeUtc,
    pub chain_id: ChainId
}
```

This new field will be signed just like the other ones and is therefore subject to the same guarantees explained in the [initial](#encrypted-authenticated-fixme-better-name-for-this-section) section.
The validity of this identifier will be checked in `process_proposal` for both the outer and inner tx: if a transaction carries an unexpected chain id, it won't be applied, meaning that the counter in storage won't be updated and no other modifications will be applied to storage.

## Implementation details

In this section we'll talk about some details of the replay protection mechanism that derive from the solution proposed in the previous section.

### Storage counters

Replay protection will require interaction with the storage from both the protocol and Wasm. To do so we can take advantage of the `StorageRead` and `StorageWrite` traits to work with a single interface.

The proposed implementation requires two transaction counters in storage for every address, so that the storage subspace of a given address looks like the following:

```
/$Address/wrapper_tx_counter: u64
/$Address/inner_tx_counter: u64
```

An implementation requiring a single counter in storage has been taken into consideration and discarded because that would not support batching; see the [relative section](#single-counter-in-storage) for a more in-depth explanation.

For both the wrapper and inner transaction, the increase of the counter in storage is an important step that must be correctly executed. More specifically, we want to increase the counter as soon as we verify that the signature, the chain id and the passed-in transaction counter are valid. The increase should happen immediately after the checks because of two reasons:

- Prevent replay attack of a transaction in the same block
- Update the transaction counter even in case the transaction fails, to prevent a possible replay attack in the future (since a transaction invalid at state Sx could become valid at state Sn where `n > x`)

For `WrapperTx`, the counter increase and fee accounting will per performed in `finalize_block` (as stated in the [relative](#wrappertx) section).

For `InnerTx`, instead, the logic is not straightforward. The transaction code will be executed in a Wasm environment ([Wasmer](https://wasmer.io)) till it eventually completes or raises an exception. In case of success, the counter in storage will be updated correctly but, in case of failure, the protocol will discard all of the changes brought by the transactions to the write-ahead-log, including the updated transaction counter. This is a problem because the transaction could be successfully replayed in the future if it will become valid.

The ideal solution would be to interrupt the execution of the Wasm code after the transaction counter (if any) has been increased. This would allow performing a first run of the involved VPs and, if all of them accept the changes, let the protocol commit these changes before any possible failure. After that, the protocol would resume the execution of the transaction from the previous interrupt point until completion or failure, after which a second pass of the VPs is initiated to validate the remaining state modifications. In case of a VP rejection after the counter increase there would be no need to resume execution and the transaction could be immediately deemed invalid so that the protocol could skip to the next tx to be executed. With this solution, the counter update would be committed to storage regardless of a failure of the transaction itself.

Unfortunately, at the moment, Wasmer doesn't allow [yielding](https://github.com/wasmerio/wasmer/issues/1127) from the execution. For now, the responsibility will be up to the user to provide a valid inner transaction, and, in case of an invalid one, to take actions to prevent a possible replay attack: in essence, the user will be required to submit a new valid transaction to invalidate the counter of the previous one.

### Batching and transaction ordering

The proposed replay protection technique supports the execution of multiple transactions with the same address as _source_ in a single block. Actually, the presence of the transaction counters and the checks performed on them now impose a strict ordering on the execution sequence (which can be an added value for some use cases). The correct execution of more than one transaction per source address in the same block is preserved as long as:

1. The wrapper transactions are inserted in the block with the correct ascending order
2. No hole is present in the counters' sequence
3. The counter of the first transaction included in the block matches the expected one in storage

The conditions are enforced by the block proposer who has an interest in maximizing the amount of fees extracted by the proposed block. To support this incentive, we will charge gas and fees at the same moment in which we perform the counter increase explained in the [storage counters](#storage-counters) section: this way we can avoid charging fees and gas if the transaction is invalid (invalid signature, wrong counter or wrong chain id), effectively incentivizing the block proposer to include only valid transactions and correctly reorder them to maximize the fees (see the [block rejection](#block-rejection) section for an alternative solution that was discarded in favor of this).

In case of a missing transaction causes a hole in the sequence of transaction counters, the block proposer will include in the block all the transactions up to the missing one and discard all the ones following that one, effectively preserving the correct ordering.

Correctly ordering the transactions is not enough to guarantee the correct execution. As already mentioned in the [WrapperTx](#wrappertx) section, the block proposer and the validators also need to access the storage to check that the first transaction counter of a sequence is actually the expected one.

The entire counter ordering is only done on the `WrapperTx`: if the inner counter is wrong then the inner transaction will fail and the signer of the corresponding wrapper will be charged with fees. This incentivizes submitters to produce valid transactions and discourages malicious user from rewrapping and resubmitting old transactions.

### Mempool checks

As a form of optimization to prevent mempool spamming, some of the checks that have been introduced in this document will also be brought to the `mempool_validate` function. Of course, we always refer to checks on the `WrapperTx` only. More specifically:

- Check the `ChainId` field
- Check the signature of the transaction against the `pk` field of the `WrapperTx`
- Perform a limited check on the transaction counter

Regarding the last point, `mempool_validate` will check if the counter in the transaction is `>=` than the one in storage for the address signing the `WrapperTx`. A complete check (checking for strict equality) is not feasible, as described in the [relative](#mempool-counter-validation) section.

## Alternatives considered

In this last section we list some possible solutions that were taken into consideration during the writing of this spec but were eventually discarded.

### Mempool counter validation

The idea of performing a complete validation of the transaction counters in the `mempool_validate` function was discarded because of a possible flaw. 

Suppose a client sends five transactions (counters from 1 to 5). The mempool of the next block proposer is not guaranteed to receive them in order: something on the network could shuffle the transactions up so that they arrive in the following order: 2-3-4-5-1. Now, since we validate every single transaction to be included in the mempool in the exact order in which we receive them, we would discard the first four transactions and only accept the last one, that with counter 1. Now the next block proposer might have the four discarded transactions in its mempool (since those were not added to the previous block and therefore not evicted from the other mempools, at least they shouldn't, see [block rejection](#block-rejection)) and could therefore include them in the following block. But still, a process that could have ended in a single block actually took two blocks. Moreover, there are two more issues:

- The next block proposer might have the remaining transactions out of order in his mempool as well, effectively propagating the same issue down to the next block proposer
- The next block proposer might not have these transactions in his mempool at all

Finally, transactions that are not allowed into the mempool don't get propagated to the other peers, making their inclusion in a block even harder.
It is instead better to avoid a complete filter on the transactions based on their order in the mempool: instead we are going to perform a simpler check and then let the block proposer rearrange them correctly when proposing the block.

### In-protocol protection for InnerTx

An alternative implementation could place the protection for the inner tx in protocol, just like the wrapper one, based on the transaction counter inside `SignedTxData`. The check would run in `process_proposal` and the update in `finalize_block`, just like for the wrapper transaction. This implementation, though, shows two drawbacks:

- it implies the need for an hard fork in case of a modification of the replay protection mechanism
- it's not clear who's the source of the inner transaction from the outside, as that depends on the specific code of the transaction itself. We could use specific whitelisted txs set to define when it requires a counter (would not work for future programmable transactions), but still, we have no way to define which address should be targeted for replay protection (**blocking issue**)

### In-protocol counter increase for InnerTx

In the [storage counter](#storage-counters) section we mentioned the issue of increasing the transaction counter for an inner tx even in case of failure. A possible solution that we took in consideration and discarded was to increase the counter from protocol in case of a failure.

This is technically feasible since the protocol is aware of the keys modified by the transaction and also of the results of the validity predicates (useful in case the transaction updated more than one counter in storage). It is then possible to recover the value and reapply the change directly from protocol. This logic though, is quite dispersive, since it effectively splits the management of the counter for the `InnerTx` among Wasm and protocol, while our initial intent was to keep it completely in Wasm.

### Single counter in storage

We can't use a single transaction counter in storage because this would prevent batching.

As an example, if a client (with a current counter in storage holding value 5) generates two transactions to be included in the same block, signing both the outer and the inner (default behavior of the client), it would need to generate the following transaction counters: 

```
[
    T1: (WrapperCtr: 5, InnerCtr: 6),
    T2: (WrapperCtr: 7, InnerCtr: 8)
]
```

Now, the current execution model of Namada includes the `WrapperTx` in a block first to then decrypt and execute the inner tx in the following block (respecting the committed order of the transactions). That would mean that the outer tx of `T1` would pass validation and immediately increase the counter to 6 to prevent a replay attack in the same block. Now, the outer tx of `T2` will be processed but it won't pass validation because it carries a counter with value 7 while the ledger expects 6.

To fix this, one could think to set the counters as follows: 

```
[
    T1: (WrapperCtr: 5, InnerCtr: 7),
    T2: (WrapperCtr: 6, InnerCtr: 8)
]
```

This way both the transactions will be considered valid and executed. The issue is that, if the second transaction is not included in the block (for any reason), than the first transaction (the only one remaining at this point) will fail. In fact, after the outer tx has correctly increased the counter in storage to value 6 the block will be accepted. In the next block the inner transaction will be decrypted and executed but this last step will fail since the counter in `SignedTxData` carries a value of 7 and the counter in storage has a value of 6.

To cope with this there are two possible ways. The first one is that, instead of checking the exact value of the counter in storage and increasing its value by one, we could check that the transaction carries a counter `>=` than the one in storage and write this one (not increase) to storage. The problem with this is that it the lack of support for strict ordering of execution.

The second option is to keep the usual increase strategy of the counter (increase by one and check for strict equality) and simply use two different counters in storage for each address. The transaction will then look like this:

```
[
    T1: (WrapperCtr: 5, InnerCtr: 5),
    T2: (WrapperCtr: 6, InnerCtr: 6)
]
```

Since the order of inclusion of the `WrapperTxs` forces the same order of the execution for the inner ones, both transactions can be correctly executed and the correctness will be maintained even in case `T2` didn't make it to the block (note that the counter for an inner tx and the corresponding wrapper one don't need to coincide).

### Block rejection

The implementation proposed in this document has one flaw when it comes to discontinuous transactions. If, for example, for a given address, the counter in storage for the `WrapperTx` is 5 and the block proposer receives, in order, transactions 6, 5 and 8, the proposer will have an incentive to correctly order transactions 5 and 6 to gain the fees that he would otherwise lose. Transaction 8 will never be accepted by the validators no matter the ordering (since they will expect tx 7 which got lost): this effectively means that the block proposer has no incentive to include this transaction in the block because it would gain him no fees but, at the same time, he doesn't really have a disincentive to not include it, since in this case the validators will simply discard the invalid tx but accept the rest of the block granting the proposer his fees on all the other transactions. 

A similar scenario happens in the case of a single transaction that is not the expected one (e.g. tx 5 when 4 is expected), or for a different type of inconsistencies, like a wrong `ChainId` or an invalid signature.

It is up to the block proposer then, whether to include or not these kinds of transactions: a malicious proposer could do so to spam the block without suffering any penalty. The lack of fees could be a strong enough measure to prevent proposers from applying this behavior, together with the fact that the only damage caused to the chain would be spamming the blocks.

If one wanted to completely prevent this scenario, the solution would be to reject the entire block: this way the proposer would have an incentive to behave correctly (by not including these transactions into the block) to gain the block fees. This would allow to shrink the size of the blocks in case of unfair block proposers but it would also cause the slow down of the block creation process, since after a block rejection a new Tendermint round has to be initiated.
