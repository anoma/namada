# Replay Protection

Replay protection is a mechanism to prevent _replay attacks_, which consist of a
malicious user resubmitting an already executed transaction (also mentioned as
tx in this document) to the ledger.

A replay attack causes the state of the machine to deviate from the intended one
(from the perspective of the parties involved in the original transaction) and
causes economic damage to the fee payer of the original transaction, who finds
himself paying more than once. Further economic damage is caused if the
transaction involved the moving of value in some form (e.g. a transfer of
tokens) with the sender being deprived of more value than intended.

Since the original transaction was already well formatted for the protocol's
rules, the attacker doesn't need to rework it, making this attack relatively
easy.

Of course, a replay attack makes sense only if the attacker differs from the
_source_ of the original transaction, as a user will always be able to generate
another semantically identical transaction to submit without the need to replay
the same one.

To prevent this scenario, Namada supports a replay protection mechanism to
prevent the execution of already processed transactions.

## Context

This section will illustrate the pre-existing context in which we are going to
implement the replay protection mechanism.

### Encryption-Authentication

The current implementation of Namada is built on top of Tendermint which
provides an encrypted and authenticated communication channel between every two
nodes to prevent a _man-in-the-middle_ attack (see the detailed
[spec](https://github.com/tendermint/tendermint/blob/29e5fbcc648510e4763bd0af0b461aed92c21f30/spec/p2p/peer.md)).

The Namada protocol relies on this substrate to exchange transactions (messages)
that will define the state transition of the ledger. More specifically, a
transaction is composed of two parts: a `WrapperTx` and an inner `Tx`

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
  /// The optional unshielding tx for fee payment
  pub unshield: Option<Tx>,
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

The wrapper transaction is composed of some metadata, an optional unshielding tx
for fee payment (see [fee specs](../economics/fee-system.md)), the encrypted
inner transaction itself and the hash of this. The inner `Tx` transaction
carries the Wasm code to be executed and the associated data.

A transaction is constructed as follows:

1. The struct `Tx` is produced
2. The hash of this transaction gets signed by the author, producing another
   `Tx` where the data field holds the concatenation of the original data and
   the signature (`SignedTxData`)
3. The produced transaction is encrypted and embedded in a `WrapperTx`. The
   encryption step is there for a future implementation of DKG (see
   [Ferveo](https://github.com/anoma/ferveo))
4. Finally, the `WrapperTx` gets converted to a `Tx` struct, signed over its
   hash (same as step 2, relying on `SignedTxData`), and submitted to the
   network

Note that the signer of the `WrapperTx` and that of the inner one don't need to
coincide, but the signer of the wrapper will be charged with gas and fees. In
the execution steps:

1. The `WrapperTx` signature is verified and, only if valid, the tx is processed
2. In the following height the proposer decrypts the inner tx, checks that the
   hash matches that of the `tx_hash` field and, if everything went well,
   includes the decrypted tx in the proposed block
3. The inner tx will then be executed by the Wasm runtime
4. After the execution, the affected validity predicates (also mentioned as VP
   in this document) will check the storage changes and (if relevant) the
   signature of the transaction: if the signature is not valid, the VP will deem
   the transaction invalid and the changes won't be applied to the storage

The signature checks effectively prevent any tampering with the transaction data
because that would cause the checks to fail and the transaction to be rejected.
For a more in-depth view, please refer to the
[Namada execution spec](./execution.md).

### Tendermint replay protection

The underlying consensus engine,
[Tendermint](https://github.com/tendermint/tendermint/blob/29e5fbcc648510e4763bd0af0b461aed92c21f30/spec/abci/apps.md),
provides a first layer of protection in its mempool which is based on a cache of
previously seen transactions. This mechanism is actually aimed at preventing a
block proposer from including an already processed transaction in the next
block, which can happen when the transaction has been received late. Of course,
this also acts as a countermeasure against intentional replay attacks. This
check though, like all the checks performed in `CheckTx`, is weak, since a
malicious validator could always propose a block containing invalid
transactions. There's therefore the need for a more robust replay protection
mechanism implemented directly in the application.

## Implementation

Namada replay protection consists of three parts: the hash-based solution for
both `EncryptedTx` (also called the `InnerTx`) and `WrapperTx`, a way to
mitigate replay attacks in case of a fork and a concept of a lifetime for the
transactions.

### Hash register

The actual Wasm code and data for the transaction are encapsulated inside a
struct `Tx`, which gets encrypted as an `EncryptedTx` and wrapped inside a
`WrapperTx` (see the [relative](#encryption-authentication) section). This inner
transaction must be protected from replay attacks because it carries the actual
semantics of the state transition. Moreover, even if the wrapper transaction was
protected from replay attacks, an attacker could extract the inner transaction,
rewrap it, and replay it. Note that for this attack to work, the attacker will
need to sign the outer transaction himself and pay gas and fees for that, but
this could still cause much greater damage to the parties involved in the inner
transaction.

`WrapperTx` is the only type of transaction currently accepted by the ledger. It
must be protected from replay attacks because, if it wasn't, a malicious user
could replay the transaction as is. Even if the inner transaction implemented
replay protection or, for any reason, wasn't accepted, the signer of the wrapper
would still pay for gas and fees, effectively suffering economic damage.

To prevent the replay of both these transactions we will rely on a set of
already processed transactions' digests that will be kept in storage. These
digests will be computed on the **unsigned** transactions, to support replay
protection even for [multisigned](multisignature.md) transactions: in this case,
if hashes were taken from the signed transactions, a different set of signatures
on the same tx would produce a different hash, effectively allowing for a
replay. To support this, we'll need a subspace in storage headed by a
`ReplayProtection` internal address:

```
/\$ReplayProtectionAddress/\$tx0_hash: None
/\$ReplayProtectionAddress/\$tx1_hash: None
/\$ReplayProtectionAddress/\$tx2_hash: None
...
```

The hashes will form the last part of the path to allow for a fast storage
lookup.

The consistency of the storage subspace is of critical importance for the
correct working of the replay protection mechanism. To protect it, a validity
predicate will check that no changes to this subspace are applied by any wasm
transaction, as those should only be available from protocol.

Both in `mempool_validation` and `process_proposal` we will perform a check
(together with others, see the [relative](#wrapper-checks) section) on both the
digests against the storage to check that neither of the transactions has
already been executed: if this doesn't hold, the `WrapperTx` will not be
included into the mempool/block respectively. If both checks pass then the
transaction is included in the block and executed. In the `finalize_block`
function we will add the transaction's hash to storage to prevent re-executions.
We will first add the hash of the wrapper transaction. After that, in the
following block, we deserialize the inner transaction, check the correct order
of the transactions in the block and execute the tx: if it runs out of gas then
we'll avoid storing its hash to allow rewrapping and executing the transaction,
otherwise we'll add the hash in storage (both in case of success or failure of
the tx).

#### Optional unshielding

The optional `unshield` field is supposed to carry an unshielding masp
`Transfer`. Given this assumption, there's no need to manage it since masp has
an internal replay protection mechanism.

Still, since this field represents a valid, signed `Tx`, there are three
possible attacks that can be run by leveraging this field:

1. If the wrapper signer constructs an `unshield` tx that actually encodes
   another type of transaction, then this one can be extracted and executed
   separately
2. A malicious user could extract this tx before it makes it to a block and play
   it in advance
3. A combination of the previous two

In the first case, the unshielding operation would fail because of the checks
run in protocol, but the tx itself could be extracted, wrapped and submitted to
the network. This issue could be solved with the mechanism explained in the
previous section.

The second attack, instead, is performed before the original tx is placed in a
block and, therefore, cannot be prevented with a replay protection mechanism.
The only result of this attack would be that the original wrapper transaction
would fail since it would attempt to replay a masp transfer: in this case, the
submitter of the original tx can recreate it without the need for the
unshielding operation since the attacker has already performed it.

In the last case the unshielding transaction (which is not a masp transfer)
could be encrypted, wrapped and executed before the original transaction is
inserted in a block. When the latter gets executed the protocol checks detect
that this is not a masp unshielding transfer and reject it.

Given that saving the hash of the unshielding transaction is redundant in case
of a proper masp transfer and it doesn't prevent the second scenario in case of
non-masp transaction, Namada does not implement the replay protection mechanism
on the unshielding transaction, whose correctness is left to the wrapper signer
and the masp validity predicate (in case the unshielding tx was indeed a correct
masp unshield transfer). The combination of the fee system, the validity
predicates set and the protocol checks on the unshielding operation guarantees
that even if one of the attacks explained in this section is performed:

- The original wrapper signer doesn't suffer economic damage (the wrapper
  containing the invalid unshielding forces the block rejection without fee
  collection)
- The attacker has to pay fees on the rewrapped tx preventing him to submit
  these transactions for free
- The invalid unshielding transaction must still be a valid transaction per the
  VPs triggered

### Forks

In the case of a fork, the transaction hash is not enough to prevent replay
attacks. Transactions, in fact, could still be replayed on the other branch as
long as their format is kept unchanged and the counters in storage match.

To mitigate this problem, transactions will need to carry a `ChainId` identifier
to tie them to a specific fork. This field needs to be added to the `Tx` struct
so that it applies to both `WrapperTx` and `EncryptedTx`:

```rust
pub struct Tx {
  pub code: Vec<u8>,
  pub data: Option<Vec<u8>>,
  pub timestamp: DateTimeUtc,
  pub chain_id: ChainId
}
```

This new field will be signed just like the other ones and is therefore subject
to the same guarantees explained in the [initial](#encryption-authentication)
section. The validity of this identifier will be checked in `process_proposal`
for both the outer and inner tx: if a transaction carries an unexpected chain
id, it won't be applied, meaning that no modifications will be applied to
storage.

### Transaction lifetime

In general, a transaction is valid at the moment of submission, but after that,
a series of external factors (ledger state, etc.) might change the mind of the
submitter who's now not interested in the execution of the transaction anymore.

We have to introduce the concept of a lifetime (or timeout) for the
transactions: basically, the `Tx` struct will hold an extra field called
`expiration` stating the maximum `DateTimeUtc` up until which the submitter is
willing to see the transaction executed. After the specified time, the
transaction will be considered invalid and discarded regardless of all the other
checks.

By introducing this new field we are setting a new constraint in the
transaction's contract, where the ledger will make sure to prevent the execution
of the transaction after the deadline and, on the other side, the submitter
commits himself to the result of the execution at least until its expiration. If
the expiration is reached and the transaction has not been executed the
submitter can decide to submit a new transaction if he's still interested in the
changes carried by it.

In our design, the `expiration` will hold until the transaction is executed:
once it's executed, either in case of success or failure, the tx hash will be
written to storage and the transaction will not be replayable. In essence, the
transaction submitter commits himself to one of these three conditions:

- Transaction is invalid regardless of the specific state
- Transaction is executed (either with success or not) and the transaction hash
  is saved in the storage
- Expiration time has passed

The first condition satisfied will invalidate further executions of the same tx.

In anticipation of DKG implementation, the current struct `WrapperTx` holds a
field `epoch` stating the epoch in which the tx should be executed. This is
because Ferveo will produce a new public key each epoch, effectively limiting
the lifetime of the transaction (see section 2.2.2 of the
[documentation](https://eprint.iacr.org/2022/898.pdf)). Unfortunately, for
replay protection, a resolution of 1 epoch (~ 1 day) is too low for the possible
needs of the submitters, therefore we need the `expiration` field to hold a
maximum `DateTimeUtc` to increase resolution down to a single block (~ 10
seconds).

```rust
pub struct Tx {
  pub code: Vec<u8>,
  pub data: Option<Vec<u8>>,
  pub timestamp: DateTimeUtc,
  pub chain_id: ChainId,
  /// Lifetime of the transaction, also determines which decryption key will be used
  pub expiration: DateTimeUtc,
}

pub struct WrapperTx {
  /// The fee to be payed for including the tx
  pub fee: Fee,
  /// Used to determine an implicit account of the fee payer
  pub pk: common::PublicKey,
  /// Max amount of gas that can be used when executing the inner tx
  pub gas_limit: GasLimit,
  /// the encrypted payload
  pub inner_tx: EncryptedTx,
  /// sha-2 hash of the inner transaction acting as a commitment
  /// the contents of the encrypted payload
  pub tx_hash: Hash,
}
```

Since we now have more detailed information about the desired lifetime of the
transaction, we can remove the `epoch` field and rely solely on `expiration`.
Now, the producer of the inner transaction should make sure to set a sensible
value for this field, in the sense that it should not span more than one epoch.
If this happens, then the transaction will be correctly decrypted only in a
subset of the desired lifetime (the one expecting the actual key used for the
encryption), while, in the following epochs, the transaction will fail
decryption and won't be executed. In essence, the `expiration` parameter can
only restrict the implicit lifetime within the current epoch, it can not surpass
it as that would make the transaction fail in the decryption phase.

The subject encrypting the inner transaction will also be responsible for using
the appropriate public key for encryption relative to the targeted time.

The wrapper transaction will match the `expiration` of the inner for correct
execution. Note that we need this field also for the wrapper to anticipate the
check at mempool/proposal evaluation time, but also to prevent someone from
inserting a wrapper transaction after the corresponding inner has expired
forcing the wrapper signer to pay for the fees.

### Wrapper checks

In `mempool_validation` we will perform some checks on the wrapper tx to
validate it. These will involve:

- Signature
- `GasLimit` is below the block gas limit
- `Fees` are paid with an accepted token and match the minimum amount required
- `ChainId`
- Transaction hash
- Expiration
- Unshielding tx (if present), is indeed a masp unshielding transfer

For gas, fee and the unshielding tx more details can be found in the
[fee specs](../economics/fee-system.md).

These checks can all be done before executing the transactions themselves. If
any of these fails, the transaction should be considered invalid and the action
to take will be one of the followings:

1. If the checks fail on the signature, chainId, expiration, transaction hash or
   the unshielding tx, then this transaction will be forever invalid, regardless
   of the possible evolution of the ledger's state. There's no need to include
   the transaction in the block. Moreover, we **cannot** include this
   transaction in the block to charge a fee (as a sort of punishment) because
   these errors may not depend on the signer of the tx (could be due to
   malicious users or simply a delay in the tx inclusion in the block)
2. If the checks fail on `Fee` or `GasLimit` the transaction should be
   discarded. In theory the gas limit of a block is a Namada parameter
   controlled by governance, so there's a chance that the transaction could
   become valid in the future should this limit be raised. The same applies to
   the token whitelist and the minimum fee required. However we can expect a
   slow rate of change of these parameters so we can reject the tx (the
   submitter can always resubmit it at a future time)

If instead all the checks pass validation we will include the transaction in the
block to store the hash and charge the fee.

All these checks are also run in `process_proposal` with a few additions:

- Wrapper signer has enough funds to pay the fee. This check should not be done
  in mempool because the funds available for a certain address are variable in
  time and should only be checked at block inclusion time. If any of the checks
  fail here, the entire block is rejected forcing a new Tendermint round to
  begin (see a better explanation of this choice in the
  [relative](#block-rejection) section)
- The unshielding tx (if present) releases the minimum amount of tokens required
  to pay fees
- The unshielding tx (if present) runs succesffuly

The `expiration` parameter also justifies that the check on funds is only done
in `process_proposal` and not in mempool. Without it, the transaction could be
potentially executed at any future moment, possibly going against the mutated
interests of the submitter. With the expiration parameter, now, the submitter
commits himself to accept the execution of the transaction up to the specified
time: it's going to be his responsibility to provide a sensible value for this
parameter. Given this constraint the transaction will be kept in mempool up
until the expiration (since it would become invalid after that in any case), to
prevent the mempool from increasing too much in size.

This mechanism can also be applied to another scenario. Suppose a transaction
was not propagated to the network by a node (or a group of colluding nodes).
Now, this tx might be valid, but it doesn't get inserted into a block. Without
an expiration, this tx can be replayed (better, applied, since it was never
executed in the first place) at a future moment in time when the submitter might
not be willing to execute it any more.

### Block rejection

To prevent a block proposer from including invalid transactions in a block, the
validators will reject the entire block in case they find a single invalid
wrapper transaction.

Rejecting the single invalid transaction while still accepting the block is not
a valid solution. In this case, in fact, the block proposer has no incentive to
include invalid transactions in the block because these would gain him no fees
but, at the same time, he doesn't really have a disincentive to not include
them, since in this case the validators will simply discard the invalid tx but
accept the rest of the block granting the proposer his fees on all the other
transactions. This, of course, applies in case the proposer has no other valid
tx to include. A malicious proposer could act like this to spam the block
without suffering any penalty.

To recap, a block is rejected when at least one of the following conditions is
met:

- At least one `WrapperTx` is invalid with respect to the checks listed in the
  [relative section](#wrapper-checks)
- The order/number of decrypted txs differs from the order/number committed in
  the previous block

## Possible optimizations

In this section we describe two alternative solutions that come with some
optimizations.

### Transaction counter

Instead of relying on a hash (32 bytes) we could use a 64 bits (8 bytes)
transaction counter as nonce for the wrapper and inner transactions. The
advantage is that the space required would be much less since we only need two 8
bytes values in storage for every address which is signing transactions. On the
other hand, the handling of the counter for the inner transaction will be
performed entirely in wasm (transactions and VPs) making it a bit less
efficient. This solution also imposes a strict ordering on the transactions
issued by a same address.

**NOTE**: this solution requires the ability to
[yield](https://github.com/wasmerio/wasmer/issues/1127) execution from Wasmer
which is not implemented yet.

#### InnerTx

We will implement the protection entirely in Wasm: the check of the counter will
be carried out by the validity predicates while the actual writing of the
counter in storage will be done by the transactions themselves.

To do so, the `SignedTxData` attached to the transaction will hold the current
value of the counter in storage:

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

The counter must reside in `SignedTxData` and not in the data itself because
this must be checked by the validity predicate which is not aware of the
specific transaction that took place but only of the changes in the storage;
therefore, the VP is not able to correctly deserialize the data of the
transactions since it doesn't know what type of data the bytes represent.

The counter will be signed as well to protect it from tampering and grant it the
same guarantees explained at the [beginning](#encryption-authentication) of this
document.

The wasm transaction will simply read the value from storage and increase its
value by one. The target key in storage will be the following:

```
/$Address/inner_tx_counter: u64
```

The VP of the _source_ address will then check the validity of the signature
and, if it's deemed valid, will proceed to check if the pre-value of the counter
in storage was equal to the one contained in the `SignedTxData` struct and if
the post-value of the key in storage has been incremented by one: if any of
these conditions doesn't hold the VP will discard the transactions and prevent
the changes from being applied to the storage.

In the specific case of a shielded transfer, since MASP already comes with
replay protection as part of the Zcash design (see the [MASP specs](../masp.md)
and [Zcash protocol specs](https://zips.z.cash/protocol/protocol.pdf)), the
counter in `SignedTxData` is not required and therefore should be optional.

To implement replay protection for the inner transaction we will need to update
all the VPs checking the transaction's signature to include the check on the
transaction counter: at the moment the `vp_user` validity predicate is the only
one to update. In addition, all the transactions involving `SignedTxData` should
increment the counter.

#### WrapperTx

To protect this transaction we can implement an in-protocol mechanism. Since the
wrapper transaction gets signed before being submitted to the network, we can
leverage the `tx_counter` field of the `SignedTxData` already introduced for the
inner tx.

In addition, we need another counter in the storage subspace of every address:

```
/$Address/wrapper_tx_counter: u64
```

where `$Address` is the one signing the transaction (the same implied by the
`pk` field of the `WrapperTx` struct).

The check will consist of a signature check first followed by a check on the
counter that will make sure that the counter attached to the transaction matches
the one in storage for the signing address. This will be done in the
`process_proposal` function so that validators can decide whether the
transaction is valid or not; if it's not, then they will discard the transaction
and skip to the following one.

At last, in `finalize_block`, the ledger will update the counter key in storage,
increasing its value by one. This will happen when the following conditions are
met:

- `process_proposal` has accepted the tx by validating its signature and
  transaction counter
- The tx was correctly applied in `finalize_block` (for `WrapperTx` this simply
  means inclusion in the block and gas accounting)

Now, if a malicious user tried to replay this transaction, the `tx_counter` in
the struct would no longer be equal to the one in storage and the transaction
would be deemed invalid.

#### Implementation details

In this section we'll talk about some details of the replay protection mechanism
that derive from the solution proposed in this section.

##### Storage counters

Replay protection will require interaction with the storage from both the
protocol and Wasm. To do so we can take advantage of the `StorageRead` and
`StorageWrite` traits to work with a single interface.

This implementation requires two transaction counters in storage for every
address, so that the storage subspace of a given address looks like the
following:

```
/$Address/wrapper_tx_counter: u64
/$Address/inner_tx_counter: u64
```

An implementation requiring a single counter in storage has been taken into
consideration and discarded because that would not support batching; see the
[relative section](#single-counter-in-storage) for a more in-depth explanation.

For both the wrapper and inner transaction, the increase of the counter in
storage is an important step that must be correctly executed. First, the
implementation will return an error in case of a counter overflow to prevent
wrapping, since this would allow for the replay of previous transactions. Also,
we want to increase the counter as soon as we verify that the signature, the
chain id and the passed-in transaction counter are valid. The increase should
happen immediately after the checks because of two reasons:

- Prevent replay attack of a transaction in the same block
- Update the transaction counter even in case the transaction fails, to prevent
  a possible replay attack in the future (since a transaction invalid at state
  Sx could become valid at state Sn where `n > x`)

For `WrapperTx`, the counter increase and fee accounting will per performed in
`finalize_block` (as stated in the [relative](#wrappertx) section).

For `InnerTx`, instead, the logic is not straightforward. The transaction code
will be executed in a Wasm environment ([Wasmer](https://wasmer.io)) till it
eventually completes or raises an exception. In case of success, the counter in
storage will be updated correctly but, in case of failure, the protocol will
discard all of the changes brought by the transactions to the write-ahead-log,
including the updated transaction counter. This is a problem because the
transaction could be successfully replayed in the future if it will become
valid.

The ideal solution would be to interrupt the execution of the Wasm code after
the transaction counter (if any) has been increased. This would allow performing
a first run of the involved VPs and, if all of them accept the changes, let the
protocol commit these changes before any possible failure. After that, the
protocol would resume the execution of the transaction from the previous
interrupt point until completion or failure, after which a second pass of the
VPs is initiated to validate the remaining state modifications. In case of a VP
rejection after the counter increase there would be no need to resume execution
and the transaction could be immediately deemed invalid so that the protocol
could skip to the next tx to be executed. With this solution, the counter update
would be committed to storage regardless of a failure of the transaction itself.

Unfortunately, at the moment, Wasmer doesn't allow
[yielding](https://github.com/wasmerio/wasmer/issues/1127) from the execution.

In case the transaction went out of gas (given the `gas_limit` field of the
wrapper), all the changes applied will be discarded from the WAL and will not
affect the state of the storage. The inner transaction could then be rewrapped
with a correct gas limit and replayed until the `expiration` time has been
reached.

##### Batching and transaction ordering

This replay protection technique supports the execution of multiple transactions
with the same address as _source_ in a single block. Actually, the presence of
the transaction counters and the checks performed on them now impose a strict
ordering on the execution sequence (which can be an added value for some use
cases). The correct execution of more than one transaction per source address in
the same block is preserved as long as:

1. The wrapper transactions are inserted in the block with the correct ascending
   order
2. No hole is present in the counters' sequence
3. The counter of the first transaction included in the block matches the
   expected one in storage

The conditions are enforced by the block proposer who has an interest in
maximizing the amount of fees extracted by the proposed block. To support this
incentive, validators will reject the block proposed if any of the included
wrapper transactions are invalid, effectively incentivizing the block proposer
to include only valid transactions and correctly reorder them to gain the fees.

In case of a missing transaction causes a hole in the sequence of transaction
counters, the block proposer will include in the block all the transactions up
to the missing one and discard all the ones following that one, effectively
preserving the correct ordering.

Correctly ordering the transactions is not enough to guarantee the correct
execution. As already mentioned in the [WrapperTx](#wrappertx) section, the
block proposer and the validators also need to access the storage to check that
the first transaction counter of a sequence is actually the expected one.

The entire counter ordering is only done on the `WrapperTx`: if the inner
counter is wrong then the inner transaction will fail and the signer of the
corresponding wrapper will be charged with fees. This incentivizes submitters to
produce valid transactions and discourages malicious user from rewrapping and
resubmitting old transactions.

##### Mempool checks

As a form of optimization to prevent mempool spamming, some of the checks that
have been introduced in this document will also be brought to the
`mempool_validate` function. Of course, we always refer to checks on the
`WrapperTx` only. More specifically:

- Check the `ChainId` field
- Check the signature of the transaction against the `pk` field of the
  `WrapperTx`
- Perform a limited check on the transaction counter

Regarding the last point, `mempool_validate` will check if the counter in the
transaction is `>=` than the one in storage for the address signing the
`WrapperTx`. A complete check (checking for strict equality) is not feasible, as
described in the [relative](#mempool-counter-validation) section.

#### Alternatives considered

In this section we list some possible solutions that were taken into
consideration during the writing of this solution but were eventually discarded.

##### Mempool counter validation

The idea of performing a complete validation of the transaction counters in the
`mempool_validate` function was discarded because of a possible flaw.

Suppose a client sends five transactions (counters from 1 to 5). The mempool of
the next block proposer is not guaranteed to receive them in order: something on
the network could shuffle the transactions up so that they arrive in the
following order: 2-3-4-5-1. Now, since we validate every single transaction to
be included in the mempool in the exact order in which we receive them, we would
discard the first four transactions and only accept the last one, that with
counter 1. Now the next block proposer might have the four discarded
transactions in its mempool (since those were not added to the previous block
and therefore not evicted from the other mempools, at least they shouldn't, see
[block rejection](#block-rejection)) and could therefore include them in the
following block. But still, a process that could have ended in a single block
actually took two blocks. Moreover, there are two more issues:

- The next block proposer might have the remaining transactions out of order in
  his mempool as well, effectively propagating the same issue down to the next
  block proposer
- The next block proposer might not have these transactions in his mempool at
  all

Finally, transactions that are not allowed into the mempool don't get propagated
to the other peers, making their inclusion in a block even harder. It is instead
better to avoid a complete filter on the transactions based on their order in
the mempool: instead we are going to perform a simpler check and then let the
block proposer rearrange them correctly when proposing the block.

##### In-protocol protection for InnerTx

An alternative implementation could place the protection for the inner tx in
protocol, just like the wrapper one, based on the transaction counter inside
`SignedTxData`. The check would run in `process_proposal` and the update in
`finalize_block`, just like for the wrapper transaction. This implementation,
though, shows two drawbacks:

- it implies the need for an hard fork in case of a modification of the replay
  protection mechanism
- it's not clear who's the source of the inner transaction from the outside, as
  that depends on the specific code of the transaction itself. We could use
  specific whitelisted txs set to define when it requires a counter (would not
  work for future programmable transactions), but still, we have no way to
  define which address should be targeted for replay protection (**blocking
  issue**)

##### In-protocol counter increase for InnerTx

In the [storage counter](#storage-counters) section we mentioned the issue of
increasing the transaction counter for an inner tx even in case of failure. A
possible solution that we took in consideration and discarded was to increase
the counter from protocol in case of a failure.

This is technically feasible since the protocol is aware of the keys modified by
the transaction and also of the results of the validity predicates (useful in
case the transaction updated more than one counter in storage). It is then
possible to recover the value and reapply the change directly from protocol.
This logic though, is quite dispersive, since it effectively splits the
management of the counter for the `InnerTx` among Wasm and protocol, while our
initial intent was to keep it completely in Wasm.

##### Single counter in storage

We can't use a single transaction counter in storage because this would prevent
batching.

As an example, if a client (with a current counter in storage holding value 5)
generates two transactions to be included in the same block, signing both the
outer and the inner (default behavior of the client), it would need to generate
the following transaction counters:

```
[
    T1: (WrapperCtr: 5, InnerCtr: 6),
    T2: (WrapperCtr: 7, InnerCtr: 8)
]
```

Now, the current execution model of Namada includes the `WrapperTx` in a block
first to then decrypt and execute the inner tx in the following block
(respecting the committed order of the transactions). That would mean that the
outer tx of `T1` would pass validation and immediately increase the counter to 6
to prevent a replay attack in the same block. Now, the outer tx of `T2` will be
processed but it won't pass validation because it carries a counter with value 7
while the ledger expects 6.

To fix this, one could think to set the counters as follows:

```
[
    T1: (WrapperCtr: 5, InnerCtr: 7),
    T2: (WrapperCtr: 6, InnerCtr: 8)
]
```

This way both the transactions will be considered valid and executed. The issue
is that, if the second transaction is not included in the block (for any
reason), than the first transaction (the only one remaining at this point) will
fail. In fact, after the outer tx has correctly increased the counter in storage
to value 6 the block will be accepted. In the next block the inner transaction
will be decrypted and executed but this last step will fail since the counter in
`SignedTxData` carries a value of 7 and the counter in storage has a value of 6.

To cope with this there are two possible ways. The first one is that, instead of
checking the exact value of the counter in storage and increasing its value by
one, we could check that the transaction carries a counter `>=` than the one in
storage and write this one (not increase) to storage. The problem with this is
that it the lack of support for strict ordering of execution.

The second option is to keep the usual increase strategy of the counter
(increase by one and check for strict equality) and simply use two different
counters in storage for each address. The transaction will then look like this:

```
[
    T1: (WrapperCtr: 5, InnerCtr: 5),
    T2: (WrapperCtr: 6, InnerCtr: 6)
]
```

Since the order of inclusion of the `WrapperTxs` forces the same order of the
execution for the inner ones, both transactions can be correctly executed and
the correctness will be maintained even in case `T2` didn't make it to the block
(note that the counter for an inner tx and the corresponding wrapper one don't
need to coincide).

### Wrapper-bound InnerTx

The solution is to tie an `InnerTx` to the corresponding `WrapperTx`. By doing
so, it becomes impossible to rewrap an inner transaction and, therefore, all the
attacks related to this practice would be unfeasible. This mechanism requires
even less space in storage (only a 64 bit counter for every address signing
wrapper transactions) and only one check on the wrapper counter in protocol. As
a con, it requires communication between the signer of the inner transaction and
that of the wrapper during the transaction construction. This solution also
imposes a strict ordering on the wrapper transactions issued by a same address.

To do so we will have to change the current definition of the two tx structs to
the following:

```rust
pub struct WrapperTx {
  /// The fee to be payed for including the tx
  pub fee: Fee,
  /// Used to determine an implicit account of the fee payer
  pub pk: common::PublicKey,
  /// Max amount of gas that can be used when executing the inner tx
  pub gas_limit: GasLimit,
  /// Lifetime of the transaction, also determines which decryption key will be used
  pub expiration: DateTimeUtc,
  /// Chain identifier for replay protection
  pub chain_id: ChainId,
  /// Transaction counter for replay protection
  pub tx_counter: u64,
  /// the encrypted payload
  pub inner_tx: EncryptedTx,
}

pub struct Tx {
  pub code: Vec<u8>,
  pub data: Option<Vec<u8>>,
  pub timestamp: DateTimeUtc,
  pub wrapper_commit: Option<Hash>,
}
```

The Wrapper transaction no longer holds the inner transaction hash while the
inner one now holds a commit to the corresponding wrapper tx in the form of the
hash of a `WrapperCommit` struct, defined as:

```rust
pub struct WrapperCommit {
  pub pk: common::PublicKey,
  pub tx_counter: u64,
  pub expiration: DateTimeUtc,
  pub chain_id: ChainId,
}
```

The `pk-tx_counter` couple contained in this struct, uniquely identifies a
single `WrapperTx` (since a valid tx_counter is unique given the address) so
that the inner one is now bound to this specific wrapper. The remaining fields,
`expiration` and `chain_id`, will tie these two values given their importance in
terms of safety (see the [relative](#wrappertx-checks) section). Note that the
`wrapper_commit` field must be optional because the `WrapperTx` struct itself
gets converted to a `Tx` struct before submission but it doesn't need any
commitment.

Both the inner and wrapper tx get signed on their hash, as usual, to prevent
tampering with data. When a wrapper gets processed by the ledger, we first check
the validity of the signature, checking that none of the fields were modified:
this means that the inner tx embedded within the wrapper is, in fact, the
intended one. This last statement means that no external attacker has tampered
data, but the tampering could still have been performed by the signer of the
wrapper before signing the wrapper transaction.

If this check (and others, explained later in the [checks](#wrappertx-checks)
section) passes, then the inner tx gets decrypted in the following block
proposal process. At this time we check that the order in which the inner txs
are inserted in the block matches that of the corresponding wrapper txs in the
previous block. To do so, we rely on an in-storage queue holding the hash of the
`WrapperCommit` struct computed from the wrapper tx. From the inner tx we
extract the `WrapperCommit` hash and check that it matches that in the queue: if
they don't it means that the inner tx has been reordered and we reject the
block.

If this check passes then we can send the inner transaction to the wasm
environment for execution: if the transaction is signed, then at least one VP
will check its signature to spot possible tampering of the data (especially by
the wrapper signer, since this specific case cannot be checked before this step)
and, if this is the case, will reject this transaction and no storage
modifications will be applied.

In summary:

- The `InnerTx` carries a unique identifier of the `WrapperTx` embedding it
- Both the inner and wrapper txs are signed on all of their data
- The signature check on the wrapper tx ensures that the inner transaction is
  the intended one and that this wrapper has not been used to wrap a different
  inner tx. It also verifies that no tampering happened with the inner
  transaction by a third party. Finally, it ensures that the public key is the
  one of the signer
- The check on the `WrapperCommit` ensures that the inner tx has not been
  reordered nor rewrapped (this last one is a non-exhaustive check, inner tx
  data could have been tampered with by the wrapper signer)
- The signature check of the inner tx performed in Vp grants that no data of the
  inner tx has been tampered with, effectively verifying the correctness of the
  previous check (`WrapperCommit`)

This sequence of controls makes it no longer possible to rewrap an `InnerTx`
which is now bound to its wrapper. This implies that replay protection is only
needed on the `WrapperTx` since there's no way to extract the inner one, rewrap
it and replay it.

#### WrapperTx checks

In `mempool_validation` we will perform some checks on the wrapper tx to
validate it. These will involve:

- Valid signature
- `GasLimit` is below the block gas limit (see the
  [fee specs](../economics/fee-system.md) for more details)
- `Fees` are paid with an accepted token and match the minimum amount required
  (see the [fee specs](../economics/fee-system.md) for more details)
- Valid chainId
- Valid transaction counter
- Valid expiration

These checks can all be done before executing the transactions themselves. If
any of these fails, the transaction should be considered invalid and the action
to take will be one of the followings:

1. If the checks fail on the signature, chainId, expiration or transaction
   counter, then this transaction will be forever invalid, regardless of the
   possible evolution of the ledger's state. There's no need to include the
   transaction in the block nor to increase the transaction counter. Moreover,
   we **cannot** include this transaction in the block to charge a fee (as a
   sort of punishment) because these errors may not depend on the signer of the
   tx (could be due to malicious users or simply a delay in the tx inclusion in
   the block)
2. If the checks fail on `Fee` or `GasLimit` the transaction should be
   discarded. In theory the gas limit of a block is a Namada parameter
   controlled by governance, so there's a chance that the transaction could
   become valid in the future should this limit be raised. The same applies to
   the token whitelist and the minimum fee required. However we can expect a
   slow rate of change of these parameters so we can reject the tx (the
   submitter can always resubmit it at a future time)
3. If all the checks pass validation we will include the transaction in the
   block to increase the counter and charge the fee

Note that, regarding point one, there's a distinction to be made about an
invalid `tx_counter` which could be invalid because of being old or being in
advance. To solve this last issue (counter greater than the expected one), we
have to introduce the concept of a lifetime (or timeout) for the transactions:
basically, the `WrapperTx` will hold an extra field called `expiration` stating
the maximum time up until which the submitter is willing to see the transaction
executed. After the specified time the transaction will be considered invalid
and discarded regardless of all the other checks. This way, in case of a
transaction with a counter greater than expected, it is sufficient to wait till
after the expiration to submit more transactions, so that the counter in storage
is not modified (kept invalid for the transaction under observation) and
replaying that tx would result in a rejection.

This actually generalizes to a more broad concept. In general, a transaction is
valid at the moment of submission, but after that, a series of external factors
(ledger state, etc.) might change the mind of the submitter who's now not
interested in the execution of the transaction anymore. By introducing this new
field we are introducing a new constraint in the transaction's contract, where
the ledger will make sure to prevent the execution of the transaction after the
deadline and, on the other side, the submitter commits himself to the result of
the execution at least until its expiration. If the expiration is reached and
the transaction has not been executed the submitter can decide to submit a new,
identical transaction if he's still interested in the changes carried by it.

In our design, the `expiration` will hold until the transaction is executed,
once it's executed, either in case of success or failure, the `tx_counter` will
be increased and the transaction will not be replayable. In essence, the
transaction submitter commits himself to one of these three conditions:

- Transaction is invalid regardless of the specific state
- Transaction is executed (either with success or not) and the transaction
  counter is increased
- Expiration time has passed

The first condition satisfied will invalidate further executions of the same tx.

Since the signer of the wrapper may be different from the one of the inner we
also need to include this `expiration` field in the `WrapperCommit` struct, to
prevent the signer of the wrapper from setting a lifetime which is in conflict
with the interests of the inner signer. Note that adding a separate lifetime for
the wrapper alone (which would require two separate checks) doesn't carry any
benefit: a wrapper with a lifetime greater than the inner would have no sense
since the inner would fail. Restricting the lifetime would work but it also
means that the wrapper could prevent a valid inner transaction from being
executed. We will then keep a single `expiration` field specifying the wrapper
tx max time (the inner one will actually be executed one block later because of
the execution mechanism of Namada).

To prevent the signer of the wrapper from submitting the transaction to a
different chain, the `ChainId` field should also be included in the commit.

Finally, in case the transaction run out of gas (based on the provided
`GasLimit` field of the wrapper) we don't need to take any action: by this time
the transaction counter will have already been incremented and the tx is not
replayable anymore. In theory, we don't even need to increment the counter since
the only way this transaction could become valid is a change in the way gas is
accounted, which might require a fork anyway, and consequently a change in the
required `ChainId`. However, since we can't tell the gas consumption before the
inner tx has been executed, we cannot anticipate this check.

All these checks are also run in `process_proposal` with an addition: validators
also check that the wrapper signer has enough funds to pay the fee. This check
should not be done in mempool because the funds available for a certain address
are variable in time and should only be checked at block inclusion time. If any
of the checks fail here, the entire block is rejected forcing a new Tendermint
round to begin (see a better explanation of this choice in the
[relative](#block-rejection) section).

The `expiration` parameter also justifies that the check on funds is only done
in `process_proposal` and not in mempool. Without it, the transaction could be
potentially executed at any future moment, possibly going against the mutated
interests of the submitter. With the expiration parameter, now, the submitter
commits himself to accept the execution of the transaction up to the specified
time: it's going to be his responsibility to provide a sensible value for this
parameter. Given this constraint the transaction will be kept in mempool up
until the expiration (since it would become invalid after that in any case), to
prevent the mempool from increasing too much in size.

This mechanism can also be applied to another scenario. Suppose a transaction
was not propagated to the network by a node (or a group of colluding nodes).
Now, this tx might be valid, but it doesn't get inserted into a block. Without
an expiration, if the submitter doesn't submit any other transaction (which gets
included in a block to increase the transaction counter), this tx can be
replayed (better, applied, since it was never executed in the first place) at a
future moment in time when the submitter might not be willing to execute it any
more.

#### WrapperCommit

The fields of `WrapperTx` not included in `WrapperCommit` are at the discretion
of the `WrapperTx` producer. These fields are not included in the commit because
of one of these two reasons:

- They depend on the specific state of the wrapper signer and cannot be forced
  (like `fee`, since the wrapper signer must have enough funds to pay for those)
- They are not a threat (in terms of replay attacks) to the signer of the inner
  transaction in case of failure of the transaction

In a certain way, the `WrapperCommit` not only binds an `InnerTx` no a wrapper,
but effectively allows the inner to control the wrapper by requesting some
specific parameters for its creation and bind these parameters among the two
transactions: this allows us to apply the same constraints to both txs while
performing the checks on the wrapper only.

#### Transaction creation process

To craft a transaction, the process will now be the following (optional steps
are only required if the signer of the inner differs from that of the wrapper):

- (**Optional**) the `InnerTx` constructor request, to the wrapper signer, his
  public key and the `tx_counter` to be used
- The `InnerTx` is constructed in its entirety with also the `wrapper_commit`
  field to define the constraints of the future wrapper
- The produced `Tx` struct get signed over all of its data (with `SignedTxData`)
  producing a new struct `Tx`
- (**Optional**) The inner tx produced is sent to the `WrapperTx` producer
  together with the `WrapperCommit` struct (required since the inner tx only
  holds the hash of it)
- The signer of the wrapper constructs a `WrapperTx` compliant with the
  `WrapperCommit` fields
- The produced `WrapperTx` gets signed over all of its fields

Compared to a solution not binding the inner tx to the wrapper one, this
solution requires the exchange of 3 messages (request `tx_counter`, receive
`tx_counter`, send `InnerTx`) between the two signers (in case they differ),
instead of one. However, it allows the signer of the inner to send the `InnerTx`
to the wrapper signer already encrypted, guaranteeing a higher level of safety:
only the `WrapperCommit` struct should be sent clear, but this doesn't reveal
any sensitive information about the inner transaction itself.
