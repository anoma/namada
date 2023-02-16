# Fee system

In order to be accepted by the Namada ledger, transactions must pay fees.
Transaction fees serve two purposes: first, the efficient allocation of block
space and gas (which are scarce resources) given permissionless transaction
submission and varying demand, and second, incentive-compatibility to encourage
block producers to add transactions to the blocks which they create and publish.

Namada transaction fees can be paid in any fungible token which is a member of a
whitelist controlled by Namada governance. Governance also sets minimum fee
rates (which can be periodically updated so that they are usually sufficient)
which transactions must pay in order to be accepted (but they can always pay
more to encourage the proposer to prioritize them). When using the shielded
pool, transactions can also unshield tokens in order to pay the required fees.

The token whitelist consists of a list of $(T, GP_{min})$ pairs, where $T$ is a
token identifier and $GP_{min}$ is the minimum (base) price per unit gas which
must be paid by a transaction paying fees using that asset. This whitelist can
be updated with a standard governance proposal. All fees collected are paid
directly to the block proposer (incentive-compatible, so that side payments are
no more profitable).

## Fee payment

The `WrapperTx` struct holds all the data necessary for the payment of fees in
the form of the types: `Fee`, `GasLimit` and the `PublicKey` used to derive the
address of the fee payer which coincides with the signer of the wrapper
transaction itself.

Since fees have a purpose in allocating scarce block resources (space and gas
limit) they have to be paid upfront, as soon as the transaction is deemed valid
and accepted into a block (refer to
[replay protection specs](../base-ledger/replay-protection.md) for more details
on transactions' validity). Moreover, for the same reasons, the fee payer will
pay for the entire `GasLimit` allocated and not the actual gas consumed for the
transaction: this will incentivize fee payers to stick to a reasonable gas limit
for their transactions allowing for the inclusion of more transactions into a
block. Since the gas used by a transaction leaks a bit of information about the
transaction itself, a submitter may want to obfuscate this value a bit by
increasing the gas limit of the wrapper transaction (refer to section 2.1.3 of
the Ferveo [documentation](https://eprint.iacr.org/2022/898.pdf)).

Fees are not distributed among the validators who actively participate in the
block validation process. This is because a tx submitter could be side-paying
the block proposer for tx inclusion which would prevent the correct distribution
of fees among validators. The fair distribution of fees is enforced by the
stake-proportional block proposer rotation policy of Tendermint.

By requesting an upfront payment, fees also serve as prevention against DOS
attacks since the signer needs to pay for all the submitted transactions. More
specifically, to serve as a denial-of-service and spam prevention mechanism, the
fee system needs to enforce:

1. **Successful** payment at block inclusion time (implying the ability to check
   the good outcome at block creation time)
2. Minimal payment overhead in terms of computation/memory requirements
   (otherwise fee payment itself could be exploited as a DOS vector)

Given that transactions are executed in the same order they appear in the block,
block proposers will tend to a common behavior: they'll place all the wrapper
transactions before the decrypted transactions coming from the previous block.
By doing this, they will make sure to prevent inner transactions from draining
the addresses of the funds needed to pay fees. The proposers will be able to
check in advance that fee payers have enough unshielded funds and, if this is
not the case, exclude the transaction from the block and leave it in the mempool
for future inclusion. This behavior ultimately leads to more resource-optimized
blocks.

As a drawback, this behavior could cause some inner txs coming from the previous
block to fail (in case they involve an unshielded transfer) because funds have
been moved to the block proposer as a fee payment for a `WrapperTx` included in
the same block. This is somehow undesirable since inner transactions' execution
should have priority over the wrapper. There are two ways to overcome this
issue:

1. Users are responsible for correctly timing/funding their transactions with
   the help of the wallet
2. Namada forces in protocol that a block should list the wrappers after the
   decrypted transactions

If we follow the second option the block proposers will no more be able to
optimize the block (this would require running the inner transactions to
calculate the possibly new unshielded balance) and, inevitably, some wrapper
transactions for which fees cannot be paid will end up in the block. These will
be deemed invalid during validation so that the corresponding inner transaction
will not be executed, preserving the correctness of the state machine, but it
represents a slight underoptimization of the block and a potential vector for
DOS attacks since the invalid wrapper has allocated space and gas in the block
without being charged due to the lack of funds. Because of this, we stick to the
first option.

Fees are collected via protocol for `WrapperTx`s which have been processed with
success: this is to prevent a malicious block proposer from including
transactions that are known in advance to be invalid just to collect more fees.
Given the two-block execution model of Namada (wrapper and inner tx) and the
need to collect fees for the allocated resources, nothing can be done in case
the inner transaction fails: by that point, fees have already been collected and
no refunds will be issued, meaning that the inner tx signer is responsible for
submitting a semantically valid transaction for the state of the application
(importance on the lifetime parameter of the tx here).

Since a signer might submit more than one transaction per block, the
`process_proposal` function needs to cache the updated unshielded balance to
correctly manage fees. To guarantee that the results coming from this process
are correct, Namada imposes that **all the wrapper transactions in a block are
listed before the inner transactions**. This is already the expected behavior of
the block proposers (as stated before) but we need to enforce it in protocol: if
this wasn't the case, an inner transaction placed in between wrappers could
modify a balance involved in fee payment, leading to a miscalculation of the
balance itself which would cause a late rejection of the block in
`finalize_block`.

If enough funds are available, these are deducted from the unshielded storage
balances of the fee payers and directed to the balance of the block proposer. If
instead, the balance is not enough to cover fees, then the proposed block is
considered invalid and rejected, the WAL is discarded and a new Tendermint round
is initiated.

To support the in-protocol fee payment mechanism we need to update the `Header`
struct to carry the `ProposerAddress`:

```rust
/// The data from Tendermint header
/// relevant for Anoma storage
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Header {
  /// Merkle root hash of block
  pub hash: Hash,
  /// Timestamp associated to block
  pub time: DateTimeUtc,
  /// Hash of the addresses of the next validator set
  pub next_validators_hash: Hash,
  /// Address of the block proposer
  pub proposer_address: Address
}
```

From this address, it is then possible to derive the relative Namada address for
the payment.

The `Fee` field of `WrapperTx` is defined as follows:

```rust
pub struct Fee {
  /// amount of the fee
  pub amount: Amount,
  /// address of the token
  pub token: Address,
}
```

The signer of the wrapper transaction defines the token in which fees must be
paid among those available in the token whitelist. At the same time, he also
sets the amount which must meet the minimum price per gas unit for that token,
$GP_{min}$ (also defined in the whitelist). The difference between the minimum
and the actual value set by the submitter represents the incentive for the block
proposer to prefer the inclusion of this transaction over other ones.

The block proposer can check the validity of these two parameters while
constructing the block. These validity checks are also replicated in
`process_proposal` and `mempool_check`. In case a transaction with invalid
parameters ended up in a block, the entire block would be rejected (as already
explained earlier in this document). As mentioned before, a signer might submit
more than one transaction per block and the proposer should take into
consideration the updated value of the unshielded balance.

Since the whitelist can be changed via governance, transactions could fail these
checks in the block where the whitelist change happens. For `mempool_check`, the
checks could reject transactions that may become valid in the future or
vice-versa: since we can assume a slow rate of change for these parameters and
mempool and block space optimizations are a priority, it is up to the clients to
track any changes in these parameters and act accordingly.

### Unshielding

To provide improved privay, Namada allows the signer of the wrapper transaction
to unshield some funds on the go to cover the cost of the fee. This also
addresses a possible locked-out problem in which a user doesn't have enough
funds to pay fees (preventing any sort of operation on the chaind). The
`WrapperTx` struct must be extended as follows:

```rust
pub struct WrapperTx {
  /// The fee to be paid for including the tx
  pub fee: Fee,
  /// Used to determine an implicit account of the fee payer
  pub pk: common::PublicKey,
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
```

The new `unshield` field carries an optional tx encoding for an unshielding
`Transfer`. The unshielding operation is exempt from paying fees and doesn't
charge gas.

The proposer and the validators must also check the validity of the optional
unshielding transfer attached to the wrapper. More specifically the correctness
implies that:

1. The unshielding provides just the right amount of funds to pay fees
2. The actual wasm execution runs successfully

The first condition can be tested statically and requires that:

1. The tx encodes a `Transfer`
2. The `shielded` field must be set to `Some`
3. The `source` address must be the masp. The `target` address matches that of
   the wrapper signer
4. The `token` match the one specified in the `Fee` struct
5. The `amount`, added to the already available unshielded balance for that
   token, is just enough to cover the fees, i.e. the value given by
   $Fee.amount * GasLimit$ (to prevent leveraging this transfer for other
   purposes)

The spending key associated with this operation could be relative to any address
as long as the signature of the transfer itself is valid.

If any of the checks fail, the transaction must be discarded. Once these
controls have been performed, the block proposer should run the actual transfer
against the current state of the application to check whether the transaction is
valid or not: if this succeeds the transaction can be included in the block,
otherwise it should be discarded.

These same checks are done by the validators in `process_proposal`: if any of
them fail, the entire block is rejected. The balance key must be searched in the
local cache before the storage to ensure a correct computation in case of
transactions involving the same addresses.

### Governance proposals

Governance [proposals](../base-ledger/governance.md) may carry some wasm code to
be executed in case the proposal passed. This code is embedded into a
`DecryptedTx` directly by the validators at block processing time and is not
inserted into the block itself. These transactions are exempt from fees and
don't charge gas.

### Protocol transactions

Protocol transactions can only be correctly crafted by validators and serve a
role in allowing the chain to function properly. Given these, they are not
subject to fees and do not charge gas.

## Gas accounting

Gas must take into account the two scarce resources of a block: gas and space.

Regarding the space limit, Namada charges, for every `WrapperTx`, a fixed amount
of gas per byte.

For the gas limit, we provide a mapping between all the whitelisted transactions
and VPs to their cost in gas units: more specifically, the cost of a tx/VP is
given by the run time cost of its wasm code. As the cost is constant, it is
guaranteed that the same transaction will always require the same amount of gas:
since the price per gas unit is controlled via governance, though, the price for
the same transaction may vary in time. A transaction is also charged with the
gas required by the validity predicates that it triggers.

In addition to these, each inner transaction spends gas for compilation costs
(of both the tx and the associated, non-native, VPs) which are charged even if
the compiled transactions was already available in cache, and ancillaries
operations (like loading non-native VP codes from storage).

To summarize, the gas for a given wrapper transaction can be computed as:

$$WrapperGas = TxSize + FixedRuntimeGas + TxCodeSize + MiscOpsGas$$

Gas accounting is about preventing a transaction from exceeding two gas limits:

1. Its own `GasLimit` (declared in the wrapper transaction)
2. The gas limit of the entire block

### Wrapper GasLimit

The protocol injects a gas counter in each transaction and VP to be executed
which allows monitoring of the exact amount of gas utilized. To do so, the gas
meter simply checks the hash of the transaction or VP against the table in
storage to determine which one it is and, from there, derives the amount of gas
required.

To perform the check we need the limit which was declared by the corresponding
wrapper transaction: this can be recovered from the queue of `WrapperTx`s in
storage.

Since the hash can be retrieved as soon as the transaction gets decrypted, we
can immediately check whether the `GasLimit` set in the corresponding wrapper is
enough to cover this amount. This check, though, is weak because we also need to
keep in account the gas required for the involved VPs which is hard to determine
ahead of time: this is just an optimization to short-circuit the execution of
transactions whose gas limit is not enough to cover even the tx itself.

When executing the VPs in parallel the procedure is the same and, again, since
we know ahead of time the gas required by each VP we can immediately terminate
the execution if it overshoots the limit.

In any case, if the gas limit is exceeded, the transaction is considered invalid
and all the modifications applied to the WAL get discarded. This doesn't affect
the other transactions which can be executed normally (see the following
section).

### Block GasLimit

This constraint is given by the following two:

- The compliance of each inner transaction with the `WrapperTx` gas limit
  explained in the previous section
- The compliance of the cumulative wrapper transactions' `GasLimit` with the
  maximum gas allowed for a block

Tendermint doesn't provide more than the `BlockSize.MaxGas` parameter, leaving
the validation step to the application (see
[tendermint spec](https://github.com/tendermint/tendermint/blob/29e5fbcc648510e4763bd0af0b461aed92c21f30/spec/core/data_structures.md#consensusparams)
and [this issue](https://github.com/tendermint/tendermint/issues/2310)):
therefore, instead of using the Tendermint provided param, Namada introduces a
`MaxBlockGas` protocol parameter. This limit is checked during block validation,
in `process_proposal`: if the block exceeds the maximum amount of gas allowed,
the validators will reject it.

Note that block gas limit validation should always occur against the `GasLimit`
declared in the wrappers, not the real gas used by the inner transactions. If
this was the case, in fact, a malicious proposer could craft a block exceeding
the gas limit with the hope that some transactions may use less gas than
declared: if this doesn't happen, the last transactions of the block will be
rejected because they would exceed the block gas limit even though they were
charged fees in the previous block, effectively suffering economic damage. In
this sense, since the wrapper tx gas limit imposes an economic constraint, it is
the reference point for all the gas limit checks.

Given that the block allocates a certain gas for each transaction and that
transactions are prevented from going out of gas, it derives that the execution
of each transaction is isolated from all the other ones in terms of gas, which
explains the last statement of the previous section.

## Checks

This section summarizes the checks performed in protocol.

| Method                          | Checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | If check fails         |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| `CheckTx` and `ProcessProposal` | <ul><li> Each wrapper tx `GasLimit` doesn't surpass `MaxBlockGas` protocol parameter</li><li> Fees are paid with a whitelisted token and meet the minimum amount required of fee per unit of gas</li><li>If unshielding: <ul><li>tx data must deserialize to `Transfer`</li><li>`source` must be the masp</li><li>`target` must match the wrapper signer</li><li>`token` must match the `Fee` one</li><li>`amount` is the minimum required</li><li>the transfer must run successfully</li></ul><li>Paying address has enough funds to cover fee</li></li></ul> | Reject the block       |
| `ProcessProposal`               | <ul><li>Wrapper transactions are listed before decrypted transactions</li><li>Cumulated `GasLimit` isn't greater than the `MaxBlockGas` parameter</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                    | Reject the block       |
| `FinalizeBlock`                 | <ul><li>For every tx, gas used isn't greater than the `GasLimit` allocated in the corresponding wrapper</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                              | Reject the transaction |

## Alternatives considered

### Inter-chain fee payment

One may want to pay fees for a `WrapperTx` on Namada with some funds kept on a
different chain that can communicate with Namada, so either Ethereum or an
IBC-compatible chain.

This solution, though, has the following drawbacks:

- Require an internal address (with the corresponding VP) as a target of the
  payment (cannot pay to the block proposer directly)
- Since the payment must be initiated from another chain it must happen at least
  one block ahead of the wrapper transaction for which it's paying the fee. This
  means that the fee payment effectively happens in advance and we would need a
  mechanism to map a payment to a specific wrapper transaction
- The payer would be an address outside of Namada which could be a problem in
  terms of accountability

Moreover, this technique is already feasible: it is sufficient to move funds
from the external chain to an address on the Namada chain which requires the
same amount of operations and the same costs.

So, at the cost of increased complexity of the Namada logic, this type of
payment doesn't actually introduce any new feature.

### Shielded fee payment

Shielded fee payment should not be supported since that would make it impossible
for validator nodes to check the correctness of the payment: they could only
check that the transaction run without errors but would not be able to determine
the exact amount paid (which must match the `GasLimit`) and the token involved
(must be a whitelisted one).
