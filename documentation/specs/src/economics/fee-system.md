# Fee system

In order to be accepted by the Namada ledger, transactions must pay fees. Transaction fees serve two purposes: first, the efficient allocation of block space and gas (which are scarce resources) given permissionless transaction submission and varying demand, and second, incentive-compatibility to encourage block producers to add transactions to the blocks which they create and publish.

Namada transaction fees can be paid in any fungible token which is a member of a whitelist controlled by Namada governance. Governance also sets minimum fee rates (which can be periodically updated so that they are usually sufficient) which transactions must pay in order to be accepted (but they can always pay more to encourage the proposer to prioritize them). When using the shielded pool, transactions can also unshield tokens in order to pay the required fees.

The token whitelist consists of a list of $(T, GP_{min})$ pairs, where $T$ is a token identifier and $GP_{min}$ is the minimum (base) price per unit gas which must be paid by a transaction paying fees using that asset. This whitelist can be updated with a standard governance proposal. All fees collected are paid directly to the block proposer (incentive-compatible, so that side payments are no more profitable).

Fees are distributed among the delegators with the mechanism explained in the [POS](./proof-of-stake/reward-distribution.md) specs.

Fees are only meant for `InnerTx` transactions: `WrapperTx`s are not subject to them.

## Fee payment

The `WrapperTx` struct holds all the data necessary for the payment of fees in the form of the types: `Fee`, `GasLimit` and the `PublicKey` used to derive the address of the fee payer which coincides with the signer of the wrapper transaction itself.

Since fees have a purpose in allocating scarce block resources (space and gas limit) they have to be paid upfront, as soon as the transaction is deemed valid and accepted into a block (refer to [replay protection](../base-ledger/replay-protection.md) specs for more details on transactions' validity). Moreover, for the same reasons, the fee payer will pay for the entire `GasLimit` allocated and not the actual gas consumed for the transaction: this will incentivize fee payers to stick to a reasonable gas limit for their transactions allowing for the inclusion of more transactions into a block. Since the gas used by a transaction leaks a bit of information about the transaction itself: a submitter may want to obfuscate this value a bit by increasing the gas limit of the wrapper transaction but he will be charged for this (refer to section 2.1.3 of the Ferveo [documentation](https://eprint.iacr.org/2022/898.pdf)).

Fees are not distributed among the validators who actively participate in the block validation process. This is because a tx submitter could be side-paying the block proposer for tx inclusion which would prevent the correct distribution of fees among validators. The fair distribution of fees is enforced by the block proposer rotation policy of Tendermint.

By requesting an upfront payment, fees also serve as prevention against DOS attacks since the signer needs to pay for all the submitted transactions. More specifically, to serve as a denial-of-service and spam prevention mechanism, fee payment needs to enforce:

1. **Succesful** payment at block inclusion time (implying the ability to check the good outcome at block creation time)
2. Minimal payment overhead in terms of computation/memory requirements (otherwise fee payment itself could be exploited as a DOS vector)

Given that transactions are executed in the same order they appear in the block this will lead to a common behavior across all the block proposers: they'll tend to place all the wrapper transactions before the decrypted transactions coming from the previous block. By doing this, they will make sure to prevent inner transactions from draining the addresses of the funds needed to pay fees. The proposer will be able to check in advance that fee payers have enough unshielded funds and, if this is not the case, exclude the transaction from the block and leave it in the mempool for future inclusion. This behavior ultimately leads to more resource-optimized blocks. 

As a drawback, this behavior could cause some inner txs coming from the previous block to fail (in case they involve an unshielded transfer) because funds have been moved to the block proposer as a fee payment for a `WrapperTx` included in the same block. This is somehow undesirable since inner transactions' execution should have priority over the wrapper. There are two ways to overcome this issue:

1. Users are responsible for correctly timing/funding their transactions with the help of the wallet
2. We force in protocol that a block should list the wrappers after the decrypted transactions

If we follow the second option the block proposers will no more be able to optimize the block (this would require running the inner transactions to calculate the possibly new unshielded balance) and, inevitably, some wrapper transactions for which fees cannot be paid will end up in the block. These will be deemed invalid during validation so that the corresponding inner transaction will not be executed, preserving the correctness of the state machine, but it represents a slight underoptimization of the block and a potential vector for DOS attacks since the invalid wrapper has allocated space and gas in the block without being charged due to the lack of funds. Because of this, we stick to the first option by not imposing any specific order in procotol.

Fees are collected via protocol, in the `finalize_block` function, for `WrapperTx`s which have been processed with success: this is to prevent a malicious block proposer from including transactions that are known in advance to be invalid just to collect more fees. Given the two-block execution model of Namada (wrapper and inner tx) and the need to collect fees for the allocated resources, nothing can be done in case the inner transaction fails: by that point, fees have already been collected and no refunds will be issued, meaning that the inner tx signer is responsible for submitting a semantically valid transaction for the state of the application (importance on the lifetime parameter of the tx here). If enough funds are available, these are deducted from the unshielded storage balances of the fee payers and directed to the balance of the block proposer: payers (wrapper tx signers) are responsible for keeping enough unshielded funds for their transactions. If instead, the balance is not enough to cover fees, then the corresponding inner transaction gets discarded and no funds are moved from the payer address to the block proposer. This is due to the following reasons:

- It would penalize the tx submitter who might not be responsible for the lack of funds at that moment
- Moving insufficient funds would incentivize the block proposer to include transactions for which fees cannot be paid. Since the block proposer knows the balances of the involved addresses at block creation time and given the strategy of placing wrapper txs first, this would constitute malicious behavior by the proposer

By discarding the transaction without paying fees instead we avoid these pitfalls. This logic implies that the strategy of placing wrapper transactions before any decrypted tx in the block will be reinforced. It might look like a contradiction to what was said before, a wrapper transaction included in a block will not pay fees for the resources it acquired, but this is not true:

- An address might have no funds at all making it impossible to perform any payment
- The only actor with an interest in managing block resources is the block proposer who's aware of the balances of the involved addresses

To support the in-protocol fee payment mechanism we need to update the `Header` struct to carry the `ProposerAddress`:

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

From this address, it is then possible to derive the relative Namada address for the payment.

The `Fee` field of `WrapperTx` is defined as follows:

```rust
pub struct Fee {
    /// amount of the fee
    pub amount: Amount,
    /// address of the token
    pub token: Address,
}
```

The signer of the wrapper transaction defines the token in which fees must be paid among those available in the token whitelist. At the same time, he also sets the amount which must meet the minimum price per gas unit for that token $GP_{min}$ (also defined in the whitelist). The difference between the minimum and the actual value set by the submitter represents the incentive for the block proposer to prefer the inclusion of this transaction over other ones.

The block proposer can check the validity of these two parameters while constructing the block. These validity checks are also replicated in `process_proposal` and `mempool_check`. In case a transaction with invalid parameters ended up in a block, it would be discarded without paying any fee (as already explained earlier in this document). The block proposer and the `process_proposal` function should also cache the available funds of every fee-paying address involved in the block: this is because a signer might submit more than one transaction per block and the check on funds should take into consideration the updated value of the unshielded balance.

Since the whitelist can be changed via governance, transactions could fail these checks in the block where the whitelist change happens. For `mempool_check`, the checks could reject transactions that may become valid in the future or vice-versa: since we can assume a slow rate of change for these parameters and mempool and block space optimizations are a priority, it is up to the clients to track any changes of these parameters and act accordingly.

## Gas accounting

We provide a mapping between all the whitelisted transactions and VPs to their cost in gas units. Being the cost hardcoded, it is guaranteed that the same transaction will always require the same amount of gas: since the price per gas is controlled via governance, though, the price for the same transaction may vary in time. A transaction is also charged with the gas required by the validity predicates that it triggers.

Gas accounting is about preventing a transaction from exceeding two gas limits:

1. Its own `GasLimit` (declared in the wrapper transaction)
2. The gas limit of the entire block

### Wrapper GasLimit

The protocol injects a gas counter in each transaction and VP to be executed which allows monitoring of the exact amount of gas utilized. To do so, the gas meter simply checks the hash of the transaction or VP against the table in storage to determine which one it is and, from there, derives the amount of gas required.

To perform the check we need the limit which was declared by the corresponding wrapper transaction: this limit should be saved in storage together with the queue of encrypted transactions for easy access.

Since the hash can be retrieved as soon as the transaction gets decrypted, we can immediately check whether the `GasLimit` set in the corresponding wrapper is enough to cover this amount. This check, though, is weak because we also need to keep in account the gas required for the involved VPs which is hard to determine ahead of time: this is just an optimization to short-circuit the execution of transactions whose gas limit is not enough to cover for even the tx itself.

When executing the VPs the procedure is the same and, again, since we know ahead of time the gas required by each VP we can immediately terminate the execution if it overshoots the limit.

In any case, if the gas limit is exceeded, the transaction is considered invalid and all the modifications applied to the WAL get discarded. This doesn't affect the other transactions which can be executed normally (see the following section).

### Block GasLimit

This constraint is given by the following two:

- The compliance of each inner transaction with the `WrapperTx` gas limit explained in the previous section
- The compliance of the cumulative wrapper transactions' `GasLimit` with the maximum gas allowed for a block

Tendermint doesn't provide more than the `BlockSize.MaxGas` parameter, leaving the validation step to the application (see [tendermint spec](https://github.com/tendermint/tendermint/blob/29e5fbcc648510e4763bd0af0b461aed92c21f30/spec/core/data_structures.md#consensusparams) and [issue](https://github.com/tendermint/tendermint/issues/2310)): therefore, instead of using the Tendermint provided param, Namada introduces a `MaxBlockGas` protocol parameter.
This limit is checked during block validation, in `process_proposal`: if the block exceeds the maximum amount of gas allowed, the validators will still accept the block and discard only the excess transactions.

Note that block gas limit validation should always occur against the `GasLimit` declared in the wrappers, not the real gas used by the inner transactions. If this was the case, in fact, a malicious proposer could craft a block exceeding the gas limit with the hope that some transaction may use less gas than declared: but if this doesn't happen, then the last transactions of the block will be rejected because they would exceed the block gas limit even though they were charged with fees in the previous block, effectively suffering economic damage. In this sense, since the wrapper tx gas limit imposes an economic constraint, it is the reference point for all the gas limit checks.

Given that the block allocates a certain gas for each transaction and that transactions are prevented from going out of gas, it derives that the execution of each transaction is isolated from all the other ones in terms of gas, which explains the last statement of the previous section.

## Checks

This section summarizes the checks performed in protocol.



|Method|Checks|
|---|---|
|`CheckTx` and `ProcessProposal`| <ul><li> Each wrapper tx `GasLimit` doesn't surpass `MaxBlockGas` protocol parameter</li><li> Fees are paid with a whitelisted token and meet the minimum amount required of fee per unit of gas</li></ul>|
|`ProcessProposal`|<ul><li>Paying address has enough funds to cover fee</li><li>Cumulated `GasLimit` isn't greater than the `MaxBlockGas` parameter</li></ul>|
|`FinalizeBlock`| <ul><li>For every tx, gas used isn't greater than the `GasLimit` allocated in the corresponding wrapper</li></ul>|

## Alternatives considered

A drawback of the proposed implementation is that fee payment can only occur from an unshielded balance. This restricts the sources from which a user can gather the funds necessary for the transaction and may also cause a locked-out problem in which a user finds himself with no more unshielded funds, making it impossible for him to operate on the chain. In this case, the user could always reach out to another user to sign wrapper txs for him (ideally to unshield some tokens).

An alternative solution could be to allow the signer of a wrapper to perform a transfer transaction to pay fees. To do so we would need the `WrapperTx` struct to hold a signed `Transfer` struct in plaintext carrying all the information regarding the transfer. The transaction itself can be crafted in protocol by validators to reduce the burden of the messages on the network and to prevent users from including arbitrary transactions. Since the block proposer is not known ahead of time, we would also need to implement a new internal address with the relative VP to which users should pay the fees. The block proposer could then redeem the tokens from there. This mechanism could function in two ways:

1. The internal VP prevents any movement of funds from the internal address and the withdraws happen via protocol
2. The internal VP has a way to retrieve the current block proposer and allows only him to withdraw. The block proposer then inserts a last transaction in the block (without going out of gas or size) to redeem all of the tokens in the internal address balance

Unfortunately, at the benefit of a more generalized fee payment mechanism, this solution adds the following cons:

- The need for an additional internal VP
- Overhead given by the transfer execution which could become a possible DOS vector in case a lot of transfers failed
- Transfer execution would technically require gas making the problem recursive
- Checking the funds in advance would be harder