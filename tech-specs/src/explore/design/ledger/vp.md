# Validity predicates

[Tracking Issue](https://github.com/anomanetwork/anoma/issues/44)

---

Each [account](accounts.md) is associated with exactly one validity predicate (VP).

Conceptually, a VP is a function from the transaction's data and the storage state prior and posterior to a transaction execution returning a boolean value. A transaction may modify any data in the [accounts' dynamic storage sub-space](accounts.md#dynamic-storage-sub-space). Upon [execution](tx-execution.md), the VPs associated with the accounts whose storage has been modified are invoked to verify the transaction. If any of them reject the transaction, all of its storage modifications are discarded.

VPs are implemented as [WASM programs](wasm-vm.md). One can build a custom VP using the [VP template](https://github.com/anomanetwork/anoma/tree/master/vps/vp_template) or use one of the pre-defined VPs.

## Fungible token VP

The [fungible token VP](https://github.com/anomanetwork/anoma/tree/master/vps/vp_token) allows to associate accounts balances of a specific token under its account. 

For illustration, users `Albert` and `Bertha` might hold some amount of token with the address `XAN`. Their balances would be stored in the `XAN`'s storage sub-space under the storage keys `@XAN/balance/@Albert` and `@XAN/balance/@Bertha`, respectively. When `Albert` or `Bertha` attempt to transact with their `XAN` tokens, its validity predicate would be triggered to check:

- the total supply of `XAN` token is preserved (i.e. inputs = outputs)
- the senders (users whose balance has been deducted) are checked that their validity predicate has also been triggered

Note that the fungible token VP doesn't need to know whether any of involved users accepted or rejected the transaction, because if any of the involved users rejects it, the whole transaction will be rejected.

## User VP

The [user VP](https://github.com/anomanetwork/anoma/tree/master/vps/vp_user) currently provides a signature verification against a public key for sending tokens as prescribed by the fungible token VP. In this VP, a transfer of tokens doesn't have to be authorized by the receiving party. 

It also allows arbitrary storage modifications to the user's sub-space to be performed by a transaction that has been signed by the secret key corresponding to the user's public key stored on-chain. This functionality also allows one to update their own validity predicate.

