# Execution

The Namada ledger execution system is based on an initial version of the [Anoma protocol](https://specs.anoma.net). The system implements a generic computational substrate with WASM-based transactions and validity predicate verification architecture, on top of which specific features of Namada such as IBC, proof-of-stake, and the MASP are built.

## Validity predicates

Conceptually, a validity predicate (VP) is a function from the transaction's data and the storage state prior and posterior to a transaction execution returning a boolean value. A transaction may modify any data in the accounts' dynamic storage sub-space. Upon transaction execution, the VPs associated with the accounts whose storage has been modified are invoked to verify the transaction. If any of them reject the transaction, all of its storage modifications are discarded. 
## Namada ledger

The Namada ledger is built on top of [Tendermint](https://docs.tendermint.com/master/spec/)'s [ABCI](https://docs.tendermint.com/master/spec/abci/) interface with a slight deviation from the ABCI convention: in Namada, the transactions are currently *not* being executed in ABCI's [`DeliverTx` method](https://docs.tendermint.com/master/spec/abci/abci.html), but rather in the [`EndBlock` method](https://docs.tendermint.com/master/spec/abci/abci.html). The reason for this is to prepare for future DKG and threshold decryption integration. 

The ledger features an account-based system (in which UTXO-based systems such as the MASP can be internally implemented as specific accounts), where each account has a unique address and a dynamic key-value storage sub-space. Every account in Namada is associated with exactly one validity predicate. Fungible tokens, for example, are accounts, whose rules are governed by their validity predicates. Many of the base ledger subsystems specified here are themselves just special Namada accounts too (e.g. PoS, IBC and MASP).

Interaction with the Namada ledger are made possible via transactions (note transaction whitelist below). In Namada, transactions are allowed to perform arbitrary modifications to the storage of any account, but the transaction will be accepted and state changes applied only if all the validity predicates that were triggered by the transaction accept it. That is, the accounts whose storage sub-spaces were touched by the transaction and/or an account that was explicitly elected by the transaction as the verifier will all have their validity predicates verifying the transaction. A transaction can add any number of additional verifiers, but cannot remove the ones determined by the protocol. For example, a transparent fungible token transfer would typically trigger 3 validity predicates - those of the token, source and target addresses.

## Supported validity predicates

While the execution model is fully programmable, for Namada only a selected subset of provided validity predicates and transactions will be permitted through pre-defined whitelists configured at network launch. 

There are some native VPs for internal transparent addresses that are built into the ledger. All the other VPs are implemented as WASM programs. One can build a custom VP using the [VP template](https://github.com/anoma/anoma/tree/master/wasm/vp_template) or use one of the pre-defined VPs.

Supported validity predicates for Namada:
- Native
    - Proof-of-stake (see [spec](../economics/proof-of-stake.md))
    - IBC & IbcToken (see [spec](../interoperability/ibc.md))
    - Governance (see [spec](./governance.md))
    - SlashFund (see [spec](./governance.md#SlashFundAddress))
    - Protocol parameters
- WASM
    - Fungible token (see [spec](./core-concepts.md))
    - MASP (see [spec](../masp.md))
    - Implicit account VP (see [spec](./core-concepts.md))
    - k-of-n multisignature VP (see [spec](./core-concepts.md))
