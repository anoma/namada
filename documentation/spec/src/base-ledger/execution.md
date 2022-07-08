# Execution system

Namada chain is running on the [Anoma ledger](https://docs.anoma.network/master/specs/ledger.html). Namada is set out to initially only leverage a selected subset of Anoma's features and e.g. Anoma Intent gossiper and Matchmaker systems will not be supported. The main component specified on this page is the Tendermint-based Anoma ledger with a WASM-based transaction and validity predicate system, that powers many other components of Namada (such as IBC, PoS and MASP integrations).

## Anoma Ledger

The [Anoma ledger](https://docs.anoma.network/master/specs/ledger.html) is built on top of [Tendermint](https://docs.tendermint.com/master/spec/)'s [ABCI](https://docs.tendermint.com/master/spec/abci/) interface with a slight deviation from the ABCI convention, that is in Anoma, the transactions are currently *not* being executed in ABCI `DeliverTx` method, but rather in the `EndBlock` method. The reason for this is [DKG and ABCI++ integration](https://github.com/orgs/anoma/projects/1/views/13) in Anoma, which has not yet been fully finished and hence is out-of-scope for Namada.

The Anoma ledger features an [account-based system](https://docs.anoma.network/master/specs/ledger.html#accounts) (with UTXO employed inside it in certain integrations, such as MASP) where each account has a unique [address](https://docs.anoma.network/master/specs/ledger.html#addresses) and a dynamic key-value [storage sub-space](https://docs.anoma.network/master/specs/ledger.html#dynamic-storage-sub-space). Every account in Anoma is associated with exactly one validity predicate. Fungible tokens are accounts, whose rules are governed by its validity predicate. Many of the ledger integrations are themselves just special Anoma accounts too (e.g. PoS, IBC and MASP).

Interaction with the Namada ledger are made possible via [Anoma transactions](https://docs.anoma.network/master/specs/ledger.html#transactions) (note [transaction whitelist](#transaction-and-validity-predicate-whitelist)). Please refer to the [protocol section](https://docs.anoma.network/master/specs/ledger.html#the-protocol) that specifies the transaction execution model. In short, in Anoma transactions are allowed to perform arbitrary modification to  storage of any account, but the transaction will be accepted only if all the [validity predicates](https://docs.anoma.network/master/specs/ledger.html#validity-predicates-check) that were triggered by the transaction accept it. That is, the accounts whose storage sub-spaces were touched by the transaction and/or an account that was explicitly elected by the transaction as the verifier will all have their validity predicates verifying the transaction. A transaction can add any number of additional verifiers, but of course cannot remove the ones determined by the protocol. For example, a transparent fungible token transfer would typically trigger 3 validity predicates - those of the token, source and target addresses.

## Transaction and validity predicate whitelist

While Anoma ledger aims to be a fully programmable ledger, for Namada only a selected subset of provided validity predicates and transactions will be permitted through pre-defined whitelists configured for the Namada network.

# Validity Predicates

Conceptually, a VP is a function from the transaction's data and the storage state prior and posterior to a transaction execution returning a boolean value. A transaction may modify any data in the [accounts' dynamic storage sub-space](accounts.md#dynamic-storage-sub-space). Upon [transaction execution](tx.md#tx-execution), the VPs associated with the accounts whose storage has been modified are invoked to verify the transaction. If any of them reject the transaction, all of its storage modifications are discarded.

There are some native VPs for [internal transparent addresses](accounts.md#internal-transparent-addresses) that are built into the ledger. All the other VPs are implemented as [WASM programs](wasm-vm.md). One can build a custom VP using the [VP template](https://github.com/anoma/anoma/tree/master/wasm/vp_template) or use one of the pre-defined VPs.

## List of Default VP for Namada
native:
- Pos
- IBC: main IBC VP
- IbcToken: for IBC token escrow, burn and mint
- Protocol parameters: for now, it doesn’t allow any changes
- Default VPs: this is just being added. It’s a validity predicate for default WASM validity predicates :doge-fractal: , we’re adding the default implicit account’s VP to it, but there might be others later. For now, this also doesn’t allow any changes

WASM:
- fungible token VP: checks tx inputs == outputs and it’s used for the native token
- MASP: this could potentially be native too, it’s not difficult to change as they have the same API available
implicit account VP: allows cryptographic sigs authorization

we also have a reserved internal address for PosSlashPool  where slashed token would be sent to, but we don’t have any VP for it yet