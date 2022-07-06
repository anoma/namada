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
