# The ledger

## The protocol

### Transactions

A transaction [encoded with proto3](./encoding.md#transactions) received from ABCI `DeliverTx` method is executed in two main steps:

1. [Transaction execution](#transaction-execution)
1. [Validity predicates check](#validity-predicates-check)

#### Transaction execution

For any error encountered in any of the following steps of transaction execution, the protocol MUST charge the gas used by the transaction and discard any storage changes that the transaction attempted to perform.

1. Charge a base transaction [gas](#gas).

   TODO: just charge the base gas, not the gas proportional to the whole tx size
1. Decode the transaction bytes and validate the data.
1. Charge WASM compilation gas, proportional to the bytes length of the `code` field of the transaction (this is because the WASM code is compiled with a single-pass compiler).
1. [Validate the WASM code](#wasm-validation) from the `code` field of the transaction.
1. Inject a [gas counter](#gas) into the `code`.
1. Inject a [stack height](#stack-height-limiter) limiter into the `code`.
1. Compile the transaction `code` with single-pass compiler. The compilation computational complexity MUST be linear in proportion to the `code` size.
1. Initialize the WASM linear memory with descriptor having the initial memory size equal to `6.4 MiB` and maximum memory size to `12.8 MiB`.
1. Instantiate the WASM module with imported [transaction host environment functions](#transaction-host-environment-functions) and the instantiated WASM memory.
1. Write the transaction's `data` into the memory exported from the WASM module instance.
1. Attempt to call the module's entrypoint function. The entrypoint MUST have signature:
   ```wat
   func (param i64 i64)
   ```
   The first argument is the offset to the `data` input written into the memory and the second argument is its bytes length.

If the transaction executed successfully, it is followed [Validity predicates check](#validity-predicates-check).

#### Validity predicates check

For the transaction to be valid, all the triggered validity predicates must accept it.

First, the addresses whose validity predicates should be triggered by the transaction are determined. In this process, the addresses get associated with a set of modified storage keys that are relevant to the address:
1. The addresses set by the transaction (see `insert_verifier` in [transaction host environment functions](#transaction-host-environment-functions)) are associated with *all* the modified storage keys.

   TODO - <https://github.com/anomanetwork/anoma/issues/292>
1. The storage keys that were modified by the transaction are associated with the addresses included in the storage keys. Note that a storage key may contain more than one address, in which case all its addresses are associated with this key. 
1. All these addresses are additionally associated with the storage key to the validity predicates of any newly initialized accounts' by the transaction (see `init_account` in [transaction host environment functions](#transaction-host-environment-functions)).

For all these addresses, attempt to read their validity predicate WASM code from the storage. For each validity predicate look-up, charge storage read gas and WASM compilation gas, proportional to the bytes length of the validity predicate. If any of the validity predicates look-ups fails, or any validity rejects the transaction or fails anywhere in the execution, the whole transaction is rejected. If the transaction is rejected, the protocol MUST charge the gas used by the transaction and discard any storage changes that the transaction attempted to perform.

Execute all validity predicates in parallel as follows:

1. Charge WASM compilation gas, proportional to the bytes length of the validity predicate (same as for the transaction, WASM code is compiled with a single-pass compiler).
1. [Validate the WASM code](#wasm-validation) of the validity predicate.
1. Inject a [gas counter](#gas) into the `code`.
1. Inject a [stack height](#stack-height-limiter) limiter into the `code`.
1. Compile the validity predicate with single-pass compiler. The compilation computational complexity MUST be linear in proportion to its bytes size.
1. Initialize the WASM linear memory with descriptor having the initial memory size equal to `6.4 MiB` and maximum memory size to `12.8 MiB`.
1. Instantiate the WASM module with imported [validity predicate host environment functions](#validity-predicate-host-environment-functions) and the instantiated WASM memory.
1. Write the address of the validity predicate’s owner, the transaction `data`, the modified storage keys encoded with Borsh, and all the triggered validity predicates owners' addresses encoded with Borsh into the memory exported from the WASM module instance.
1. Attempt to call the module's entrypoint function. The entrypoint MUST have signature:
   ```wat
   func (param u64 u64 u64 u64 u64 u64 u64 u64) (result u64))
   ```
   - The first argument is the offset to the owner’s address written into the memory, the second argument is its bytes length
   - The third is the offset of the transaction’s `data` and fourth is it’s bytes length
   - The fifth is the offset of the modified storage keys and sixth is its bytes length
   - The seventh is the offset of the triggered validity predicates owners' addresses and eighth is its bytes length

#### Gas

- TODO describe gas accounting, wasm gas counter, limits, what happens if we go over limits and how gas relates to fees

#### WebAssembly (WASM)

The WASM instantiation, the types, instructions, validation and execution of WASM modules MUST conform to the [WebAssembly specification](https://webassembly.github.io/spec/core/intro/index.html).

##### WASM validation

The WebAssembly code is REQUIRED to only use deterministic instructions. Furthermore, it MUST NOT use features from any of the following WebAssembly proposals:

- The reference types proposal
- The multi-value proposal
- The bulk memory operations proposal
- The module linking proposal
- The SIMD proposal
- The threads proposal
- The tail-call proposal
- The multi memory proposal
- The exception handling proposal
- The memory64 proposal

##### Stack height limiter

To make stack overflows deterministic, set the upper bound of the stack size to `65535`. If the stack height exceeds the limit then execution MUST abort.

<!--
cargo test test_tx_stack_limiter
cargo test test_vp_stack_limiter
-->

##### Transaction host environment functions

- TODO
