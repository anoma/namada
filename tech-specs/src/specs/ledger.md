# The ledger

## The protocol

### Transaction execution

A transaction [encoded with proto3](./encoding.md#transactions) received from ABCI `DeliverTx` method is executed as follows:

1. Charge a base transaction [gas](#gas) and gas proportional to the transaction's `code` bytes length (this is because the WASM code is compiled with a single-pass compiler).
1. Decode the transaction bytes and validate the data.
1. Charge WASM compilation gas, proportional to the bytes length of the `code` field of the transaction.
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

For any error encountered in any of the steps of transaction execution, the protocol MUST charge the gas used by the transaction and discard any storage changes that the transaction attempted to perform.

### Validity predicates check


### Gas

- TODO describe gas accounting, wasm gas counter, limits, what happens if we go over limits and how gas relates to fees

### WebAssembly (WASM)

The WASM instantiation, the types, instructions, validation and execution of WASM modules MUST conform to the [WebAssembly specification](https://webassembly.github.io/spec/core/intro/index.html).

#### WASM validation

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

#### Stack height limiter

To make stack overflows deterministic, set the upper bound of the stack size to `65535`. If the stack height exceeds the limit then execution MUST abort.

<!--
cargo test test_tx_stack_limiter
cargo test test_vp_stack_limiter
-->

#### Transaction host environment functions

- TODO
