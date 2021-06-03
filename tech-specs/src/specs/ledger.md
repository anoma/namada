# The ledger

## The state machine

### Transaction execution

A transaction [encoded with proto3](./encoding.md#transactions) received from ABCI `DeliverTx` method is executed as follows:

1. Charge a base transaction [gas](#gas) and gas proportional to the transaction's bytes length.
1. Decode the transaction bytes and validate the data. The field `timestamp` is REQUIRED.
1. Charge WASM compilation gas, proportional to the bytes length of the `code` field of the transaction.
1. [Validate the WASM code](#wasm-validation) from the `code` field of the transaction.

For any error encountered in any of the steps of transaction execution, the protocol MUST charge the gas used by the transaction and discard any storage changes that the transaction attempted to perform.


### Gas

- TODO describe gas accounting, limits, what happens if we go over limits and how gas relates to fees

### WASM

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
