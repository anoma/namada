# Development considerations

Given our settings, the number one consideration for development is correctness. To that end, striving to write clean code with small, reusable and well-tested units is very helpful. Less code means less opportunities for defects. First and foremost, optimize code for readability. Common approaches to managing complexity like separation of concerns and separation of effectful code from pure code is always a good idea as it makes it easier to test. On a hot path, it's good to avoid allocations when possible.

For safety critical parts it is good to add redundancy in safety checks, especially if those checks that can prevent accidental loss of assets. As an example, the node should try to prevent validators from double signing that could lead to weakening of security of the PoS system and punitive loss of tokens in slashing for the validator. The term "belt and braces" is appropriate for such measures.

## Error handling

A very related concern to correctness is error handling. Whenever possible, it is best to rule out errors using the type system, i.e. make invalid states impossible to represent using the type system. However, there are many places where that is not practical or possible (for example, when we consume some values from Tendermint, in complex logic or in IO operations like reading and writing from/to storage). How errors should be handled depends on the context.

When you're not sure which context some piece of code falls into or if you want to make it reusable in different settings, the default should be "defensive coding" approach, with any possible issues captured in `Result`'s errors and propagated up to the caller. The caller can then decide how to handle errors.

### Native code that doesn't depend on interactions

In ledger's shell and the protocol code that's compiled to native binary, in logic that is not dependent on user interactions like transactions and queries, for an error in functionality that is critical to the overall operation of the ledger (systems without which the ledger cannot continue to operate) it is preferable to fail early. *Panics* are preferable when a error from which there is no reasonable way to recover occurs in this context. Emphasis on panics as it's perhaps somewhat counter-intuitive. It makes for easy diagnostics and prevents the error from propagating into a deeper issue that might even go unnoticed. To counter point possible issues, this code must be tested incredibly well to ensure that the panics cannot actually occur during regular operation and to maintain ledger's stability. Property based testing is a good fit, but it is essential that the inputs generated to these tests cover as much of the real-world scenarios as possible.

### Interaction-sensitive code

A place where "defensive coding" comes into play is logic that depends on user input (typically transactions and queries handling in the native ledger code and native VPs, the P2P layer is abstracted away by Tendermint). We must ensure that a malicious input cannot trigger unexpected behavior or cause a panic. In practical terms, this means avoid making assumptions about the user input and handle any possible issues (like data decoding issues, fallible conversions and interference overflows) gracefully. Fuzz testing can help in finding these issues.

### Sandboxed code

In the WASM transactions and validity predicates, we have a safety net of a sandboxed environment and so it is totally fine to *panic* on unexpected inputs. It however doesn't provide very good experience as any panic that occurs in the WASM is turned into a generic WASM runtime error message. That takes us to the next point.

### The client

In the context of the client, we should do as much checking as possible before submitting a transaction (e.g. before a transfer, we check the balance of the source is sufficient to execute the transaction) to the ledger to prevent possible issues early, before any gas is spent, and provide a nice experience with user-friendly messages, where we can explain what went wrong.

## Practical guidelines

In practical terms this means:

- Avoid using `unwrap`,  `expect` and `panic!`/`unreachable!`. Instead, turn error conditions into `Error` types. Using `unwrap_or_default` can often be a sensible choice, but it should be well reasoned about - for example when reading token balance, the default value `0` is fine in most setting.
- Avoid the default arithmetic operators, use checked versions instead (e.g. `checked_add` or `checked_div`).
- Avoid using `as` for conversions, use `TryFrom`/`TryInto` instead.
- Avoid `unsafe` code - this is typically only needed at FFI boundaries (e.g. WASM) and should be well tested and abstracted away from a public API.
- Avoid indexing operators and slicing without bounds checks (e.g. `[0]` or `[0..2]`), prefer to use calls that cannot panic or guard them with bounds checks.
- Don't use `assert!` in non-test code, but use `debug_assert!` generously.
- Type system doesn't make up for lack of tests. Specified behavior should always be covered by tests to avoid regressions.
- If some code is hard to test, take it as a hint that it could use refactoring. If it's hard to test, it's most likely easy for it to break in unexpected ways.
- If something breaks past the development stage (i.e. in devnets or testnets), it's hint for a lack of testing. You should write a test that reproduces the issue before fixing it.
