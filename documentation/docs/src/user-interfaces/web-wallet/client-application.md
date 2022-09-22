# Client Application

### React Web Application

- Built with TypeScript
- State-management with Redux Toolkit (`@reduxjs/toolkit`)
- CRA (create-react-app) scripts v5 with Craco to enable yarn workspaces (monorepo package management)
- `wasm-react-scripts` - enabling WebAssembly files into the Webpack pipeline
- Styled-Componenents for all application/component styling

## WebAssembly Library

Much of the core functionality of the web app requires either direct interfacing with types from the Anoma codebase, or other Rust libraries that provide encryption, key-management, mnemonic-generation, etc., that are more easily and robustly handled in the Rust ecosystem than that of TypeScript.

The primary functionality that we currently pull from `anoma` involves constructing transactions. The web wallet interface should be able to serialize the data broadcast to the ledger for different transactions, and this requires items to be serialized within the WebAssembly code. We created `anoma-lib`, which houses wrapped Anoma types (wrapped when some work is needed to get it to work well with wasm), and the logic needed for us to be able to interface with it from TypeScript.

The Rust source code `anoma-lib` is structured as follows:

```bash
.
├── types
│   ├── address.rs
│   ├── keypair.rs
│   ├── mod.rs
│   ├── transaction.rs
│   ├── tx.rs
│   └── wrapper.rs
├── account.rs
├── lib.rs
├── transfer.rs
├── utils.rs
```

Here, we have several types that are essentially built on top of `anoma` types, allowing us to interface easily from the client app, such as `address`, `keypair`, `tx`, and `wrapper`, then a generic `transaction` type that handles the logic common to all transactions. Essentially, we want these types to handle any serialization that the `anoma` types require entirely within the wasm, then later translate the results into something the client can understand.

Outside of types, we have an `account.rs` file that allows us to call account functions, such as `initialize` (to construct an "init-account" transaction), from the client app. `transfer.rs` is similar, in that it provides the bridge for the client to issue a transfer transaction. Additional transactions can be easily created in this way, with a specific differences being handled in a top level Rust source file, the common logic of transactions handled by `types/transaction`, and any types that need extra work in order to be useful to the client being added as well to `types`.

## Interfacing between the Client and WebAssembly

When compiling the `wasm` utilizing `wasm-pack`, we get the associated JavaScript source to interact with the WebAssembly output, as well as a TypeScript type definition file. When we set the `wasm-pack` target to `web`, we get an additional exported `init` function, which is a promise that resolves when the wasm is fully loaded, exposing the `memory` variable. In most cases we shouldn't need to interact directly with the memory of the wasm, but by awaiting the `init()` call, we can immediately execute any of the wasm methods.

In the case of `anoma-lib`, there is a corresponding class that initializes and exposes the features of the wasm in `anoma-wallet`, called `AnomaClient`. (**NOTE**: This is one use case for wasm, but we may have any number of wasm projects that the wallet can utilize). Exposing the features through a TypeScript class is a good opportunity to move from Rust-style "snake-casing" to camel-casing (most common in TypeScript), and any additional type definitions we can add at this level as well.

The goal of bridging wasm and the client TypeScript application should be to make its usage as straightforward as any TypeScript class. It should also be fairly easy for the developer to add new features to the Rust source and quickly bring that into the client app.

### Dealing with Rust types in TypeScript

One of the challenges of working with WebAssembly is how we might go about handling types from Rust code. We are limited to what JavaScript can handle, and often when serializing output from the wasm, we'll choose a simple type like `string` or `number`, or send the data as a byte array (very common, especially when dealing with numbers larger than JavaScript can handle by default). Sending raw data to the client is often a decent solution, then any encoding we prefer we can enact on the client-side (hexadecimal, base58, base64, etc), and choosing a Rust type like `Vec<u8>` makes this straight-forward. _(More to come on this topic in the future)_

There is much more nuance to handling types from Rust wasm in TypeScript when working with `wasm-bindgen`, and more information can be found at the following URL:

https://rustwasm.github.io/wasm-bindgen/reference/types.html

## Testing with WebAssembly

The wallet-interface should be able to run within the Jest testing framework. This is made possibly by switching our `wasm-pack` target and rebuilding before the test is run, as tests run within NodeJS. So, instead of the following:

```bash
wasm-pack build ../anoma-lib/ --out-dir ../anoma-wallet/src/lib/anoma --out-name anoma --target web

```
We would issue this in order to support Jest in NodeJS:

```bash
wasm-pack build ../anoma-lib/ --out-dir ../anoma-wallet/src/lib/anoma --out-name anoma --target nodejs
```
