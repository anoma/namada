- Sanitize wasm memory accesses which are outside of the 32-bit address
  range, to avoid crashing the ledger while executing malicious wasm payloads.
  ([\#2385](https://github.com/anoma/namada/pull/2385))