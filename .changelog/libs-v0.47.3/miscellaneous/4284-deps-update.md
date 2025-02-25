- Updated most of the dependencies. Note that WASM build of the SDK crate now
  requires `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`. Consult <https://github.com/rust-random/getrandom?tab=readme-ov-file#webassembly-support>
  for more details. ([\#4284](https://github.com/anoma/namada/pull/4284))