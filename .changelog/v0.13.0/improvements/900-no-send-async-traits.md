- Disable 'Send' on async traits that don't need 'Send'
  futures. This allows to use them with 'wasm-bindgen'.
  ([#900](https://github.com/anoma/namada/pull/900))