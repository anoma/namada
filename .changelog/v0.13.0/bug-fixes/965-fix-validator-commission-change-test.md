- Fix the commission rate change wasm test, which failed because an arbitrary
  value for a new rate was allowed that could be equal to the previous rate.
  ([#965](https://github.com/anoma/namada/pull/965))