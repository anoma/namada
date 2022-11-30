- Public parts of shared `namada` crate have been split up into a
  `namada_core` crate. The `namada_proof_of_stake`, `namada_vp_prelude`
  and `namada_tx_prelude` crates now depend on this `namada_core` crate.
  ([#733](https://github.com/anoma/namada/pull/733))
