- Disallowed deriving ed25519 keys from the default HD path
  that's used for deriving shielded keys with the newly default
  modified ZIP32 to prevent accidental leak of these keys.
  ([\#4272](https://github.com/anoma/namada/pull/4272))