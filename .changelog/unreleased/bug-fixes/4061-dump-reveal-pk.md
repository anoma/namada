- fix the cli command 'namada client reveal_pk' to respect the
  '--dump-tx' and '--dump-wrapper-tx' flags when present. this
  allows offline accounts to reveal their public keys to the network
  ([\#4061](https://github.com/anoma/namada/pull/4061))