- Fixed running CometBFT as a validator when the Namada config `tendermint_mode`
  is set to a non-validator mode. When the `tendermint_mode` changes
  from a validator to non-validator mode, the node will replace and
  backup the validator consensus key and state in the CometBFT directory.
  ([\#4245](https://github.com/anoma/namada/pull/4245))