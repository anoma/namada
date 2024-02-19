- Fixed a bug in the communication of validator set updates to
  CometBFT after a change of validator consensus key that occurs
  at the same epoch as a validator entering the consensus set.
  ([\#2653](https://github.com/anoma/namada/pull/2653))