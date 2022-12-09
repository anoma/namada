- Optimize the PoS code to depend only on bonded stake, removing
  the VotingPower(Delta) structs. This mitigates some previous
  information loss in PoS calculations. Instead, the notion of
  voting power is only relevant when communicating with Tendermint.
  ([#707](https://github.com/anoma/namada/pull/707))