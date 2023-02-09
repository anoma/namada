- Infrastructure for PoS inflation and rewards. Includes inflation
  using the PD controller mechanism and rewards based on validator block voting
  behavior. Rewards are tracked and effectively distributed using the F1 fee
  mechanism. In this PR, rewards are calculated and stored, but they are not
  yet applied to voting powers or considered when unbonding and withdrawing.
  ([#714](https://github.com/anoma/namada/pull/714))