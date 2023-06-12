- The implementation of the cubic slashing system that touches virtually all
  parts of the proof-of-stake system. Slashes tokens are currently kept in the
  PoS address rather than being transferred to the Slash Pool address. This PR
  also includes significant testing infrastructure, highlighted by the PoS state
  machine test with slashing. ([#892](https://github.com/anoma/namada/pull/892))