- Rather than allowing CometBFT to keep processing blocks after a storage write
  has failed in Namada, crash the ledger to avoid any potential corruption of
  state. ([\#2657](https://github.com/anoma/namada/pull/2657))