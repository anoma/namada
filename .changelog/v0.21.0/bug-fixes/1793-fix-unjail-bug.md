- Fixes buggy error handling in pos unjail_validator. Now properly enforces that
  if an unjail tx is submitted when the validator state is something other than
  Jailed in any of the current or future epochs, the tx will error out and fail.
  ([\#1793](https://github.com/anoma/namada/pull/1793))