- Reworks the way the ledger waits for genesis start. It now fully initializes the node and 
  outputs logs before sleeping until genesis start time. Previously it would not start any 
  processes until genesis times, giving no feedback to users until genesis time was reached.
  ([\#2502](https://github.com/anoma/namada/pull/2502))