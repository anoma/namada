- Clean up the code in the phase 1 of the Shielded Sync implementation. The
  main objective was to avoid the turbo fish syntax required by the fact
  the masp rpc client was being instantiated inside of the fetch methods.
  ([\#3426](https://github.com/anoma/namada/pull/3426))