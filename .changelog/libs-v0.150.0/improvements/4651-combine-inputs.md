- Compute transaction change to a shielded account only after all shielded
  inputs from it have been constructed. The intent of this is to reduce wasted
  change. ([\#4651](https://github.com/anoma/namada/pull/4651))