- Instead of having every user tx be executed across two blocks, the first executing a wrapper and the 
  second executing the main payload, this change makes it so that the entire tx is executed in a single
  block (or rejected). ([\#2627](https://github.com/anoma/namada/pull/2627)) 