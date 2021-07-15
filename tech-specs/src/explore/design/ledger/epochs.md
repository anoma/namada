# Epochs

An epoch is a range of blocks whose length is determined by the [epoch duration protocol parameter](./parameters.md#epoch-duration). They are identified by consecutive natural numbers starting at 0.

We store the current epoch, its start block height and start block time, and the epoch of each block in the block storage.

The first epoch (ID 0) starts on the genesis block. The epoch start time is set to the genesis time configured for the chain and the epoch start height is set to the height of the genesis block (typically 1).

On each block `BeginBlock` Tendermint call, we check if the current epoch is finished, in which case we move on to the next epoch. An epoch is finished when both the minimum number of blocks and minimum duration of an epoch have been created from the first block of a current epoch. When a new epoch starts, the start block height is set to the block's height and start block time is set to block's time from the block header.
