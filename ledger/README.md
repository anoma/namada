# Anoma ledger prototype

To run:

```shell
# Init and start a tendermint node
tendermint init
tendermint node

# Run Anoma
make run
```

Send transactions to the tendermint node:

```shell
curl "localhost:26657/broadcast_tx_commit?tx=0x01"
```

Reset tendermint node state:

```shell
tendermint unsafe_reset_all
```
