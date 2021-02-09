# Anoma ledger prototype

To run:

```shell
# Run Anoma (this will also initialize and run Tendermint node)
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
