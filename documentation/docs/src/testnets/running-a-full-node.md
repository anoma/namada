# 4) Run your full node as a user
1. Wait for the genesis file to be ready, you will receive a `$CHAIN_ID`.
2. Join the network with the `CHAIN_ID`
```bash
  export CHAIN_ID="public-testnet-3.0.81edd4d6eb6"
  namada client utils join-network --chain-id $CHAIN_ID
  ```
3. Start your node and sync
```bash
  NAMADA_TM_STDOUT=true namada node ledger run
  ```
Optional: If you want more logs, you can instead run
```bash
NAMADA_LOG=debug ANOMA_TM_STDOUT=true namada node ledger run
```
And if you want to save your logs to a file, you can instead run:
```bash
TIMESTAMP=$(date +%s)
ANOMA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run &> logs-${TIMESTAMP}.txt
tail -f -n 20 logs-${TIMESTAMP}.txt ## (in another shell)
```