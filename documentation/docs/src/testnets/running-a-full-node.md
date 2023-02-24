# 4) Run your full node as a user
- Wait for the genesis file to be ready, you will receive a `$CHAIN_ID`.
- Join the network with the `CHAIN_ID`
```bash
  export CHAIN_ID="TBD"
  namada client utils join-network --chain-id $CHAIN_ID
  ```
- Start your node and sync
    - `NAMADA_TM_STDOUT=true namada node ledger run`
    - if you want more logs
        - `NAMADA_LOG=debug ANOMA_TM_STDOUT=true namada node ledger run`
    - if you want to save logs to a file
        - `TIMESTAMP=$(date +%s)`
        - `ANOMA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run &> logs-${TIMESTAMP}.txt`
        - `tail -f -n 20 logs-${TIMESTAMP}.txt` (in another shell)