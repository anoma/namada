# 3) (OPTIONAL) Reset your validator node
**You can skip to 3.1 if you don't need to reset the ledger state (most can skip to 3.1)**
- This is the right time to save any logs file you want to share with us!

**IMPORTANT STEP**

- Save your `pre-genesis` folder in the ledger base directory
    - `mkdir backup-pregenesis && cp -r .namada/pre-genesis backup-pregenesis/`
**Ensure keys are saved**
- `ls backup-pregenesis` should output a saved `wallet.toml`.

**DELETING THE OLD DIRECTORY**

*(WARNING: THIS WILL ALSO DELETE YOUR VALIDATOR KEYS, DO NOT RUN UNLESS YOU'VE BACKED IT UP)*

- Delete ledger base directory 
    - `rm -rf .namada`
- Check that namada and tendermint binaries are correct (see step 1)
- Create a `.namada` folder
    - `mkdir .namada`
    - `mkdir .namada/pre-genesis`
- Copy the backuped file back to `.namada/pre-genesis` folder
    - `cp -r backup-pregenesis/* .namada/pre-genesis/`

## 3.1) Run your node as a genesis validator

- Wait for the genesis file to be ready, `CHAIN_ID`.
- Join the network with the `CHAIN_ID`
    ``` bash
    export CHAIN_ID="TBD"
    namada client utils join-network \
    --chain-id $CHAIN_ID --genesis-validator $ALIAS
    ```
- Start your node and sync
    - `NAMADA_TM_STDOUT=true namada node ledger run`
    - if you want more logs
        - `NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run`
    - if you want to save logs to a file
        - `TIMESTAMP=$(date +%s)`
        - `NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run &> logs-${TIMESTAMP}.txt`
        - `tail -f -n 20 logs-${TIMESTAMP}.txt` (in another shell)
- If started correctly you should see a the following log:
    - `[<timestamp>] This node is a validator ...`
    