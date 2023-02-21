# 3) (OPTIONAL) Reset your validator node
**You can skip to 3.1 if you don't need to reset the ledger state (most can skip to 3.1)**

This is the right time to save any logs file you want to share with us!

**IMPORTANT STEP**

1. Save your `pre-genesis` folder in the ledger base directory

```bash
mkdir backup-pregenesis && cp -r .namada/pre-genesis backup-pregenesis/
```

2. **Ensure keys are saved**

`ls backup-pregenesis` should output a saved `wallet.toml`.

**DELETING THE OLD DIRECTORY**

*(WARNING: THIS WILL ALSO DELETE YOUR VALIDATOR KEYS, DO NOT RUN UNLESS YOU'VE BACKED IT UP)*

3. Delete ledger base directory 
```bash
rm -rf .namada
```
4. Check that namada and tendermint binaries are correct (see step 1)
5. Create a `.namada` folder
```bash
mkdir .namada
mkdir .namada/pre-genesis
```
6. Copy the backuped file back to `.namada/pre-genesis` folder
```bash
cp -r backup-pregenesis/* .namada/pre-genesis/
```

```admonish note
Make sure to check the [Changelog](https://github.com/anoma/namada/tree/main/.changelog) and our other communication channels for any manual changes that may need to be made to the files in the pre-genesis folder.
```

## 3.1) Run your node as a genesis validator

<<<<<<< HEAD
- Wait for the genesis file to be ready, `CHAIN_ID`.
- Join the network with the `CHAIN_ID`
    ``` bash
    export CHAIN_ID="TBD"
    namada client utils join-network \
    --chain-id $CHAIN_ID --genesis-validator $ALIAS
    ```
- Start your node and sync
    - `NAMADA_TM_STDOUT=true namada node ledger run`
    - If you want more logs:
        - `NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run`
    -  If you want to save logs to a file:
        - `TIMESTAMP=$(date +%s)`
        - `NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run &> logs-${TIMESTAMP}.txt`
        - `tail -f -n 20 logs-${TIMESTAMP}.txt` (in another shell)
- If started correctly, you should see a the following log:
    - `[<timestamp>] This node is a validator ...`
=======
1. Wait for the genesis file to be ready, `CHAIN_ID`.
2. Join the network with the `CHAIN_ID`
``` bash
export CHAIN_ID="TBD"
namada client utils join-network \
--chain-id $CHAIN_ID --genesis-validator $ALIAS
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
4. If started correctly you should see a the following log:
`[<timestamp>] This node is a validator ...`
>>>>>>> f83b94757 (removed the chain-id)
    