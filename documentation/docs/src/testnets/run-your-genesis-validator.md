# 3) (OPTIONAL) Reset your validator node
**You can skip to 3.1 if you don't need to reset the ledger state (most can skip to 3.1)**

```admonish note
With the release of `v0.15.3` we have introduced a new base directory. This means that you will need to reset your validator node to use the new base directory. This is a one time operation.
The base directory has been moved from `.namada` to `.local/share/namada` on Linux and `Library/Application Support/Namada` on MacOS.
```



This is the right time to save any logs file you want to share with us!

### 1. IMPORTANT! Save your `pre-genesis` folder in the ledger base directory

```bash
mkdir backup-pregenesis && cp -r .namada/pre-genesis backup-pregenesis/
```

### 2. **Ensure keys are saved**

`ls backup-pregenesis` should output a saved `wallet.toml`.

**DELETING THE OLD DIRECTORY**

*(WARNING: THIS WILL ALSO DELETE YOUR VALIDATOR KEYS, DO NOT RUN UNLESS YOU'VE BACKED IT UP)*

### 3. Delete ledger base directory by running `rm -rf .namada`

### 4. Check that namada and tendermint binaries are correct. `namada --version` should give `v0.15.3` and `tendermint version` should give `0.1.4-abciplus`
### 5. Create a base directory for the ledger
#### Linux
`mkdir $HOME/.local/share/namada`
#### MacOS 
`mkdir $HOME/Library/Application\ Support/Namada`

### 6. Save the base directory path to a variable
#### Linux:
```bash
export BASE_DIR=$HOME/.local/share/namada
```
#### MacOS:
```bash
export BASE_DIR=$HOME/Library/Application\ Support/Namada
```
### 7. Create a pre-genesis directory
#### Linux: 
`mkdir $HOME/.local/share/namada/pre-genesis`
#### MacOS: 
`mkdir $HOME/Library/Application\ Support/Namada/pre-genesis`

### 8. Copy the backuped file back to `$BASE_DIR/pre-genesis` folder
```bash
cp -r backup-pregenesis/* $BASE_DIR/pre-genesis/
```

## 3.1) Run your node as a genesis validator

#### 1. Wait for the genesis file to be ready, `CHAIN_ID`.
#### 2. Join the network with the `CHAIN_ID`
``` bash
export CHAIN_ID="public-testnet-8.0.b92ef72b820"
namada client utils join-network \
--chain-id $CHAIN_ID --genesis-validator $ALIAS
```

#### 3. Start your node and sync
```bash
NAMADA_TM_STDOUT=true namada node ledger run
```
Optional: If you want more logs, you can instead run
```bash
NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run
```
And if you want to save your logs to a file, you can instead run:
```bash
TIMESTAMP=$(date +%s)
NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run &> logs-${TIMESTAMP}.txt
tail -f -n 20 logs-${TIMESTAMP}.txt ## (in another shell)
```
#### 4. If started correctly you should see a the following log:
`[<timestamp>] This node is a validator ...`
    
