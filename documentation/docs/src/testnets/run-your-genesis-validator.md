## 3) MANDATORY: Reset your validator node
- You can skip to 3.1 if you don't need to reset the ledger state
- This is the right time to save any logs file you want to share with us!
- Save your `pre-genesis` folder in the ledger base directory
    - `mkdir backup-pregenesis && cp -r .anoma/pre-genesis backup-pregenesis/`
- Delete ledger base directory **[WARNING: THIS WILL ALSO DELETE YOUR VALIDATOR KEYS, DO NOT RUN UNLESS YOU'VE BACKED IT UP]**
    - `rm -rf .anoma`
- Check that namada and tendermint binaries are correct (see step 1)
- If you have you are a genesis validator from the previous testnet continue with the instructions below otherwise go to step `3.1`
- Inside the `backup-genesis` folder there are 2 files `validator.toml` and `wallet.toml`. You need make some changes to those:
    - Remove `staking_reward_public_key` from `validator.toml`
    - Remove `rewards_key` from `wallet.toml`
    - Add the following two field to `validator.toml`
        ```
        commission_rate = 0.05
        max_commission_rate_change = 0.01
        ```
- Create a `.namada` folder
    - `mkdir .namada`
    - `mkdir .namada/pre-genesis`
- Copy the backuped file back to `.namada/pre-genesis` folder
    - `cp -r backup-pregenesis/* .namada/pre-genesis/`

<!-- New!
With the new update, the folder will be located in the `.namada` folder rather than the `.anoma`

 - You can now move over your keys from your old .anoma folder to the new .namada folder in the namada/ directory by running `mv backup-pregenesis/. -r .namada/pre-genesis` -->

## 3.1) Run your node as a genesis validator

- Wait for the genesis file to be ready, `CHAIN_ID`.
- Join the network with the `CHAIN_ID`
    ``` bash
    export CHAIN_ID="qc-testnet-5.1.025a61165acd05e"
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
    