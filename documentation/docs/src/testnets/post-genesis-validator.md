# 5) Become a validator post genesis

After genesis, you can still join the network as a user and become a validator through self-bonding. 

After following step 4), create a user account through the following command

```bash
namada wallet address gen --alias my-account
```

Now choose a name for your validator:

```bash!
export VALIDATOR_ALIAS="your-validator-name"
```

A validator account requires additional keys compared to a user account, so start by initialising a validator account:

```bash!
namada client init-validator \
  --alias $VALIDATOR_ALIAS \
  --source my-account \
  --commission-rate <enter-your-commission-rate> \
  --max-commission-rate-change <enter-decimal-rate>
  
```

Then ensure you have enough NAM in order to self bond. Each voting power requires 1000 NAM, and you must be in the top 120 validators in terms of voting-power in order to become an active validator. You can see other validators' voting power through:

```bash!
namada client bonded-stake
```

## Faucet

In order to gain more NAM, the following command can be run: 
```bash!
namadac transfer \
    --token NAM \
    --amount 1000 \
    --source faucet \
    --target $VALIDATOR_ALIAS \
    --signer $VALIDATOR_ALIAS
```
Note: A maximum amount of 1000 NAM can be sourced from the faucet per transaction, so to get more, run this multiple times

```bash!
namada client bond \
  --validator $VALIDATOR_ALIAS \
  --amount <enter-amount>
```
