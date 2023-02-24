# Off-chain proposals

If for any reason issuing an on-chain proposal is not adequate to your needs, you still have the option to create an off-chain proposal.

## Create proposal

Create the same json file as in the on-chain proposal and use the following command:

```shell
namada client init-proposal \
    --data-path proposal.json \
    --offline
```

This command will create a `proposal` file same directory where the command was launched.

## Vote on proposal

To vote on an offline proposal use the following command:

```shell
namada client vote-proposal --data-path proposal \
    --vote yay \
    --signer validator \
    --offline
```

This command will create a `proposal-vote-${address}` file (where address is the `--signer` address).

## Tally off-chain proposal

To compute the tally for an offline proposal we need to collect

- `proposal` file (must have this name)
- all the `proposal-vote-${address}` files

All those files will have to be in a folder (lets call it `offline-proposal`).

Now you can use the following command:

```shell
namada client query-proposal-result \
    --offline \
    --data-path `offline-proposal`
```

which will tell you the proposal result.
