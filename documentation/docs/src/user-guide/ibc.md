# Using IBC with Namada

This document describes using the inter-blockchain communication (IBC) protocol with Namada. This documentation covers being able to create connections through IBC as well as setting up local fractal instances of Namada for testing purposes.

:::warning
Warning! This is quite an advanced feature at the moment and is currently in development
:::

This document will cover three essential steps for using IBC with namada

1. Configuring the client for IBC
2. Creating channels between nodes
3. Setting up the relayer (which handles all connections between channels)
4. Transferring assets over connections

## Configuring the Client

The below is intended for those that wish to conduct IBC message transfer between two Namada chains. There is of course the cabablitiy to do this between any two IBC compatible chains (such as a cosmos chain). In this case, it is necessary to have a node of both the destination and the source chain running in order to make any package transfers. Below, we discuss first how to enable this connection between two pre-existing chains, and second setting up 2 Namada local instances for this purpose.

## Between two pre-existing chains
### Configuring Hermes.toml
One essential piece of the puzzle is to create a  `Hermes.toml` file that describes what connections will be set up that the relayer will be responsible for.

Make a relayer config toml file (Hermes' config.toml). If you don't specify the file, `~/.hermes/config.toml` is read as default.

1. Create the file found [here](https://hackmd.io/l6HNSqJmQt6QfkjfTmSfbw) in the ibc-rs head directory

Once this has created, you can export the true path of the new file to a varaible, which will be useful for later
```bash!
export HERMES_CONFIG="<path-to-toml.toml>"
```
    
**Interpreting the toml**
Each chain configuration is specified under the `[[chains]]` object.

These are the pieces of this puzzle you want to keep your :eyes: on:
- `chains.id` is the name of the chain
- `chains.rpc_address` specifies the port that the channel is communicating through, and will be the argument for the `net_address` when interacting with the ledger (will become clearer later)
    - Make sure to change the IP address to the IP address of your local machine that is running this node!
- `chains.key_name` specifies the key of the signer who signs a transaction from the relayer. The key should be generated before starting the relayer.

## Setting up the relayer

In order to create the relayer that is able to set up IBC connections, the following repo will need to be cloned. Then we enter the directory.

```bash=
export COMMIT="b50df2af6149f86aac6829a0c9be810785137c39\"
git clone git@github.com:heliaxdev/ibc-rs.git
git checkout $COMMIT
cd ibc-rs
```

The relayer is then started by running 
```bash
cargo run --bin hermes -- -c ${HERMES_CONFIG} start
```
### Running the chains

In order to make IBC transfers across two Namada chains, one must be running two nodes of Namada at once. In order to do this, two CHAIN-IDs will need to be retrieved. Either this can be done by using the chain-ids found in [this link](https://hackmd.io/l6HNSqJmQt6QfkjfTmSfbw).

However, it is also possible to do this locally.

Below, we discuss how to setup connections between two local namada testnets. If one wishes to make ibc-transfers across a devnet and a testnet, one must be running a node on each. We discuss how to set these up as well.

#### Running the testnet and devnet
First, export the correct chain-ids:
```bash!
export TESTNET_CHAIN_ID="<found-in-link>"
export DEVNET_CHAIN_ID="<found-in-link>"
```
Run 
```bash!
mkdir testnet
cd testnet
namadac utils join-network --chain-id $TESTNET_CHAIN_ID
export BASE_DIR_A=$(pwd)/.namada
```
Then run 
```bash!
namadan ledger run
```

Follow up by following the same instructions for the devnet
```bash!
cd ../
mkdir devnet
cd devnet
namadac utils join-network --chain-id $DEVNET_CHAIN_ID
export BASE_DIR_B=$(pwd)/.namada
```


#### Setting up 2 local Namada fractal instances
In order to setup two local testnets, we have created an easy script that does this for you. The following command will setup two local testnets.

In order for this to be completed, one must have cloned the namada directory and built the wasm scripts. This is achieved by the following commands

```bash=
git clone 
#Make sure you are in the home directory
cd ~
#Now clone
git@github.com:anoma/namada.git && cd namada
make build-wasm-scripts
export NAMADA_DIR=${HOME}/namada
```

The second command requires the executor to be located in the achieved in the ibc-rs directory.



```bash=
cd ~/ibc-rs/
./scripts/setup-namada.sh ${NAMADA_DIR}
#Followed by
cargo run --bin hermes -- -c namada_e2e_config.toml start
```

Congratulaitons, you now (hopefully) have 2 local namada chains running in the background.

We finally export some useful variables for later
```bash!
export BASE_DIR_A="$HOME/ibc-rs/data/namada-a/.namada"
```
```bash!
export BASE_DIR_B="$HOME/ibc-rs/data/namada-b/.namada"
```

```bash!
export HERMES_CONFIG=$(pwd)/namada_e2e_config.toml
```


## Creating channels
You should now have what is required in order to setup communication channels

We will begin by collecting the CHAIN_IDs for the different blockchains we want to establish a connection between.

A simple way to find these chain ids is to run

```bash=
ls ~/ibc-rs/.anoma
```

This should show something like

```bash=
ls .anoma/
global-config.toml                   namada-test.d9efda6aeb93cf8c38
namada-test.79d9d85f3dbfa1afa2       namada-test.d9efda6aeb93cf8c38.toml
namada-test.79d9d85f3dbfa1afa2.toml

```

In this case, the 2 chain ids of interest are 

```bash!
export CHAIN_A_ID=namada-test.d9efda6aeb93cf8c38
export CHAIN_B_ID= namada-test.79d9d85f3dbfa1afa2
```

:::info
But the above CHAIN_IDs will depend on your own setup, so do check this for yourself!
:::

Finally,

```bash!
cargo run --bin hermes -- -c ${HERMES_CONFIG} \
create channel ${CHAIN_A_ID} --chain-b ${CHAIN_B_ID} \
--port-a transfer --port-b transfer \
--new-client-connection
```

## Transferring assets across
This will establish a connection that will allow you to make transfers across chains.

In order to do this, we will need to know the ledger-address of each chain.

These can be found in the relevant `hermes.config` files.

One can run `grep "rpc_address" ${HERMES_CONFIG}`


:::info
**For the local testnets ONLY**
To find your ledger address for CHAIN_A, you can run the following command
```bash!
export LEDGER_ADDRESS_A = "$(grep "rpc_address" ~/ibc-rs/data/namada-a/.anoma/${CHAIN_A_ID}/setup/validator-0/.anoma/${CHAIN_A_ID}/config.toml)"
```
:::
And then the channel-id for this chain will depend on the order in which one created the channels. Since we have only opened one channel, the `channel-id` is `channel-0`, but as more are created, these increase by index incremented by 1.

So one can go ahead and run
```bash!
export CHANNEL_ID = "channel-0"
```


Such transfers can be achieved by

```bash!
namadac --base-dir ${BASE_DIR_A}
    ibc-transfer \
        --amount ${AMOUNT} \
        --source ${SOURCE_ALIAS} \
        --receiver ${RECEIVER_RAW_ADDRESS} \
        --token ${TOKEN_ALIAS} \
        --channel-id ${CHANNEL_ID} \
        --ledger-address ${LEDGER_ADDRESS_A}
```
Where the above variables in `${VARIABLE}` must be substituted with appropriate values.

E.g

```bash!
namadac --base-dir ${BASE_DIR_A}
    ibc-transfer \
    --amount 100 \
    --source albert \
    --receiver cosmos1lkp4xrhd5hh3f7u5n2aj429upuur3wk28qgtll \
    --token xan \
    --channel-id channel-0 \
    --ledger-address 127.0.0.1:27657
```




In order to close any ledgers setup by the script, one can run

`killall namadan`

