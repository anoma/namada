# Using IBC with Namada

This document describes using the inter-blockchain communication (IBC) protocol with Namada. This documentation covers being able create connections through IBC as well as setting up local fractal instances of Namada for testing purposes.

:::warning
Warning! This is quite an advanced feature at the moment and is currently in development
:::

This document will cover three essential steps for using IBC with namada

1. Configuring the client for IBC
2. Creating channels between nodes
3. Setting up the relayer (which handles all connections between channels)
4. Transferring assets over connections

## Configuring the Client

The below is intended for those that wish to conduct IBC message transfer between two Namada chains. There is of course the cabablitiy to do this between any two IBC compatible chains (such as a cosmos chain). In this case, it is necessary to have a node of both the destination and the source chain running in order to make any package transfers. Below, we discuss setting up 2 Namada local instances for this purpose.

### Hermes.toml
One essential piece of the puzzle is to create a  `Hermes.toml` file that describes what connections will be set up that the relayer will be responsible for.

Make a relayer config toml file (Hermes' config.toml). If you don't specify the file, `~/.hermes/config.toml` is read as default.

```toml!
    [global]
    log_level = 'debug'

    [mode]

    [mode.clients]
    enabled = true
    refresh = true
    misbehaviour = true

    [mode.connections]
    enabled = false

    [mode.channels]
    enabled = false

    [mode.packets]
    enabled = true
    clear_interval = 10  # relay packets frequently
    clear_on_start = true
    tx_confirmation = true

    [telemetry]
    enabled = false
    host = '127.0.0.1'
    port = 3001

    [[chains]]
    id = 'gaia'
    rpc_addr = 'http://127.0.0.1:26657'
    grpc_addr = 'http://127.0.0.1:9090'
    websocket_addr = 'ws://127.0.0.1:26657/websocket'
    rpc_timeout = '10s'
    account_prefix = 'cosmos'
    key_name = 'testkey'
    store_prefix = 'ibc'
    max_gas = 3000000
    max_msg_num = 30
    max_tx_size = 2097152
    gas_price = { price = 0.001, denom = 'stake' }
    clock_drift = '5s'
    trusting_period = '14days'
    trust_threshold = { numerator = '1', denominator = '3' }

    [[chains]]
    id = 'anoma-test.87a9a2419736a342be7'  # set your chain ID
    rpc_addr = 'http://127.0.0.1:27657'  # set the IP and the port of the chain
    grpc_addr = 'http://127.0.0.1:9090'  # not used for now
    websocket_addr = 'ws://127.0.0.1:27657/websocket'  # set the IP and the port of the chain
    rpc_timeout = '10s'
    account_prefix = 'cosmos'  # not used
    key_name = 'relayer'  # The key is an account name you made
    store_prefix = 'ibc'
    max_gas = 3000000    # the below params are not used for now
    max_msg_num = 30
    max_tx_size = 2097152
    gas_price = { price = 0.001, denom = 'stake' }
    clock_drift = '5s'
    trusting_period = '14days'
    trust_threshold = { numerator = '1', denominator = '3' }
```

Once this has created, you can export the true path of the new file to a varaible, which will be useful for later
```bash!
export HERMES_CONFIG="<path-to-toml.toml>"
```
    
**Interpreting the toml**
Each chain configuration is specified under the `[[chains]]` object.

These are the pieces of this puzzle you want to keep your :eyes: on:
- `chains.id` is the name of the chain
- `chains.rpc_address` specifies the port that the channel is communicating through, and will be the argument for the `net_address` when interacting with the ledger (will become clearer later)
- `chains.key_name` specifies the key of the signer who signs a transaction from the relayer. The key should be generated before starting the relayer.

## Setting up the relayer

In order to create the relayer that is able to set up IBC connections, the following repo will need to be cloned. Then we enter the directory.

```bash=
export COMMIT="3ea4b4bff6f790a472c5c7ec61725703085c2ebf"
git clone git@github.com:heliaxdev/ibc-rs.git
git checkout $COMMIT
cd ibc-rs
```

The relayer is then started by running 
```bash
cargo run --bin hermes -- -c ${HERMES_CONFIG} start
```
### Running 2 local instances of Namada

In order to make IBC transfers across two Namada chains, one must be running two nodes of Namada at once. In order to do this, two CHAIN-IDs will need to be retrieved. In the case that there is only 1 testnet running, one may need to setup a local namada chain (which will be proof of authority since you will be the only one running it :P).

Below, we discuss how to setup connections between two local namada testnets, and then append how to achieve ibc package transfers between arbitrary CHAIN-IDs afterwards.

#### Setting up local Namada fractal instances
In order to setup a local testnet, we have created an easy script that does this for you. The following command will setup two local testnets.

In order for this to be completed, one must have cloned the namada directory and built the wasm scripts. This is achieved by the following command

```bash=
git clone 
#Make sure you are in the home directory
cd ~
#Now clone
git@github.com:anoma/namada.git && cd namada
make build-wasm-scripts
export NAMADA_DIR=${HOME}/namada
```

The second command requires being located in the achieved in the ibc-rs directory.



```bash=
cd ~/ibc-rs/
./scripts/setup-namada.sh ${NAMADA_DIR}
#Followed by
cargo run --bin hermes -- -c namada_e2e_config.toml start
```

Congratulaitons, you now (hopefully) have 2 local namada chains running in the background.

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
export HERMES_CONFIG=
cargo run --bin hermes -- -c ${HERMES_CONFIG} \
create channel ${CHAIN_A_ID} --chain-b ${CHAIN_B_ID} \
--port-a transfer --port-b transfer \
--new-client-connection
```

## Transferring assets across
This will establish a connection that will allow you to make transfers across chains.

We begin by exporting some helpful variables

We first need to specify the base directory for each chain, so that the client knows what chain it is calling.

```bash!
export BASE_DIR_A="$HOME/ibc-rs/data/namada-a/.namada"
```

```bash!
export BASE_DIR_B="$HOME/ibc-rs/data/namada-b/.namada"
```

To find your ledger address for CHAIN_A, you can run the following command
```bash!
export LEDGER_ADDRESS_A = "$(grep "rpc_address" ~/ibc-rs/data/namada-a/.anoma/${CHAIN_A_ID}/setup/validator-0/.anoma/${CHAIN_A_ID}/config.toml)"
```
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

