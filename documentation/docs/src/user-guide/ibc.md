# Using IBC with Namada

This document describes using the inter-blockchain communication (IBC) protocol with Namada. This documentation covers being able to create connections through IBC as well as setting up local instances of Namada for testing purposes.

> **Warning**
>
> This feature is currently in development. Expect the unexpected.

This document will cover three essential steps for using IBC with Namada

1. [Setup Hermes](#setup-hermes)
2. [Setup nodes for Namada instances](#setup-nodes-for-namada-instances)
3. [Transferring assets over IBC](#transferring-assets-over-IBC)

The below is intended for those that wish to conduct IBC message transfers between two Namada chains. There is of course the cabablitiy to do this between any two IBC compatible chains (such as a cosmos chain). In this case, it is necessary to have a node of both the destination and the source chain running in order to make any package transfers. Below, we discuss first how to enable this connection between two pre-existing chains by Hermes, and second setting up 2 Namada local instances or joining two pre-existing Namada instances for this purpose.

## Setup Hermes
Hermes is an IBC relayer to relay packets between chains(instances). We have our [Hermes supporting Namada instances](https://github.com/heliaxdev/ibc-rs/tree/yuji/v0.14.0_namada).
Before packet relay, we need the following step to configure and start Hermes.

1. Make Hermes config file
2. Create IBC client/connection/channel between instances
3. Run Hermes

### Make Hermes config file
One essential piece of the puzzle is to create a `config.toml` file that describes what connections will be set up that the relayer will be responsible for.

```bash!
export HERMES_CONFIG="<choose path for hermes config>/config.toml"
touch $HERMES_CONFIG
``` 

If you don't specify the file path, `~/.hermes/config.toml` is read as default.

You can find an example of the config file [here](https://hackmd.io/l6HNSqJmQt6QfkjfTmSfbw). Essentially, you change only the chain IDs, the RPC addresses, and the key names in the config file for Namada. If you don't have nodes, please set up nodes manually or through our [scripts](#setup-nodes-for-namada-instances).

The path to the config file, which is is saved in the variable `$HERMES_CONFIG` will be useful later.

```admonish note

 **Interpreting the toml**

 Each chain configuration is specified under the `[[chains]]` object.

 These are the pieces of this puzzle you want to keep your :eyes: on:
 - `chains.id` is the name of the chain
 - `chains.rpc_address` specifies the port that the channel is communicating through, and will be the argument for the `ledger_address` of Namada when interacting with the ledger (will become clearer later)
     - Make sure to change the IP address to the IP address of your local machine that is running this node!
 - `chains.key_name` specifies the key of the signer who signs a transaction from the relayer. The key should be generated before starting the relayer.
```

### Create IBC client/connection/channel between instances
Hermes CLI has commands to create them. Before the creation, a node of each instance should be running.

#### Install Hermes
Before conducting any IBC operations, we build Heliax's Hermes fork from source.

```bash
export COMMIT="470137e845b997228f9bcda8eec8bc02bd0be6da"
git clone git@github.com:heliaxdev/ibc-rs.git
git checkout $COMMIT
cd ibc-rs
cargo build --release --bin hermes
export IBC_RS=$(pwd) # if needed
```
Check the binary:
```bash
./target/release/hermes --version
```

````admonish note
It is recommended to now add hermes to `$PATH` such that it is callable without any pre-fixes.
For ubuntu users, this can be achieved by
```bash
cp ./target/release/hermes /usr/local/bin/
```
````

### Create IBC channel
The "create channel" command (below) creates not only the IBC channel but also the necessary IBC client connection.

```bash
hermes -c $HERMES_CONFIG \
  create channel $CHAIN_A_ID \
  --chain-b $CHAIN_B_ID \
  --port-a transfer \
  --port-b transfer \
  --new-client-connection
```

```admonish note
Note that the above `CHAIN_IDs` will depend on your own setup, so do check this for yourself!
```

This command will ask you with the following message. You can continue with `y`.
```
to re-use a pre-existing connection. [y/n]
```

When the creation has been completed, you can see the channel IDs. For example, the following text shows that a channel with ID `7` has been created on Chain A `namada-test.0a4c6786dbda39f786`, and a channel with ID `12` has been created on Chain B `namada-test.647287156defa8728c`. You will need the channel IDs for a transfer over IBC. It means that you have to specify `channel-7` as a channel ID (The prefix `channel-` is always required) for a transfer from Chain A to Chain B. Also, you have to specify `channel-12` as a channel ID for a transfer from Chain B to Chain A.
```
Success: Channel {
    ordering: Unordered,
    a_side: ChannelSide {
        chain: BaseChainHandle {
            chain_id: ChainId {
                id: "namada-test.0a4c6786dbda39f786",
                version: 0,
            },
            runtime_sender: Sender { .. },
        },
        client_id: ClientId(
            "07-tendermint-0",
        ),
        connection_id: ConnectionId(
            "connection-3",
        ),
        port_id: PortId(
            "transfer",
        ),
        channel_id: Some(
            ChannelId(
                7,
            ),
        ),
        version: None,
    },
    b_side: ChannelSide {
        chain: BaseChainHandle {
            chain_id: ChainId {
                id: "namada-test.647287156defa8728c",
                version: 0,
            },
            runtime_sender: Sender { .. },
        },
        client_id: ClientId(
            "07-tendermint-1",
        ),
        connection_id: ConnectionId(
            "connection-2",
        ),
        port_id: PortId(
            "transfer",
        ),
        channel_id: Some(
            ChannelId(
                12,
            ),
        ),
        version: None,
    },
    connection_delay: 0ns,
}
```

### Run Hermes
Once you run Hermes, it monitors instances via the nodes and relays packets according to monitored events.
```bash
hermes -c $HERMES_CONFIG start
```

## Setup nodes for Namada instances
We need a node for each instance to be monitored by Hermes. In this document, we will set up two local nodes for two instances. But, of course, the node doesn't have to be on the same machine as Hermes.

We will explain for two cases:
- Set up nodes to join existing Namada instances
- Set up local Namada instances for testing purposes

Before running the following scripts, you have to build Namada and wasm.
```bash
git clone git@github.com:anoma/namada.git
cd namada
git checkout v0.12.2
make build-release
make build-wasm-scripts
export NAMADA_DIR=$(pwd) # if needed
```

You can use scripts in [our Hermes branch](https://github.com/heliaxdev/ibc-rs/tree/yuji/v0.14.0_namada) to setup these nodes automatically.

### Set up nodes to join existing Namada instances
The script `join-namada.sh` will set up two nodes for two instances, copy necessary files for Hermes, and make an account for Hermes on each ledger. Also, it will make a Hermes' config file `config_for_namada.toml` in the `ibc-rs` directory.

The script requires the Namada directory path and chain IDs.
```bash
git clone git@github.com:heliaxdev/ibc-rs.git
git checkout $COMMIT # The branch is the same as our Hermes
cd ibc-rs
./scripts/join-namada.sh $NAMADA_DIR $CHAIN_ID_A $CHAIN_ID_B
```

You need to wait to sync each node with the corresponding instance.
And, you have to transfer NAM token to the relayer account (the script will make an alias `relayer`) from the faucet or others on each instance because the fee for IBC transactions should be charged. For example, the following command transfers NAM from the faucet for namada-a instance which is created by the script. You can refer to [here](#transferring-assets-over-ibc) about `--base-dir` and `--ledger-address`.
```bash
${NAMADA_DIR}/target/release/namadac transfer \
  --base-dir ${IBC_RS}/data/namada-a/.namada \
  --source faucet \
  --target relayer \
  --token nam \
  --amount 1000 \
  --signer relayer \
  --ledger-address 127.0.0.1:26657
```

After the sync, you can create the channel and start Hermes as we explain [above](#create-ibc-channel).
```bash
# create a channel
hermes -c $HERMES_CONFIG \
  create channel $CHAIN_A_ID \
  --chain-b $CHAIN_B_ID \
  --port-a transfer \
  --port-b transfer \
  --new-client-connection

# Run Hermes
hermes -c $HERMES_CONFIG start
```

Each node data and configuration files are in `${IBC_RS}/data/namada-*/.namada`.

In order to close any ledgers setup by the script, one can run
```bash
killall namadan
```

### Set up local Namada instances
The script `setup-namada.sh` will set up two instances with one validator node, copy necessary files for Hermes, and make an account for Hermes on each ledger. Also, it will make a Hermes' config file `config_for_namada.toml` in the `ibc-rs` directory.
```bash
git clone git@github.com:heliaxdev/ibc-rs.git
git checkout $COMMIT # The branch is the same as our Hermes
cd ibc-rs
./scripts/setup-namada.sh $NAMADA_DIR $CHAIN_ID_A $CHAIN_ID_B
```

In this case, we don't have to wait for sync. If the relayer account on each instance has enough balance, you can create a channel and start Hermes immediately as we explain [above](#create-ibc-channel). You find these chain IDs of the instances in the config file `config_for_namada.toml`. One can run `grep "id" ${HERMES_CONFIG}`.
```bash
# create a channel
hermes -c $HERMES_CONFIG \
  create channel $CHAIN_A_ID \
  --chain-b $CHAIN_B_ID \
  --port-a transfer \
  --port-b transfer \
  --new-client-connection

# Run Hermes
hermes -c $HERMES_CONFIG start
```

Each node data and configuration files are in `ibc-rs/data/namada-*/.namada`.

In order to close any ledgers setup by the script, one can run
```bash
killall namadan
```

## Transferring assets over IBC
This will make transfers across chains by Namada CLI. This assumes that a channel has been created and Hermes is running with the proper config.

In order to do this by Namada's `ibc-transfer` command, we will need to know the `base-dir` and `ledger-address` of each instance (and other transfer parameters).
`base-dir` is the base directory of each node. If you have used the script, the direcotry is `${IBC_RS}/data/namada-*/.namada`.
`ledger-address` is `rpc_addr` in the relevant hermes' config files.
One can run `grep "rpc_addr" ${HERMES_CONFIG}`.


````admonish note
 **For the local node ONLY**

 To find your ledger address for Chain A, you can run the following command
 ```bash
 export BASE_DIR_A = "${IBC_RS}/data/namada-a/.namada"
 export LEDGER_ADDRESS_A = "$(grep "rpc_address" ${BASE_DIR_A}/${CHAIN_A_ID}/setup/validator-0/.namada/${CHAIN_A_ID}/config.toml)"
 ```
````

And then the channel ID for this chain will depend on the order in which one created the channel. Since we have only opened one channel, the `channel-id` is `channel-0`, but as more are created, these increase by index incremented by 1. Please refer to [here](#create-ibc-channel).

So one can go ahead and run
```bash
export CHANNEL_ID = "channel-0"
```

Such transfers from Chain A can be achieved by

```bash
namadac --base-dir ${BASE_DIR_A}
    ibc-transfer \
        --amount ${AMOUNT} \
        --source ${SOURCE_ALIAS} \
        --receiver ${RECEIVER_RAW_ADDRESS} \
        --token ${TOKEN_ALIAS} \
        --channel-id ${CHANNEL_ID} \
        --ledger-address ${LEDGER_ADDRESS_A}
```
Where the above variables in `${VARIABLE}` must be substituted with appropriate values. The raw address of the receiver can be found by `namadaw --base-dir ${BASE_DIR_B} address find --alias ${RECEIVER}`.

E.g

```bash
namadac --base-dir ${BASE_DIR_A}
    ibc-transfer \
    --amount 100 \
    --source albert \
    --receiver atest1d9khqw36g56nqwpkgezrvvejg3p5xv2z8y6nydehxprygvp5g4znj3phxfpyv3pcgcunws2x0wwa76 \
    --token nam \
    --channel-id channel-0 \
    --ledger-address 127.0.0.1:27657
```
