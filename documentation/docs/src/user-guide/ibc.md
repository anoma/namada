# Using IBC with Namada

This document describes using the inter-blockchain communication (IBC) protocol with Namada. This documentation covers being able create connections through IBC as well as setting up local fractal instances of Namada for testing purposes.

:::warning
Warning! This is quite an advanced feature at the moment and is currently in development
:::

## Setting up

The below is intended for those that wish to conduct IBC message transfer between two Namada chains. There is of course the cabablitiy to do this between any two IBC compatible chains (such as a cosmos chain). In this case, it is necessary to have a node of both the destination and the source chain running in order to make any package transfers. Below, we discuss setting up 2 Namada chains for this purpose.

### Downloading the IBC-rs repo

In order to create the relayer that is able to set up IBC connections, the following repo will need to be cloned. Then we enter the directory.

```bash=
git clone git@github.com:heliaxdev/ibc-rs.git && cd ibc-rs
```




### Running multiple instances of Namada

In order to make IBC transfers across two Namada chains, one must be running two nodes of Namada at once. In order to do this, two CHAIN-IDs will need to be retrieved. In the case that there is only 1 testnet running, one may need to setup a local namada chain (which will be proof of authority since you will be the only one running it :P).

Below, I discuss how to setup connections between two local namada testnets, and I append how to achieve ibc package transfers between arbitrary chain_ids afterwards.

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
./e2e/namada-test.sh ${NAMADA_DIR}
#Followed by
cargo run --bin hermes -- -c namada_e2e_config.toml start
```

Congratulaitons, you now (hopefully) have 2 local namada chains running in the background.

### Opening up communication
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


This will establish a connection that will allow you to make transfers across chains.

Such transfers can be achieved by

```bash!
namadac ibc-transfer \
    --amount ${AMOUNT} \
    --source ${SOURCE_ALIAS} \
    --receiver ${RECEIVER_RAW_ADDRESS} \
    --token ${TOKEN_ALIAS} \
    --channel-id ${CHANNEL_ID} \
    --ledger-address ${LEDGER_ADDRESS}
```
Where the above variables in `${VARIABLE}` must be substituted with appropriate values.

E.g

```bash!
namadac ibc-transfer \
    --amount 100 \
    --source albert \
    --receiver cosmos1lkp4xrhd5hh3f7u5n2aj429upuur3wk28qgtll \
    --token xan \
    --channel-id channel-0 \
    --ledger-address 127.0.0.1:27657
```

To find your ledger address for CHAIN_A, you can run the following command

```bash!
grep "net_address" .anoma/${CHAIN_A_ID}/setup/validator-0/.anoma/${CHAIN_A_ID}.toml 
```

In order to close any ledgers setup by the script, one can run

`killall namadan`

