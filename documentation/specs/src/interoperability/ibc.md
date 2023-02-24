# IBC integration

* [IBC (Inter-blockchain communication protocol) spec](https://github.com/cosmos/ibc)
* [IBC integration in Namada](https://github.com/anoma/namada/blob/yuji/design_ibc/docs/src/explore/design/ledger/ibc.md)

## IBC transaction
An IBC transaction [`tx_ibc.wasm`](https://github.com/anoma/namada/blob/e3c2bd0b463b35d66fcc6d2643fd0e6509e03d99/wasm/wasm_source/src/tx_ibc.rs) is provided. We have to set an IBC message to the transaction data corresponding to execute an IBC operation.

The transaction decodes the data to an IBC message and handles IBC-related data, e.g. it makes a new connection ID and writes a new connection end for `MsgConnectionOpenTry`. The operations are implemented in [`IbcActions`](https://github.com/anoma/namada/blob/e3c2bd0b463b35d66fcc6d2643fd0e6509e03d99/core/src/ledger/ibc/actions.rs). The transaction doesn't check the validity for the state changes. IBC validity predicate and IBC token validity predicate are in charge of the validity.

## IBC validity predicate
[IBC validity predicate](https://github.com/anoma/namada/blob/e3c2bd0b463b35d66fcc6d2643fd0e6509e03d99/shared/src/ledger/ibc/vp/mod.rs) checks if an IBC transaction satisfies IBC protocol. When an IBC transaction is executed, i.e. a transaction changes the state of the key that contains [`InternalAddress::Ibc`](https://github.com/anoma/namada/blob/e3c2bd0b463b35d66fcc6d2643fd0e6509e03d99/core/src/types/address.rs#L446), IBC validity predicate (one of the native validity predicates) is executed. For example, if an IBC connection end is created in the transaction, IBC validity predicate validates the creation. If the creation with `MsgConnectionOpenTry` is invalid, e.g. the counterpart connection end doesn't exist, the validity predicate makes the transaction fail.

## Fungible Token Transfer
The transfer of fungible tokens over an IBC channel on separate chains is defined in [ICS20](https://github.com/cosmos/ibc/blob/master/spec/app/ics-020-fungible-token-transfer/README.md).

In Namada, the sending tokens is triggered by a transaction having [MsgTransfer](https://github.com/informalsystems/ibc-rs/blob/0a952b295dbcf67bcabb79ce57ce92c9c8d7e5c6/modules/src/applications/ics20_fungible_token_transfer/msgs/transfer.rs#L20-L37) as transaction data. A packet including [`FungibleTokenPacketData`](https://github.com/anoma/namada/blob/e3c2bd0b463b35d66fcc6d2643fd0e6509e03d99/core/src/ledger/ibc/data.rs#L392) is made from the message in the transaction execution.

Namada chain receives the tokens by a transaction having [MsgRecvPacket](https://github.com/informalsystems/ibc-rs/blob/0a952b295dbcf67bcabb79ce57ce92c9c8d7e5c6/modules/src/core/ics04_channel/msgs/recv_packet.rs#L19-L23) which has the packet including `FungibleTokenPacketData`.

The sending and receiving tokens in a transaction are validated by not only IBC validity predicate but also [IBC token validity predicate](https://github.com/anoma/namada/blob/e3c2bd0b463b35d66fcc6d2643fd0e6509e03d99/shared/src/ledger/ibc/vp/token.rs). IBC validity predicate validates if sending and receiving the packet is proper. IBC token validity predicate is also one of the native validity predicates and checks if the token transfer is valid. If the transfer is not valid, e.g. an unexpected amount is minted, the validity predicate makes the transaction fail.

A transaction escrowing/unescrowing a token changes the escrow account's balance of the token. The key is `{token_addr}/ibc/{port_id}/{channel_id}/balance/IbcEscrow`. A transaction burning a token changes the burn account's balance of the token. The key is `{token_addr}/ibc/{port_id}/{channel_id}/balance/IbcBurn`. A transaction minting a token changes the mint account's balance of the token. The key is `{token_addr}/ibc/{port_id}/{channel_id}/balance/IbcMint`.  The key including `IbcBurn` or `IbcMint` have the balance temporarily for validity predicates. It isn't committed to a block. `IbcEscrow`, `IbcBurn`, and `IbcMint` are addresses of [`InternalAddress`](https://github.com/anoma/namada/blob/e3c2bd0b463b35d66fcc6d2643fd0e6509e03d99/core/src/types/address.rs#L446) and actually they are encoded in the storage key. When these addresses are included in the changed keys after transaction execution, IBC token validity predicate is triggered.

The receiver's account is `{token_addr}/ibc/{ibc_token_hash}/balance/{receiver_addr}`. `{ibc_token_hash}` is a hash calculated with the denomination prefixed with the port ID and channel ID. It is NOT the same as the normal account `{token_addr}/balance/{receiver_addr}`. That's because it should be origin-specific for transferring back to the source chain. We can transfer back the received token by setting `ibc/{ibc_token_hash}` or `{port_id}/{channel_id}/{token_addr}` as `denom` in `MsgTransfer`.

For example, we transfer a token `#my_token` from a user `#user_a` on Chain A to a user `#user_b` on Chain B, then transfer back the token from `#user_b` to `#user_a`. The port ID and channel ID on Chain A for Chain B are `transfer` and `channel_42`, those on Chain B for Chain A are `transfer` and `channel_24`. The denomination in the `FungibleTokenTransferData` at the first transfer should be `#my_token`.
1. User A makes `MsgTransfer` as a transaction data and submits a transaction from Chain A
```rust
    let token = Some(Coin {
        denom, // #my_token
        amount: "100000".to_string(),
    });
    let msg = MsgTransfer {
        source_port,    // transfer
        source_channel, // channel_42
        token,
        sender,   // #user_a
        receiver, // #user_b
        timeout_height: Height::new(0, 1000),
        timeout_timestamp: (Timestamp::now() + Duration::new(100, 0)).unwrap(),
    };
```
2. On Chain A, the specified amount of the token is transferred from the sender's account `#my_token/balance/#user_a` to the escrow account `#my_token/ibc/transfer/channel_42/balance/IbcEscrow`
3. On Chain B, the amount of the token is transferred from `#my_token/ibc/transfer/channel_24/balance/IbcMint` to `#my_token/ibc/{hash}/balance/#user_b`
    - The `{hash}` is calculated from a string `transfer/channel_24/#my_token` with SHA256
    - The `{hash}` is a fixed length because of hashing even if the original denomination becomes too long with many prefixes after transferring through many chains
4. To transfer back, User B makes `MsgTransfer` and submits a transaction from Chain B
```rust
    let token = Some(Coin {
        denom, // ibc/{hash} or transfer/channel_24/#my_token
        amount: "100000".to_string(),
    });
    let msg = MsgTransfer {
        source_port,    // transfer
        source_channel, // channel_24
        token,
        sender,   // #user_b
        receiver, // #user_a
        timeout_height: Height::new(0, 1000),
        timeout_timestamp: (Timestamp::now() + Duration::new(100, 0)).unwrap(),
    };
```
5. On Chain B, the amount of the token is transferred from `#my_token/ibc/{hash}/balance/#user_b` to `#my_token/ibc/transfer/channel_24/IbcBurn`
6. On Chain A, the amount of the token is transferred from `#my_token/ibc/transfer/channel_42/balance/IbcEscrow` to `#my_token/balance/#user_a`

## IBC message

IBC messages are defined in `ibc-rs`. The message should be encoded with Protobuf (NOT with Borsh) as the following code to set it as a transaction data.

```rust
use ibc::tx_msg::Msg;

pub fn make_ibc_data(message: impl Msg) -> Vec<u8> {
    let msg = message.to_any();
    let mut tx_data = vec![];
    prost::Message::encode(&msg, &mut tx_data).expect("encoding IBC message shouldn't fail");
    tx_data
}
```

* Client
  - [MsgCreateAnyClient](https://github.com/informalsystems/ibc-rs/blob/5ddec6d2571b1376de7d9ebe7e353b3cd726c2d3/modules/src/core/ics02_client/msgs/create_client.rs#L19-L23)
  - [MsgSubmitAnyMisbehaviour](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics02_client/msgs/misbehavior.rs#L17-L24) (NOT supported yet)
  - [MsgUpdateAnyClient](https://github.com/informalsystems/ibc-rs/blob/5ddec6d2571b1376de7d9ebe7e353b3cd726c2d3/modules/src/core/ics02_client/msgs/update_client.rs#L20-L24)
  - [MsgUpgradeAnyClient](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics02_client/msgs/upgrade_client.rs#L24-L31)

* Connection
  - [MsgConnectionOpenInit](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics03_connection/msgs/conn_open_init.rs#L21-L27)
  - [MsgConnectionOpenTry](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics03_connection/msgs/conn_open_try.rs#L29-L38)
  - [MsgConnectionOpenAck](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics03_connection/msgs/conn_open_ack.rs#L20-L27)
  - [MsgConnectionOpenConfirm](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics03_connection/msgs/conn_open_confirm.rs#L19-L23)

* Channel
  - [MsgChannelOpenInit](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/chan_open_init.rs#L17-L21)
  - [MsgChannelOpenTry](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/chan_open_try.rs#L22-L29)
  - [MsgChannelOpenAck](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/chan_open_ack.rs#L18-L25)
  - [MsgChannelOpenConfirm](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/chan_open_confirm.rs#L18-L23)
  - [MsgRecvPacket](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/recv_packet.rs#L19-L23)
  - [MsgAcknowledgement](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/acknowledgement.rs#L19-L24)
  - [MsgChannelCloseInit](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/chan_close_init.rs#L18-L22)
  - [MsgChannelCloseConfirm](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/chan_close_confirm.rs#L20-L25)
  - [MsgTimeout](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/timeout.rs#L19-L24)
  - [MsgTimeoutOnClose](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/core/ics04_channel/msgs/timeout_on_close.rs#L18-L23)

* ICS20 FungibleTokenTransfer
  - [MsgTransfer](https://github.com/informalsystems/ibc-rs/blob/1448a2bbc817da10b183b8479548a12344ba0e9c/modules/src/applications/ics20_fungible_token_transfer/msgs/transfer.rs#L20-L37)
