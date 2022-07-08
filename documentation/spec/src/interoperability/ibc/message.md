# IBC message

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
