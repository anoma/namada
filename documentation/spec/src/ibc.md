# IBC integration

* [IBC (Inter-blockchain communication protocol) spec](https://github.com/cosmos/ibc)
* [IBC integration in Anoma](https://github.com/anoma/anoma/blob/yuji/design_ibc/docs/src/explore/design/ledger/ibc.md) (Need to be updated)

## IBC transaction
An IBC transaction [`tx_ibc.wasm`](https://github.com/anoma/anoma/blob/fd4b7ab36929f47369ae82c82966891cb0ccc625/wasm/wasm_source/src/lib.rs#L224-L233) is provided. We have to set an [IBC message](./ibc/message.md) to the transaction data corresponding to execute an IBC operation.

The transaction decodes the data to an IBC message and handles IBC-related data, e.g. it makes a new connection ID and writes a new connection end for `MsgConnectionOpenTry`. The operations are implemented in [`IbcActions`](https://docs.anoma.network/master/rustdoc/anoma/ledger/ibc/handler/trait.IbcActions.html).The transaction doesn't check the validity for the state changes. IBC validity predicate is in charge of the validity.

## IBC validity predicate
[IBC validity predicate](https://docs.anoma.network/master/rustdoc/anoma/ledger/ibc/vp/struct.Ibc.html#impl-NativeVp) checks if an IBC-related transaction satisfies IBC protocol. When an IBC-related transaction is executed, i.e. a transaction changes the state of the key that contains [`InternalAddress::Ibc`](https://docs.anoma.network/master/rustdoc/anoma/types/address/enum.InternalAddress.html#variant.Ibc), IBC validity predicate (one of the native validity predicates) is executed. For example, if an IBC connection end is created in the transaction, IBC validity predicate validates the creation. If the creation with `MsgConnectionOpenTry` is invalid, e.g. the counterpart connection end doesn't exist, the validity predicate makes the transaction fail.

## Fungible Token Transfer
The transfer of fungible tokens over an IBC channel on separate chains is defined in [ICS20](https://github.com/cosmos/ibc/blob/master/spec/app/ics-020-fungible-token-transfer/README.md).

In Anoma, the sending tokens is triggered by a transaction having [MsgTransfer](https://github.com/informalsystems/ibc-rs/blob/0a952b295dbcf67bcabb79ce57ce92c9c8d7e5c6/modules/src/applications/ics20_fungible_token_transfer/msgs/transfer.rs#L20-L37) as transaction data. A packet including [`FungibleTokenPacketData`](https://docs.anoma.network/master/rustdoc/anoma/types/ibc/data/struct.FungibleTokenPacketData.html) is made from the message in the transaction execution.

Anoma chain receives the tokens by a transaction having [MsgRecvPacket](https://github.com/informalsystems/ibc-rs/blob/0a952b295dbcf67bcabb79ce57ce92c9c8d7e5c6/modules/src/core/ics04_channel/msgs/recv_packet.rs#L19-L23) which has the packet including `FungibleTokenPacketData`.

The sending and receiving tokens in a transaction are validated by not only IBC validity predicate but also [IBC token validity predicate](https://docs.anoma.network/master/rustdoc/anoma/ledger/ibc/vp/struct.IbcToken.html#impl-NativeVp). IBC validity predicate validates if sending and receiving the packet is proper. IBC token validity predicate is also one of the native validity predicates and checks if the token transfer is valid. If the transfer is not valid, e.g. the unexpected amount is minted, the validity predicate makes the transaction fail.

A transaction escrowing/unescrowing a token changes the escrow account's balance of the token. The key is `{token_addr}/balance/{escrow_addr}`. A transaction burning a token changes the burn account's balance of the token. The key is `{token_addr}/balance/BURN_ADDR`. A transaction minting a token changes the mint account's balance of the token. The key is `{token_addr}/balance/MINT_ADDR`. `{escrow_addr}`, `{BURN_ADDR}`, and `{MINT_ADDR}` are addresses of [`InternalAddress`](https://docs.anoma.network/master/rustdoc/anoma/types/address/enum.InternalAddress.html). When these address are included of the change keys after transaction execution, IBC token validity predicate is executed.
