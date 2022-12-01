## IBC Protocol

The web wallet must be able to transfer token amounts to other chains via the Inter-Blockchain Communication Protocol (IBC).

We need to be able to support the following:

- Fungible token transfer (ICS020) from Namada to other Namada chains
- Fungible token transfer (ICS020) from Namada to Cosmos

What the UI will need to display to the user:

- Select a chain (chain ID) as destination
- Enter a channel ID for destination (e.g., `channel-0`)
- Specify a receiver address
- Specify a token
- Specify an amount to transfer

The web wallet will need to construct a `MsgTransfer` struct, which will get wrapped in a normal, signed transaction and broadcasted to the source ledger (this struct is passed into the `Tx` `data`):

```rust
MsgTransfer {
	source_port: String,
	source_channel: String,
	token: Option<Coin>,
	sender: Signer,
	receiver: Signer,
	timeout_height: Height,
	timeout_timestamp: Timestamp
}
```

A populated `MsgTransfer` with a disabled block-height timeout (instead using a timestamp timeout), may look like the following:

```rust
MsgTransfer {
	source_port: PortId("transfer"),
	source_channel: ChannelId("channel-0"),
	token: Some(Coin {
		denom: "atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5",
		amount: "1.23456"
	}),
	sender: Signer( "atest1v4ehgw36xvmrgdfsg9rrwdzxgfprq32yxvensdjxgcurxwpeg5mrxdpjxfp5gdp3xqu5gs2xd8k4aj"
	),
	receiver: Signer( "atest1d9khqw36xu6njwp4x5eyz334g4zrjvz9gyungv6p8yurys3jxymrxvzy89pyzv2pxaprzsfedvglv2"
	),
	timeout_height: Height {
		revision: 0,
		height: 0
	},
	timeout_timestamp: Timestamp {
		time: Some(Time(PrimitiveDateTime {
			date: Date {
				year: 2022,
				ordinal: 124
			},
			time: Time {
				hour: 14,
				minute: 15,
				second: 33,
				nanosecond: 0
			}
		}))
	}
}
```

**NOTE** Unlike with `tx_transfer`, the amount we pass with the Token is _not_ submitted in micro-units, but as a regular `f32` value. No conversion is needed in the web wallet.

Once this transaction is unwrapped and validated, `apply_tx` will invoke `IBC.dispatch()` (see: <https://github.com/anoma/namada/blob/master/wasm/wasm_source/src/tx_ibc.rs>).

When this is executed on the source chain, the balance will be deducted on the source account, so we need to reflect this in the interface. If the transaction succeeds, query
the balance for that token and display to the user.

## Testing

Instructions for setting up local Namada chains, along with the Hermes relatyer (`ibc-rs`) can be found here:

<https://hackmd.io/@heliax/BJ5Gmyxrq>

The wallet UI will need to be configured to connect to the source chain from which you want to transfer tokens. The user will have to enter a valid channel ID
in the interface, in addition to an established address on the destination chain (the receiver).

## Configuration

The wallet web app should accept a configuration per-environment that will contain not only the default network, but the possible destination networks that the user can transfer tokens to. We need the following information for each, at a minimum:

- A user-friendly alias naming the network
- Destination URL
- Destination Port
- A non-default `portId`, if necessary, though in most cases, the default of `transfer` would likely be used.

## Resources

- [Namada Ledger IBC Rust Docs](https://docs.namada.network/master/rustdoc/namada/ledger/ibc/)
- [HackMD IBC Summary](https://hackmd.io/H2yGO3IQRLiWCPWwQQdVow)
- [ibc-rs](https://github.com/informalsystems/ibc-rs/)
- [ICS020 - Fungible Token Transfers](https://github.com/cosmos/ibc/blob/master/spec/app/ics-020-fungible-token-transfer/README.md)
- <https://spec.namada.network/master/architecture/namada/ibc.html>
- <https://ibc.cosmos.network/main/ibc/overview.html>
- <https://ibcprotocol.org/>

Cosmos relayers:

- <https://hub.mintscan.io/ibc-network>
- <https://www.mintscan.io/osmosis/relayers>
