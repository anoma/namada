# Transferring assets from Ethereum to Namada

In order to facilitate transferring assets from Ethereum to Namada, There
will be two internal accounts with associated native validity predicates:

- `#EthBridge` - Controls the `/eth_msgs/` [storage](ethereum_events_attestation.md#storage)
- and ledgers of balances
  for wrapped Ethereum assets (ERC20 tokens) structured in a
  ["multitoken"](https://github.com/anoma/anoma/issues/1102) hierarchy
- `#EthBridgeEscrow` which will hold in escrow wrapped Namada tokens which have
  been sent to Ethereum.

#### Wrapped ERC20

If an ERC20 token is transferred to Namada, once the associated 
`TransferToNamada` Ethereum event is included into Namada, validators mint 
the appropriate amount to the corresponding  multitoken balance key for 
the receiver, or release the escrowed native Namada token.

```rust
pub struct EthAddress(pub [u8; 20]);

/// An event transferring some kind of value from Ethereum to Namada
pub struct TransferToNamada {
    /// Quantity of ether in the transfer
    pub amount: Amount,
    /// Address on Ethereum of the asset
    pub asset: EthereumAsset,
    /// The Namada address receiving wrapped assets on Namada
    pub receiver: Address,
}
```

##### Example

For 10 DAI i.e. ERC20([0x6b175474e89094c44da98b954eedeac495271d0f](https://etherscan.io/token/0x6b175474e89094c44da98b954eedeac495271d0f)) to `atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt`
```
#EthBridge
    /ERC20
        /0x6b175474e89094c44da98b954eedeac495271d0f
            /balance
                /atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt 
                += 10
```

#### Namada tokens

Any wrapped Namada tokens being redeemed from Ethereum must have an 
equivalent amount of the native token held in escrow by `#EthBridgeEscrow`.
Once the associated`TransferToNamada` Ethereum event is included into 
Namada, validators should simply make a transfer from `#EthBridgeEscrow` to 
the `receiver` for the appropriate amount and asset.
