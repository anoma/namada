# Transferring from Namada to Ethereum

Moving assets from Namada to Ethereum will not be automatic, as opposed the
movement of value in the opposite direction. Instead, users must send an
appropriate transaction to Namada to initiate a transfer across the bridge
to Ethereum. Once this transaction is approved, the parts necessary to create
a ["proof"](proofs.md) will be created and posted on Namada. Relayer processes
can choose batches of pending transfers to Ethereum to be relayed.

It is incumbent on relayers to request an appropriate proof of existence of
such transactions. This proof must be submitted to the appropriate Ethereum smart
contract to redeem Ethereum assets / mint wrapped assets. Ethereum gas costs are
the responsibility of the end user, who should escrow NAM in `#EthBridgePool`.
After relaying a batch of pending transfers to Ethereum that make economic sense,
fees in NAM are released from `#EthBridgePool` into the relayer's address.

## Moving value to Ethereum

To redeem wrapped Ethereum assets, a user should make a transaction to burn
their wrapped tokens, which the `#EthBridge` validity predicate will accept.
For sending NAM over the bridge, a user should escrow their NAM in
`#EthBridge`. In both cases, it's important that the user also adds a
`PendingTransfer` to the [Bridge Pool](#bridge-pool-validity-predicate).

## Batching

Ethereum gas fees make it prohibitively expensive to submit
the proof for a single transaction over the bridge. Instead, it is typically
more economical to submit proofs of many transactions in bulk. This batching
is described in this section.

A pool of transfers from Namada to Ethereum will be kept by Namada. Every
transaction to Ethereum that Namada validators approve will be added to this
pool. We call this the _Bridge Pool_.

The Bridge Pool should be thought of as a sort of mempool. When users who
wish to move assets to Ethereum submit their transactions, they will pay some
additional amount of NAM (of their choosing) as a way of covering the gas
costs on Ethereum. Namada validators will hold these fees in a Bridge Pool
Escrow.

When a batch of transactions from the Bridge Pool is submitted by a user to
Ethereum, Namada validators will receive notifications via their full nodes.
They will then pay out the fees for each submitted transaction to the user who
relayed these transactions (still in NAM). These will be paid out from the
Bridge Pool Escrow.

The idea is that users will only relay transactions from the Bridge Pool
that make economic sense. This prevents DoS attacks by underpaying fees as
well as obviating the need for Ethereum gas price oracles. It also means
that transfers to Ethereum are not ordered, preventing other attack vectors.

The Bridge Pool will be organized as a Merkle tree. Every time it is updated,
the root of tree must be signed by a quorum of validators. When a user
wishes to construct a batch of transactions to relay to Ethereum, they
include the signed tree root and inclusion proofs for the subset of the pool
they are relaying. This can be easily verified by the Ethereum smart contracts.

If vote extensions are available, these are used to collect the signatures
over the Merkle tree root. If they are not, these must be submitted as protocol
transactions, introducing latency to the pool. A user wishing to relay will
need to wait until a Merkle tree root is signed for a tree that
includes all the transactions they wish to relay.

The Ethereum smart contracts won't keep track of this signed Merkle root. 
Instead, part of the proof of correct batching is submitting a root to the 
contracts that is signed by quorum of validators. Since the smart contracts 
can trust such a signed root, it can then use the root to verify inclusion 
proofs.

### Bridge Pool validity predicate

The Bridge Pool will have associated storage under the control of a native 
validity predicate. The storage layout looks as follows.

```
# all values are Borsh-serialized
/pending_transfers: Vec<PendingTransfer>
/signed_root: Signed<MerkleRoot>
```

The pending transfers are instances of the following type:
```rust
pub struct TransferToEthereum {
    /// The type of token 
    pub asset: EthAddress,
    /// The recipient address
    pub recipient: EthAddress,
    /// The amount to be transferred
    pub amount: Amount,
    /// a nonce for replay protection
    pub nonce: u64,
}

pub struct PendingTransfer {
    /// The message to send to Ethereum to 
    /// complete the transfer
    pub transfer: TransferToEthereum,
    /// The gas fees paid by the user sending
    /// this transfer
    pub gas_fee: GasFee,
}

pub struct GasFee {
    /// The amount of gas fees (in NAM)
    /// paid by the user sending this transfer
    pub amount: Amount,
    /// The address of the account paying the fees
    pub payer: Address,
}
```
When a user submits initiates a transfer, their transaction should include wasm
to craft a `PendingTransfer` and append it to the pool in storage as well as 
send the relevant gas fees into the Bridge Pool's escrow.  This will be 
validated by the Bridge Pool vp. 

The signed Merkle root is only modifiable by validators. The Merkle tree 
only consists of the `TransferToEthereum` messages as Ethereum does not need 
information about the gas fees paid on Namada. 

If vote extensions are not available, this signed root may lag behind the 
list of pending transactions. However, it should be the eventually every 
pending transaction is covered by the root or it times out.

## Replay Protection and timeouts

It is important that nonces are used to prevent copies of the same
transaction being submitted multiple times. Since we do not want to enforce
an order on the transactions, these nonces should land in a range. As a
consequence of this, it is possible that transactions in the Bridge Pool will
time out. Transactions that timed out should revert the state changes on
Namada including refunding the paid in fees.
