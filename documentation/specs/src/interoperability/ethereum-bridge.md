# Ethereum bridge

The Namada - Ethereum bridge exists to mint ERC20 tokens on Namada 
which naturally can be redeemed on Ethereum at a later time. Furthermore, it 
allows the minting of wrapped tokens on Ethereum backed by escrowed assets on 
Namada.

The Namada Ethereum bridge system consists of:
* An Ethereum full node run by each Namada validator, for including relevant 
  Ethereum events into Namada.
* A set of validity predicates on Namada which roughly implements 
  [ICS20](https://docs.cosmos.network/v0.42/modules/ibc/) fungible token 
  transfers.
* A set of Ethereum smart contracts.
* An automated process to send validator set updates to the Ethereum smart 
  contracts.
* A relayer binary to aid in submitting transactions to Ethereum

This basic bridge architecture should provide for almost-Namada consensus
security for the bridge and free Ethereum state reads on Namada, plus
bidirectional message passing with reasonably low gas costs on the
Ethereum side.

## Security
On Namada, the validators are full nodes of Ethereum and their stake is also
accounting for security of the bridge. If they carry out a forking attack
on Namada to steal locked tokens of Ethereum their stake will be slashed on Namada.
On the Ethereum side, we will add a limit to the amount of assets that can be
locked to limit the damage a forking attack on Namada can do. To make an attack
more cumbersome we will also add a limit on how fast wrapped Ethereum assets can
be redeemed from Namada. This will not add more security, but rather make the 
attack more inconvenient.

## Ethereum Events Attestation
We want to store events from the smart contracts of our bridge onto Namada. We
will include events that have been seen by at least one validator, but will not
act on them until they have been seen by at least 2/3 of voting power.

There will be multiple types of events emitted. Validators should
ignore improperly formatted events. Raw events from Ethereum are converted to a 
Rust enum type (`EthereumEvent`) by Namada validators before being included 
in vote extensions or stored on chain.

```rust
pub enum EthereumEvent {
    // we will have different variants here corresponding to different types
    // of raw events we receive from Ethereum
    TransfersToNamada(Vec<TransferToNamada>)
    // ...
}
```

Each event will be stored with a list of the validators that have ever seen it 
as well as the fraction of total voting power that has ever seen it. 
Once an event has been seen by 2/3 of voting power, it is locked into a
`seen` state, and acted upon.

There is no adjustment across epoch boundaries - e.g. if an event is seen by 1/3
of voting power in epoch n, then seen by a different 1/3 of voting power in 
epoch m>n, the event will be considered `seen` in total. Validators may never
vote more than once for a given event.

### Minimum confirmations
There will be a protocol-specified minimum number of confirmations that events
must reach on the Ethereum chain, before validators can vote to include them
on Namada. This minimum number of confirmations will be changeable via 
governance.

`TransferToNamada` events may include a custom minimum number of 
confirmations, that must be at least the protocol-specified minimum number of 
confirmations but is initially set to __100__.

Validators must not vote to include events that have not met the required 
number of confirmations. Voting on unconfirmed events is considered a 
slashable offence.

### Storage
To make including new events easy, we take the approach of always overwriting 
the state with the new state rather than applying state diffs. The storage 
keys involved are:
```
# all values are Borsh-serialized
/eth_msgs/\$msg_hash/body : EthereumEvent
/eth_msgs/\$msg_hash/seen_by : Vec<Address>
/eth_msgs/\$msg_hash/voting_power: (u64, u64)  # reduced fraction < 1 e.g. (2, 3)
/eth_msgs/\$msg_hash/seen: bool
```

`\$msg_hash` is the SHA256 digest of the Borsh serialization of the relevant 
`EthereumEvent`.

Changes to this `/eth_msgs` storage subspace are only ever made by 
nodes as part of the ledger code based on the aggregate of votes 
by validators for specific events. That is, changes to 
`/eth_msgs` happen 
in block `n` in a deterministic manner based on the votes included in the 
block proposal for block `n`. Depending on the underlying Tendermint
version, these votes will either be included as vote extensions or as
protocol transactions. 

The `/eth_msgs` storage subspace will belong 
to the `EthBridge` validity predicate. It should disallow any changes to 
this storage from wasm transactions.

### Including events into storage

For every Namada block proposal, block proposer should include the votes for 
events from other validators into their proposal. If the underlying Tendermint
version supports vote extensions, consensus invariants guarantee that a 
quorum of votes from the previous block height can be included. Otherwise, 
validators can only submit votes by broadcasting protocol transactions, 
which comes with less guarantees.

The vote of a validator should include the events of the Ethereum blocks they
have seen via their full node such that:
1. It's correctly formatted.
2. It's reached the required number of confirmations on the Ethereum chain

Each event that a validator is voting to include must be individually signed by 
them. If the validator is not voting to include any events, they must still
provide a signed empty vector of events to indicate this.

The votes will include be a Borsh-serialization of something like
the following.
```rust
/// This struct will be created and signed over by each
/// active validator, to be included as a vote extension at the end of a
/// Tendermint PreCommit phase or as Protocol Tx.
pub struct Vext {
    /// The block height for which this [`Vext`] was made.
    pub block_height: BlockHeight,
    /// The address of the signing validator
    pub validator_addr: Address,
    /// The new ethereum events seen. These should be
    /// deterministically ordered.
    pub ethereum_events: Vec<EthereumEvent>,
}
```

These votes will be given to the next block proposer who will
aggregate those that it can verify and will inject a signed protocol 
transaction into their proposal.

Validators will check this transaction and the validity of the new votes as 
part of `ProcessProposal`, this includes checking:
- signatures
- that votes are really from active validators
- the calculation of backed voting power

If vote extensions are supported, it is also checked that each vote extension 
came from the previous round, requiring validators to sign over the Namada block
height with their vote extension.

Furthermore, the vote extensions included by 
the block proposer should have at least 2 / 3 of the total voting power of the 
previous round backing it. Otherwise the block proposer would not have passed the 
`FinalizeBlock` phase of the last round.

These checks are to prevent censorship 
of events from validators by the block proposer. If vote extensions are not 
enabled, unfortunately these checks cannot be made. 

In `FinalizeBlock`, we derive a second transaction (the "state update" 
transaction) from the vote aggregation that:
- calculates the required changes to `/eth_msgs` storage and applies it
- acts on any `/eth_msgs/\$msg_hash` where `seen` is going from `false` to `true`
  (e.g. appropriately minting wrapped Ethereum assets)

This state update transaction will not be recorded on chain but will be 
deterministically derived from the protocol transaction including the 
aggregation of votes, which is recorded on chain.  All ledger nodes will 
derive and apply the appropriate state changes to their own local 
blockchain storage.

The value of `/eth_msgs/\$msg_hash/seen` will also indicate if the event 
has been acted upon on the Namada side. The appropriate transfers of tokens 
to the given user will be included on chain free of charge and requires no
additional actions from the end user.

## Namada Validity Predicates

There will be two internal accounts with associated native validity predicates:

- `#EthBridge` - Controls the `/eth_msgs/` storage and ledgers of balances 
  for  wrapped Ethereum assets (ERC20 tokens) structured in a 
["multitoken"](https://github.com/anoma/anoma/issues/1102) hierarchy
- `#EthBridgeEscrow` which will hold in escrow wrapped Namada tokens which have 
been sent to Ethereum.

### Transferring assets from Ethereum to Namada

#### Wrapped ERC20
The "transfer" transaction mints the appropriate amount to the corresponding 
multitoken balance key for the receiver, based on the specifics of a 
`TransferToNamada` Ethereum event.

```rust
pub struct EthAddress(pub [u8; 20]);

/// Represents Ethereum assets on the Ethereum blockchain
pub enum EthereumAsset {
    /// An ERC20 token and the address of its contract
    ERC20(EthAddress),
}

/// An event transferring some kind of value from Ethereum to Anoma
pub struct TransferToNamada {
    /// Quantity of ether in the transfer
    pub amount: Amount,
    /// Address on Ethereum of the asset
    pub asset: EthereumAsset,
    /// The Namada address receiving wrapped assets on Anoma
    pub receiver: Address,
}
```

##### Example

For 10 DAI i.e. ERC20([0x6b175474e89094c44da98b954eedeac495271d0f](https://etherscan.io/token/0x6b175474e89094c44da98b954eedeac495271d0f)) to `atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt`
```
#EthBridge
    /erc20
        /0x6b175474e89094c44da98b954eedeac495271d0f
            /balances
                /atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt 
                += 10
```

#### Namada tokens
Any wrapped Namada tokens being redeemed from Ethereum must have an equivalent amount of the native token held in escrow by `#EthBridgeEscrow`.
The protocol transaction should simply make a transfer from `#EthBridgeEscrow` to the `receiver` for the appropriate amount and asset.

### Transferring assets from Namada to Ethereum

Moving assets from Namada to Ethereum will not be automatic, as opposed the
movement of value in the opposite direction. Instead, users must send an 
appropriate transaction to Namada to initiate a transfer across the bridge 
to Ethereum. Once this transaction is approved, a "proof" will be created 
and posted on Namada.

It is incumbent on the end user to  request an appropriate "proof" of the 
transaction. This proof must be submitted to the appropriate Ethereum smart 
contract by the user to redeem Ethereum assets / mint wrapped assets. This also 
means all Ethereum gas costs are the responsibility of the end user.

A relayer binary will be developed to aid users in accessing the proofs
generated by Namada validators as well as posting this proof to Ethereum. It
will also aid in batching transactions.

#### Moving value to Ethereum

To redeem wrapped Ethereum assets, a user should make a transaction to burn
their wrapped tokens, which the `#EthBridge` validity predicate will accept.

Mints of a wrapped Namada token on Ethereum (including NAM, Namada's native token)
will be represented by a data type like:
```rust
struct MintWrappedNam {
    /// The Namada address owning the token
    owner: NamadaAddress,
    /// The address on Ethereum receiving the wrapped tokens
    receiver: EthereumAddress,
    /// The address of the token to be wrapped 
    token: NamadaAddress,
    /// The number of wrapped Namada tokens to mint on Ethereum
    amount: Amount,
}
```

If a user wishes to mint a wrapped Namada token on Ethereum, they must 
submit a transaction on Namada that:
- stores `MintWrappedNam` on chain somewhere - TBD
- sends the correct amount of Namada token to `#EthBridgeEscrow`

#### Batching

Ethereum gas fees make it prohibitively expensive in many cases to submit
the proof for a single transaction over the bridge. Instead, it is typically
more economical to submit proofs of many transactions in bulk. This batching
is described in this section.

A pool of transaction from Namada to Ethereum will be kept by Namada. Every
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

#### Replay Protection and timeouts

It is important that nonces are used to prevent copies of the same
transaction being submitted multiple times. Since we do not want to enforce
an order on the transactions, these nonces should land in a range. As a
consequence of this, it is possible that transactions in the Bridge Pool will
time out. Transactions that timed out should revert the state changes on
Namada including refunding the paid in fees.

#### Proofs
A proof for this bridge is a quorum of signatures by a valid validator set 
attached to a message understandable to the Ethereum smart contracts. For 
transferring value to Ethereum, a proof is a signed Merkle tree root and 
inclusion proofs of assert transfer messages understandable to the Ethereum 
smart contractions, as described in the section on batching.

A message for transferring value to Ethereum should be of the form
```rust
pub struct TransferToEthereum {
    /// The type of token 
    asset: EthereumAddress,
    /// The recipient address
    recipient: EthereumAddress,
    /// The amount to be transferred
    amount: Amount,
    /// a nonce for replay protection
    nonce: Nonce,
}
```

Additionally, when the validator set changes, the smart contracts on 
Ethereum must be updated so that it can continue to recognize valid proofs.
Since the Ethereum smart contract should  accept any header signed by bridge 
header signed by 2 / 3 of the staking validators, it needs up-to-date 
knowledge of:
- The current validators' public keys
- The current stake of each validator

This means the at the end of every Namada epoch, a special transaction must be
sent to the Ethereum smart contracts detailing the new public keys and stake 
of the new validator set. This message must also be signed by at least 2 / 3 
of the current validators as a "transfer of power".

If vote extensions are available, this signed data can be constructed 
using them. Otherwise, validators must send protocol txs to be included on 
the ledger. Once a quorum exist on chain, they can be aggregated into a 
single message that can be relayed to Ethereum. Signing an 
invalid  validator transition set will be considered a slashable offense.

Due to asynchronicity concerns, this message should be submitted well in
advance of the actual epoch change, perhaps even at the beginning of each
new epoch. Bridge headers to ethereum should include the current Namada epoch
so that the smart contract knows how to verify the headers. In short, there
is a pipelining mechanism in the smart contract.

Such a message is not prompted by any user transaction and thus will have
to be carried out by a _bridge relayer_. Once the transfer of power
message is on chain, any time afterwards a Namada bridge process may take
it to craft the appropriate message to the Ethereum smart contracts.

The details on bridge relayers are below in the corresponding section.

Signing incorrect headers is considered a slashable offense. Anyone witnessing
an incorrect header that is signed may submit a complaint (a type of transaction)
to initiate slashing of the validator who made the signature.

## Namada Bridge Relayers

Validator changes must be turned into a message that can be communicated to
smart contracts on Ethereum. These smart contracts need this information
to verify proofs of actions taken on Namada.

Since this is protocol level information, it is not user prompted and thus
should not be the responsibility of any user to submit such a transaction.
However, any user may choose to submit this transaction anyway.

This necessitates a Namada node whose job it is to submit these transactions on
Ethereum at the conclusion of each Namada epoch. This node is called the
__Designated Relayer__. In theory, since this message is publicly available 
on the blockchain, anyone can submit this transaction, but only the 
Designated Relayer will be directly compensated by Namada.

All Namada validators will have an option to serve as bridge relayer and
the Namada ledger will include a process that does the relaying. Since all
Namada validators are running Ethereum full nodes, they can monitor
that the message was relayed correctly by the Designated Relayer.

During the `FinalizeBlock` call in the ledger, if the transfer of power 
message is placed on chain, a flag should be set alerting the next block  
proposer that they are the Designated Relayer for this epoch. 

If the Ethereum event spawned by relaying their  message gets accepted by the 
Ethereum state inclusion onto Namada, new NAM tokens will be minted to 
reward them. The reward amount shall be a protocol parameter that can be 
changed via governance. It should be high enough to cover necessary gas fees.

## Ethereum Smart Contracts
The set of Ethereum contracts should perform the following functions:
- Verify bridge header proofs from Namada so that Namada messages can
  be submitted to the contract.
- Verify and maintain evolving validator sets with corresponding stake
  and public keys.
- Emit log messages readable by Namada
- Handle ICS20-style token transfer messages appropriately with escrow &
  unescrow on the Ethereum side
- Allow for message batching

Furthermore, the Ethereum contracts will whitelist ETH and tokens that
flow across the bridge as well as ensure limits on transfer volume per epoch.

An Ethereum smart contract should perform the following steps to verify
a proof from Namada:
1. Check the epoch included in the proof.
2. Look up the validator set corresponding to said epoch.
3. Verify that the signatures included amount to at least 2 / 3 of the
   total stake.
4. Check the validity of each signature.

If all the above verifications succeed, the contract may affect the
appropriate state change, emit logs, etc.

## Starting the bridge

Before the bridge can start running, some storage may need to be initialized in 
Namada. TBD.

## Resources which may be helpful:
- [Gravity Bridge Solidity contracts](https://github.com/Gravity-Bridge/Gravity-Bridge/tree/main/solidity)
- [ICS20](https://github.com/cosmos/ibc/tree/master/spec/app/ics-020-fungible-token-transfer)
- [Rainbow Bridge contracts](https://github.com/aurora-is-near/rainbow-bridge/tree/master/contracts)
- [IBC in Solidity](https://github.com/hyperledger-labs/yui-ibc-solidity)

Operational notes:
1. We will bundle the Ethereum full node with the `namada` daemon executable.
