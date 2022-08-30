# Ethereum Events Attestation

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

## Minimum confirmations
There will be a protocol-specified minimum number of confirmations that events
must reach on the Ethereum chain, before validators can vote to include them
on Namada. This minimum number of confirmations will be changeable via 
governance.

`TransferToNamada` events may include a custom minimum number of 
confirmations, that must be at least the protocol-specified minimum number of 
confirmations.

Validators must not vote to include events that have not met the required 
number of confirmations. Voting on unconfirmed events is considered a 
slashable offence.

###Storage
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
nodes as part of the ledger code based on the aggregate of vote 
extensions for the last Tendermint round. That is, changes to `/eth_msgs` happen 
in block `n+1` in a deterministic manner based on the vote extensions of the 
Tendermint round for block `n`. The `/eth_msgs` storage subspace will belong 
to the `EthBridge` validity predicate. It should disallow any changes to 
this storage from wasm transactions.

## Including events into storage

For every Namada block proposal, the vote extension of a validator should include
the events of the Ethereum blocks they have seen via their full node such that:
1. The storage value `/eth_msgs/\$msg_hash/seen_by` does not include their
   address.
2. It's correctly formatted.
3. It's reached the required number of confirmations on the Ethereum chain

Each event that a validator is voting to include must be individually signed by 
them. If the validator is not voting to include any events, they must still
provide a signed voted extension indicating this.

The vote extension data field will be a Borsh-serialization of something like the following.
```rust
pub struct VoteExtension(Vec<SignedEthEvent>);

/// A struct used by validators to sign that they have seen a particular
/// ethereum event. These are included in vote extensions
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct SignedEthEvent {
    /// The address of the signing validator
    signer: Address,
    /// The proportion of the total voting power held by the validator
    power: FractionalVotingPower,
    /// The event being signed and the block height at which
    /// it was seen. We include the height as part of enforcing
    /// that a block proposer submits vote extensions from
    /// **the previous round only**
    event: Signed<(EthereumEvent, BlockHeight)>,
}
```

These vote extensions will be given to the next block proposer who will
aggregate those that it can verify and will inject a protocol transaction
(the "vote extensions" transaction).

```rust
pub struct MultiSigned<T: BorshSerialize + BorshDeserialize> {
    /// Arbitrary data to be signed
    pub data: T,
    /// The signature of the data
    pub sigs: Vec<common::Signature>,
}

pub struct MultiSignedEthEvent {
    /// Address and voting power of the signing validators
    pub signers: Vec<(Address, FractionalVotingPower)>,
    /// Events as signed by validators
    pub event: MultiSigned<(EthereumEvent, BlockHeight)>,
}

pub enum ProtocolTxType {
    EthereumEvents(Vec<MultiSignedEthEvent>)
}
```

This vote extensions transaction will be signed by the block proposer. 
Validators will check this transaction and the validity of the new votes as 
part of `ProcessProposal`, this includes checking:
- signatures
- that votes are really from active validators
- the calculation of backed voting power

It is also checked that each vote extension came from the previous round, 
requiring validators to sign over the Namada block height with their vote
extension. Furthermore, the vote extensions included by the block proposer
should have at least 2 / 3 of the total voting power of the previous round 
backing it. Otherwise the block proposer would not have passed the 
`FinalizeBlock` phase of the last round. These checks are to prevent censorship 
of events from validators by the block proposer.

In `FinalizeBlock`, we derive a second transaction (the "state update" 
transaction) from the vote extensions transaction that:

- calculates the required changes to `/eth_msgs` storage and applies it
- acts on any `/eth_msgs/\$msg_hash` where `seen` is going from `false` to `true`
  (e.g. appropriately minting wrapped Ethereum assets)

This state update transaction will not be recorded on chain but will be 
deterministically derived from the vote extensions transaction, which is 
recorded on chain. All ledger nodes will derive and apply this transaction to 
their own local blockchain state, whenever they receive a block with a vote 
extensions transaction. This transaction cannot require a protocol signature 
as even non-validator full nodes of Namada will be expected to do this.

The value of `/eth_msgs/\$msg_hash/seen` will also indicate if the event 
has been acted on on the Namada side. The appropriate transfers of tokens to the
given user will be included on chain free of charge and requires no
additional actions from the end user.
