# Ethereum Events Attestation

We want to store events from the smart contracts of our bridge onto Namada. We
will include events that have been seen by at least one validator, but will not
act on them until they have been seen by at least 2/3 of voting power.

There will be multiple types of events emitted. Validators should
ignore improperly formatted events. ABI encoded events from Ethereum
are decoded by [`ethbridge-rs`], and converted to a Rust enum type
(`EthereumEvent`) by Namada validators before being included in vote
extensions or stored on chain.

[`ethbridge-rs`]: <https://github.com/heliaxdev/ethbridge-rs>

```rust
pub enum EthereumEvent {
    // we will have different variants here corresponding to different types
    // of raw events we receive from Ethereum
    TransfersToNamada(Vec<TransferToNamada>)
    // ...
}
```

Each event will be stored with a list of the consensus validators that have
ever seen it as well as the fraction of total voting power that has ever seen it.
Once an event has been seen by at least 2/3 of voting power, it is locked into a
`seen` state, and acted upon.

If the voting power of Namada changes across epoch boundaries, then events in
storage which are yet to be achieve a quorum decision behind them (i.e. whose
`seen` state is still `false`) must have their voting power adjusted. It is
enough to lazily adjust an event's voting power whenever a new vote is made
for it, to avoid iterating over each Ethereum event in storage.

Validators may never vote more than once on a given event. To ensure that this
invariant is held, we keep track of who voted on some event and events are timed
out if they are not `seen` within the span of `unbonding_length` epochs, which
corresponds to the period of time necessary for bonded tokens to be returned to
an address (check the [relevant proof-of-stake section] for more details).
Timing out an event consists in removing all its associated state from storage.
Therefore, this mechanism serves another purpose: purging forged events from
storage, voted on by Byzantine validators.

[relevant proof-of-stake section]: ../../economics/proof-of-stake/bonding-mechanism.md

## Minimum confirmations
There will be a protocol-specified minimum number of confirmations that events
must reach on the Ethereum chain, before validators can vote to include them
on Namada. This minimum number of confirmations will be changeable via
governance.

`TransferToNamada` events may include a custom minimum number of
confirmations that must be at least the protocol-specified minimum number of
confirmations. However, this value is initially set to __100__.

Validators must not vote to include events that have not met the required
number of confirmations. Votes on unconfirmed events will eventually time
out in storage, unless the number of confirmations was only off by a few
block heights in Ethereum. Assuming that an honest majority of validators
is operating Namada (i.e. $\ge \frac{2}{3}$ by voting power), only confirmed
events will eventually become `seen`.

## Vote extension protocol transactions
A batch of Ethereum events $E$ newly confirmed at some block height $H$
is included by some validator $v$ in a protocol transaction we dub the
*Ethereum events vote extension*. The vote extension is signed by the protocol
key of $v$, uniquely identifying $v$'s vote on some Ethereum event $e \in E$
at $H$.

Namada validators perform votes on other kinds of data, namely:

1) Validator set update vote extensions. As the name implies, these are used to
   sign off on the set of validators of some epoch $E' = E + 1$ by the validators
   of epoch $E$. The proof (quorum of signatures) is used to update the validator
   set reflected in the Ethereum smart contracts of the bridge.
2) Bridge pool root vote extensions. These vote extensions are used to reach a
   quorum decision on the most recent root and nonce of the [Ethereum bridge pool].

These protocol transactions are only ever included on-chain if the Tendermint
version that is being used to run the ledger does not include a full ABCI++
(i.e. ABCI 2.0) implementation. Alternatively, nodes receive vote extensions
from the previously decided block, never lagging behind more than one block
height. Without ABCI++, vote extensions are included in arbitrary blocks,
based on the contention of block proposers' mempools. This effectively means
that a vote extension for some height $H_0$ may only be acted upon at some
height $H \gg H_0$, or even evicted from the mempool altogether, if it is
never proposed.

[Ethereum bridge pool]: ./transfers_to_ethereum.md

## Storage
To make including new events easy, we take the approach of always overwriting
the state with the new state rather than applying state diffs. The storage
keys involved are:
```
# all values are Borsh-serialized
/eth_msgs/$msg_hash/body: EthereumEvent # the event to be voted on
/eth_msgs/$msg_hash/seen_by: BTreeMap<Address, BlockHeight> # mapping from a validator to the Namada height at which the event was observed to be confirmed by said validator
/eth_msgs/$msg_hash/voting_power: FractionalVotingPower  # reduced fraction < 1 e.g. (2, 3)
/eth_msgs/$msg_hash/seen: bool # >= 2/3 voting power across all epochs it was voted on
```

Where `$msg_hash` is the SHA256 digest of the Borsh serialization of
some `EthereumEvent`.

Changes to this `/eth_msgs` storage subspace are only ever made by nodes as part
of the ledger code based on the aggregate of votes by validators for specific events.
That is, changes to `/eth_msgs` happen in block `n` in a deterministic manner based
on the votes included in the block proposal for block `n`. Depending on the underlying
Tendermint version, these votes will either be included as vote extensions or as
protocol transactions.

The `/eth_msgs` storage subspace will belong to the `EthBridge` validity predicate.
It should disallow any changes to this storage from wasm transactions.

### Including events into storage

For every Namada block proposal, the proposer should include the votes for
events from other validators into their proposal. If the underlying Tendermint
version supports vote extensions, consensus invariants guarantee that a
quorum of votes from the previous block height can be included. Otherwise,
validators can only submit votes by broadcasting protocol transactions,
which comes with less guarantees (i.e. no consensus finality).

The vote of a validator should include the events of the Ethereum blocks they
have seen via their full node such that:
1. It's correctly formatted.
2. It's reached the required number of confirmations on the Ethereum chain
3. If a transfer to Ethereum event is detected, the underlying asset must
   be whitelisted on the Ethereum bridge smart contracts.

Each event that a validator is voting to include must be individually signed by
them. If the validator is not voting to include any events, they must still
provide a signed empty vector of events to indicate this.

The votes will include be a Borsh-serialization of something like
the following:
```rust
/// This struct will be created and signed over by each
/// consensus validator, to be included as a vote extension at the end of a
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

These votes will be delivered to subsequent block proposers who will
aggregate those that they can verify and will inject them into their
proposal. With ABCI++ this involves creating a new protocol transaction,
we dub a digest, comprised of multiple individual votes on Ethereum events.

Validators will check the validity of Ethereum events vote extensions as
part of `ProcessProposal`. This includes checking, among other things:
- The height within the vote extension is correct (e.g. not ahead of the
  last block height). If vote extensions are supported, it is also checked
  that each vote extension came from the previous height. Signing over the
  block height also acts as a replay protection mechanism.
- That signatures come from consensus validators, at the epoch the vote
  extensions originated from.
- The bridge was active when the extension was signed.
- Ethereum event nonces, to reject attempts to replay transactions through
  the bridge.

Furthermore, with ABCI++ enabled, the vote extensions included by the block
proposer should have a quorum of the total voting power of the epoch of the
block height behind it. Otherwise the block proposer would not have passed
the `FinalizeBlock` phase of the last round of the last block.

These checks are to prevent censorship of events from validators by the block
proposer. If ABCI++ is not enabled, unfortunately these checks cannot be made.

In `FinalizeBlock`, we derive a second transaction (the "state update"
transaction) from the vote aggregation that:
- Calculates the required changes to `/eth_msgs` storage and applies them.
- Acts on any `/eth_msgs/$msg_hash` where `seen` is going from `false` to `true`
  (e.g. appropriately minting wrapped Ethereum assets).

This state update transaction will not be recorded on chain but will be
deterministically derived from the protocol transaction including the
aggregation of votes, which is recorded on chain.  All ledger nodes will
derive and apply the appropriate state changes to their own local
blockchain storage.

The value of `/eth_msgs/$msg_hash/seen` will also indicate if the event
has been acted upon on the Namada side. The appropriate transfers of tokens
to the given user will be included on chain free of charge and requires no
additional actions from the end user.
