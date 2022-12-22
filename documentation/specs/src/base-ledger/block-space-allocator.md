# Block space allocator

Block space in Tendermint is a resource whose management is relinquished to the 
running application. This section covers the design of an abstraction that 
facilitates the process of transparently allocating space for transactions in a 
block at some height $H$, whilst upholding the safety and liveness properties 
of Namada.

## On block sizes in Tendermint and Namada

[Block sizes in Tendermint]
(configured through the $MaxBytes$ consensus 
parameter) have a minimum value of $1\ \text{byte}$, and a hard cap of $100\ 
MiB$, reflecting the header, evidence of misbehavior (used to slash 
Byzantine validators) and transaction data, as well as any potential protobuf 
serialization overhead. Some of these data are dynamic in nature (e.g. 
evidence of misbehavior), so the total size reserved to transactions in a block 
at some height $H_0$ might not be the same as another block's, say, at some 
height $H_1 : H_1 \ne H_0$. During Tendermint's `PrepareProposal` ABCI phase, 
applications receive a $MaxTxBytes$ parameter whose value already accounts for 
the total space available for transactions at some height $H$. Namada does not 
rely on the $MaxTxBytes$ parameter of `RequestPrepareProposal`; instead, 
app-side validators configure a $MaxProposalSize$ parameter at genesis (or
through governance) and set Tendermint blocks' $MaxBytes$ parameter to its 
upper bound.

[Block sizes in Tendermint]: <https://github.com/tendermint/tendermint/blob/v0.34.x/spec/abci/apps.md#blockparamsmaxbytes>

## Transaction batch construction

During Tendermint's `PrepareProposal` ABCI phase, Namada (the ABCI server) is 
fed a set of transactions $M = \{\ tx\ |\ tx\text{ in Tendermint's mempool}\ 
\}$, whose total combined size (i.e. the sum of the bytes occupied by each $tx 
: tx \in M$) may be greater than $MaxProposalBytes$. Therefore, consensus round 
leaders are responsible for selecting a batch of transactions $P$ whose total 
combined bytes $P_{Len} \le MaxProposalBytes$.

To stay within these bounds, block space is **allotted** to different kinds of 
transactions: decrypted, protocol and encrypted transactions. Each kind of 
transaction gets about $\frac{1}{3} MaxProposalBytes$ worth of allotted space, 
in an abstract container dubbed the `TxBin`. A transaction $tx : tx \in M$ may 
be **dumped** to a `TxBin`, resulting in a successful operation, or an error, 
if $tx$ is **rejected** due to lack of space in the `TxBin` or if $tx$'s size 
**overflows** (i.e. does not fit in) the `TxBin`. Block proposers continue 
dumping transactions from $M$ into a `TxBin` $B$ until a rejection error is 
encountered, or until there are no more transactions of the same type as $B$'s 
in $M$. The `BlockSpaceAllocator` contains three `TxBin` instances, responsible 
for holding decrypted, protocol and encrypted transactions.

<img
  src="images/block-space-allocator-bins.svg"
  alt="block space allocator tx bins"
  height="400"
  width="500"
  style="display: block; margin: 0 auto" />

During occasional Namada protocol events, such as DKG parameter negotiation, 
all available block space should be reserved to protocol transactions, 
therefore the `BlockSpaceAllocator` was designed as a state machine, whose 
state transitions depend on the state of Namada. The states of the 
`BlockSpaceAllocator` are the following:

1. `BuildingDecryptedTxBatch` - As the name implies, during this state the 
decrypted transactions `TxBin` is filled with transactions of the same type. 
Honest block proposers will only include decrypted transactions in a block at a 
fixed height $H_0$ if encrypted transactions were available at $H_0 - 1$. The 
decrypted transactions should be included in the same order of the encrypted 
transactions of block $H_0 - 1$. Likewise, all decrypted transactions available 
at $H_0$ must be included.
2. `BuildingProtocolTxBatch` - In a similar manner, during this 
`BlockSpaceAllocator` state, the protocol transactions `TxBin` is populated 
with transactions of the same type. Contrary to the first state, allocation 
stops as soon as the respective `TxBin` runs out of space for some 
$tx_{Protocol} : tx_{Protocol} \in M$. The `TxBin` for protocol transactions is 
allotted half of the remaining block space, after decrypted transactions have 
been **allocated**.
3. `BuildingEncryptedTxBatch` - This state behaves a lot like the previous 
state, with one addition: it takes a parameter that guards the encrypted 
transactions `TxBin`, which in effect splits the state into two sub-states. 
When `WithEncryptedTxs` is active, we fill block space with encrypted 
transactions (as the name implies); orthogonal to this mode of operation, there 
is `WithoutEncryptedTxs`, which, as the name implies, does not allow encrypted 
transactions to be included in a block. The `TxBin` for encrypted transactions 
is allotted $\min(R,\frac{1}{3} MaxProposalBytes)$ bytes, where $R$ is the 
block space remaining after allocating space for decrypted and protocol 
transactions.
4. `FillingRemainingSpace` - The final state of the `BlockSpaceAllocator`. Due 
to the short-circuit behavior of a `TxBin`, on allocation errors, some space 
may be left unutilized at the end of the third state. At this state, the only 
kinds of
transactions that are left to fill the available block space are
of type encrypted and protocol, but encrypted transactions are forbidden
to be included, to avoid breaking their invariant regarding
allotted block space (i.e. encrypted transactions can only occupy up to
$\frac{1}{3}$ of the total block space for a given height $H$). As such,
only protocol transactions are allowed at the fourth and final state of
the `BlockSpaceAllocator`.

For a fixed block height $H_0$, if at $H_0 - 1$ and $H_0$ no encrypted 
transactions are included in the respective proposals, the block decided for 
height $H_0$ will only contain protocol transactions. Similarly, since at most 
$\frac{1}{3}$ of the available block space at a fixed height $H_1$ is reserved 
to encrypted transactions, and decrypted transactions at $H_1+1$ will take up 
(at most) the same amount of space as encrypted transactions at height $H_1$, 
each transaction kind's `TxBin` will generally get allotted about $\frac{1}{3}$ 
of the available block space.

### Example

Consider the following diagram:

<img
  src="images/block-space-allocator-example.svg"
  alt="block space allocator example"
  height="400"
  width="600"
  style="display: block; margin: 0 auto" />

We denote `D`, `P` and `E` as decrypted, protocol and encrypted transactions, 
respectively.

* At height $H$, block space is evenly divided in three parts, one for each 
kind of transaction type.
* At height $H+1$, we do not include encrypted transactions in the proposal, 
therefore protocol transactions are allowed to take up to $\frac{2}{3}$ of the 
available block space.
* At height $H+2$, no encrypted transactions are included either. Notice that 
no decrypted transactions were included in the proposal, since at height $H+1$ 
we did not decide on any encrypted transactions. In sum, only protocol 
transactions are included in the proposal for the block with height $H+2$.
* At height $H+3$, we propose encrypted transactions once more. Just like in 
the previous scenario, no decrypted transactions are available. Encrypted 
transactions are capped at $\frac{1}{3}$ of the available block space, so the 
remaining $\frac{1}{2} - \frac{1}{3} = \frac{1}{6}$ of the available block 
space is filled with protocol transactions.
* At height $H+4$, allocation returns to its normal operation, thus block space 
is divided in three equal parts for each kind of transaction type.

## Transaction batch validation

Batches of transactions proposed during ABCI's `PrepareProposal` phase are 
validated at the `ProcessProposal` phase. The validation conditions are 
relaxed, compared to the rigid block structure imposed on blocks during 
`PrepareProposal` (i.e. with decrypted, protocol and encrypted transactions 
appearing in this order, as [examplified above](#example)). Let us fix $H$ as 
the height of the block $B$ currently being decided through Tendermint's 
consensus mechanism, $P$ as the batch of transactions proposed at $H$ as $B$'s 
payload and $V$ as the current set of active validators. To vote on $P$, each 
validator $v \in V$ checks:

* If the length of $P$ in bytes, defined as $P_{Len} := \sum_{tx \in 
P} \text{size\_of}(tx)$, is not greater than $MaxProposalBytes$.
* If $P$ does not contain more than $\frac{1}{3} MaxProposalBytes$ worth of 
encrypted transactions.
    - While not directly checked, our batch construction invariants guarantee 
that we will constrain decrypted transactions to occupy up to $\frac{1}{3} 
MaxProposalBytes$ bytes of the available block space at $H$ (or any block 
height, in fact).
* If all decrypted transactions from $H-1$ have been included in the proposal 
$P$, for height $H$.
* That no encrypted transactions were included in the proposal $P$, if no
encrypted transactions should be included at $H$.
    - N.b. the conditions to reject encrypted transactions are still not clearly
    specced out, therefore they will be left out of this section, for the
    time being.

Should any of these conditions not be met at some arbitrary round $R$ of $H$, 
all honest validators $V_h : V_h \subseteq V$ will reject the proposal $P$. 
Byzantine validators are permitted to re-order the layout of $P$ typically 
derived from the [`BlockSpaceAllocator`](#transaction-batch-construction) $A$, 
under normal operation, however this should not be a compromising factor of the 
safety and liveness properties of Namada. The rigid layout of $B$ is simply a 
consequence of $A$ allocating in different phases.

### On validator set updates

Validator set updates, one type of protocol transactions decided through BFT 
consensus in Namada, are fundamental to the liveness properties of the Ethereum 
bridge, thus, ideally we would also check if these would be included once per 
epoch at the `ProcessProposal` stage. Unfortunately, achieving a quorum of 
signatures for a validator set update between two adjacent block heights 
through ABCI alone is not feasible. Hence, the Ethereum bridge is not a live 
distributed system, since there is the possibility to cross an epoch boundary 
without constructing a valid proof for some validator set update. In practice, 
however, it is nearly impossible for the bridge to get "stuck", as validator 
set updates are eagerly issued at the start of an epoch, whose length should be 
long enough for consensus(*) to be reached on a single validator set update.

(*) Note that we loosely used consensus here to refer to the process of 
acquiring a quorum (e.g. more than $\frac{2}{3}$ of voting power, by stake) of 
signatures on a single validator set update. "Chunks" of a proof (i.e. 
individual votes) are decided and batched together, until a complete proof is 
constructed.

We cover validator set updates in detail in [the Ethereum bridge section].

[the Ethereum bridge section]: ../interoperability/ethereum-bridge.md

## Governance

Governance parameter update proposals for $MaxProposalBytes_H$ that take effect 
at $H$, where $H$ is some arbitrary block height, should be such that
$MaxProposalBytes_H \ge \frac{1}{3} MaxProposalBytes_{H-1}$, to leave enough
room for all decrypted transactions from $H-1$ at $H$. Subsequent block heights
$H' : H' > H$ should eventually lead to allotted block space converging to about
$\frac{1}{3} MaxProposalBytes_H$ for each kind of transaction type.
