# Proofs

An Ethereum bridge proof is a quorum (by $\ge 2/3$ voting power) of signatures
from a valid validator set, on some arbitrary piece of data that is required to
complete an operation in Ethereum. Namada validators create two types of proofs
during their normal operation:

1. Bridge pool merkle tree roots.
    - The signature is made over the concatenation of a merkle tree root with a
      monotonically growing Bridge pool nonce, to uniquely identify different
      Bridge pool snapshots.
    - To transfer value to Ethereum, an inclusion proof of a batch of transfers must
      be sent together with the signed merkle tree root, as well as the nonce of
      that snapshot of the Bridge pool. This process is described in the section
      on [batching](transfers_to_ethereum.md#batching).
    - A message for transferring value to Ethereum is a `TransferToEthereum`
      instance as described
      [here](./transfers_to_ethereum.md#bridge-pool-validity-predicate).
2. Validator set updates.
    - These are comprised of:
        - The validators' Ethereum-facing public keys. The `Governance` and
          `Bridge` contracts keep track of two sets of keys (cold and hot keys,
          respectively).
        - The stake of each validator, normalized to the range $[0, 2^{32}]$.
    - When the validator set changes in Namada, the smart contracts on Ethereum
      must be updated so that they can continue to recognize valid proofs. The
      validator set of some epoch $E' = E + 1$ must be signed by a quorum of
      Namada validators from $E$ before the end of this epoch.
    - The process of updating the set of validators in Ethereum can be thought
      of as a "transfer of power", from the old set of validators to the new one.
      Note that the validators in the set may be the same between epochs, but this
      must be communicated to the Ethereum bridge smart contracts, either way.

If vote extensions are available, a fully crafted transfer of power message 
will be made available on-chain. Otherwise, this message must be crafted 
offline by aggregating the protocol txs from validators in which the sign 
over the new validator set.

If vote extensions are available, this signed data can be constructed
using them. Otherwise, validators must send protocol txs to be included on
the ledger. Once a quorum exist on chain, they can be aggregated into a
single message that can be relayed to Ethereum. Signing an
invalid  validator transition set will be considered a slashable offense.

Due to asynchronicity concerns, this message should be submitted well in
advance of the actual epoch change. It should happen at the beginning of each
new epoch. Bridge headers to ethereum should include the current Namada epoch
so that the smart contract knows how to verify the headers. In short, there
is a pipelining mechanism in the smart contract - the consensus validators
for epoch `n` submit details of the consensus validator set for epoch `n+1`.

Such a message is not prompted by any user transaction and thus will have
to be carried out by a _bridge relayer_. Once the necessary data to 
construct the transfer of power  message is on chain, any time afterwards a 
Namada bridge process may take it to craft the appropriate header to the 
Ethereum smart contracts.

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
Ethereum by the conclusion of each Namada epoch. This node is called the
__bridge relayer__. In theory, since this message is publicly available
on the blockchain, anyone can submit this transaction, but only the
bridge relayer will be directly compensated by Namada.

The bridge relayer will be chosen to be the proposer of the first block of the 
new epoch. Anyone else may relay this message, but must pay for the fees out of
their own pocket.

All Namada validators will have an option to serve as bridge relayer and
the Namada ledger will include a process that does the relaying. Since all
Namada validators are running Ethereum full nodes, they can monitor
that the message was relayed correctly by the bridge relayer.

If the Ethereum event spawned by relaying their message gets accepted by the
Ethereum state inclusion onto Namada, new NAM tokens will be minted to
reward them. The reward amount shall be a protocol parameter that can be
changed via governance. It should be high enough to cover necessary gas fees.

### Recovering from an update failure

If vote extensions are not available, we cannot guarantee that a quorum of 
validator signatures can be gathered for the message that updates the 
validator set before the epoch ends.

If a significant number of validators become inactive in the next epoch, we 
need a means to complete validator set update. Until this is done, the 
bridge will halt. 

In this case, the validators from that epoch will need to craft a 
transaction with a quorum of signatures offline and submit it on-chain. This 
transaction should include the validator set update. 

The only way this is impossible is if more than 1/3 of the validators by 
stake from that epoch delete their Ethereum keys, which is extremely unlikely.
