# Proofs

A proof for the bridge is a quorum of signatures by a valid validator set
attached to a message understandable to the Ethereum smart contracts. For
transferring value to Ethereum, a proof is a signed Merkle tree root and
inclusion proofs of assert transfer messages understandable to the Ethereum
smart contractions, as described in the section on 
[batching](transfers_to_ethereum.md/#batching)

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
__bridge relayer__. In theory, since this message is publicly available
on the blockchain, anyone can submit this transaction, but only the
bridge relayer will be directly compensated by Namada.

All Namada validators will have an option to serve as bridge relayer and
the Namada ledger will include a process that does the relaying. Since all
Namada validators are running Ethereum full nodes, they can monitor
that the message was relayed correctly by the bridge relayer.

During the `FinalizeBlock` call in the ledger, if the transfer of power
message is placed on chain, a flag should be set alerting the next block  
proposer that they are the bridge relayer for this epoch.

If the Ethereum event spawned by relaying their  message gets accepted by the
Ethereum state inclusion onto Namada, new NAM tokens will be minted to
reward them. The reward amount shall be a protocol parameter that can be
changed via governance. It should be high enough to cover necessary gas fees.
