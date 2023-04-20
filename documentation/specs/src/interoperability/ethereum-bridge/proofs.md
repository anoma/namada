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
    - Validator sets in the `Bridge` contract rotate in a pipeline. This contract
      always keeps track of the current set of validators, as well as the next set
      of validators. Initially, the current and next set of validators are initialized
      with the same value. Subsequent updates to the contract will shift the next set
      of validators to the current set, and change the value of the next set to the
      set of validators that was freshly signed by a quorum of Namada validators.

More information on how these proofs are constructed is available
under the [Ethereum events attestation section].

[Ethereum events attestation section]: ethereum_events_attestation.md#vote-extension-protocol-transactions

### Recovering from a validator set update failure

If vote extensions are not available, we cannot guarantee that a quorum of 
validator signatures can be gathered for the message that updates the 
validator set before some epoch $E$ ends. Should this scenario take place,
the Ethereum bridge will halt in the Namada to Ethereum direction, since
it will not be able to authenticate user transfers.

In this case, the validators from $E$ will need to coordinate, offline, the
crafting of a transaction including their vote on the validator set of $E + 1$.
The only way this is impossible is if more than $1/3$ (by stake) of the consensus
validators from $E$ delete their Ethereum hot keys, which is extremely unlikely.

## Namada Bridge Relayers

Proofs themselves do not alter any state in Ethereum. Rather, they
authenticate state transitions in Ethereum based on the security
properties (in the BFT sense) of the Namada network. Carrying out
state updates in Ethereum is the task of an __Ethereum bridge relayer__.
The Ethereum bridge relayer must submit proofs to the Ethereum
bridge smart contracts before the conclusion of each Namada epoch, at
which point proofs become invalid, due to:

1. Validator set nonces incrementing (we use epoch values for this purpose).
2. Validator sets themselves changing.

The default set of binaries of the Namada chain provide:

- An automatic validator set update relayer daemon, as well as a manual
  validator set update relayer.
    + Validator set update relayers are currently not compensated.
      Relaying is done out of good will for the Ethereum bridge to continue
      operating.
- A manual relayer to send a batch of pending transfers to Ethereum.
  Specialized relayers for these kinds of proofs are encouraged to be developed
  by third-parties, since gas fees compensating relayers are provided by the
  Namada network.

Relaying is characterized by pushing protocol level information to Ethereum,
therefore it is not user prompted and should not be their responsibility.
However, any user may choose to assume the role of an Ethereum bridge
relayer anyway, since no restrictions are imposed on who actually performs
the relaying of Ethereum bridge proofs.
