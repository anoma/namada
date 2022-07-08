# Ethereum bridge

The Namada - Ethereum bridge exists to mint wrapped ETH tokens on Namada which naturally
can be redeemed on Ethereum at a later time. Furthermore, it allows the
minting of wrapped tokens on Ethereum backed by escrowed assets on Namada.

The Namada Ethereum bridge system consists of:
* Ethereum state inclusion onto Namada.
* A set of validity predicates on Namada which roughly implements [ICS20](https://docs.cosmos.network/v0.42/modules/ibc/) fungible token transfers.
* A set of Ethereum smart contracts.
* A Namada bridge process

This basic bridge architecture should provide for almost-Namada consensus
security for the bridge and free Ethereum state reads on Namada, plus
bidirectional message passing with reasonably low gas costs on the
Ethereum side.

## Security
On Namada, the validators are full nodes of Ethereum and their stake is also
accounting for security of the bridge. If they carry out a forking attack
on Namada to steal locked tokens of Ethereum their stake will be slashed on Namada.
On the Ethereum side, we will add a limit to the amount of ETH that can be
locked to limit the damage a forking attack on Namada can do. To make an attack
more cumbersome we will also add a limit on how fast wrapped ETH can be
redeemed. This will not add more security, but rather make the attack more
inconvenient.

## Ethereum State Inclusion
We want to store data identifying which Ethereum blocks have been seen
and validated by at least 2/3 of the staking validators in the blockchain storage.
The data stored from each Ethereum block will be:
* The block header
* The block hash
* Messages from the Ethereum smart contracts relevant
  to the bridge.
  We may also we to include Merkle proofs of inclusion of
  these messages in the relevant blocks. We might also implement policies to
  prune old/irrelevant data or do checkpointing.

Each piece of block data should have a list of the validators that have seen
this block and the current amount of stake associated with it. This
will need to be appropriately adjusted across epoch boundaries. However,
once a block has been seen by 2/3 of the staking validators, it is locked into a
`seen` state. Thus, even if after an epoch that block has no longer been
reported as seen by 2/3 of the new staking validators set, it is still
considered as `seen`.

To make this easy, we take the approach of always overwriting the state with
the new state rather than applying state diffs. The storage keys involved
are:
```
/eth_block/$block_hash/header : Vec<u8>
/eth_block/$block_hash/messages : Vec<Vec<u8>>
/eth_block/$block_hash/seen_by : Vec<Address>
/eth_block/$block_hash/voting_power: u64
/eth_block/$block_hash/seen: bool
/eth_block/$block_hash/? : [u8; 32]
# not yet decided
/eth_block/$block_hash/merkle_proofs : Vec<Vec<u8>>
```

For every Namada block proposal, the vote of a validator should include
the headers, hash, & smart contract messages (possibly with Merkle proofs)
of the Ethereum blocks they have seen via their full node such that:

1. Has not been marked as `seen` by Namada
2. The storage value `/eth_block/$block_hash/seen_by` does not include their
   address.
3. Is a descendant of a block they have seen (even if it is not marked `seen`)

After a Namada block is committed, the next block proposer receives the
aggregate of the vote extensions. From that, they should craft the proposed
state change of the above form. They subsequently include a tx to that end
in their block proposal. This aggregated state change needs to be validated
by at least 2/3 of the staking validators as usual.

## Namada Validity Predicates

### Minting wrapped ETH tokens on Namada
Namada requires a validity predicate with dedicated storage to mint wrapped
ETH. This validity predicate should be called on every inclusion of Ethereum
state above. Its storage contains a queue of messages from the Ethereum
bridge contracts. It also mints corresponding assets on Namada, where the asset denomination corresponds to
`{token address on ethereum} || {minimum number of confirmations}`.

The minimum number of confirmations indicated in the outgoing Ethereum message
(maybe defaulting to 25 or 50 if unspecified) specifies the minimum number of
confirmations in block depth that must be reached before the assets will be
minted on Namada. This is the purpose of the message queue for this validity
predicate.

This queue contains instances of the `MintEthToken` struct below.
```rust
/// The token address for wrapped ETH tokens
const WRAPPED_ETH_ADDRESS: Address = ... 
pub struct WrappedETHAddress;
pub struct NamAddress(Address);

pub trait MintingAddress {
    fn get_address(&self) -> &Address;
}

impl MintingAddress for WrappedETHAddress {
    fn get_address(&self) -> &Address {
        &WRAPPED_ETH_ADDRESS
    }
}

impl MintingAddress for NamAddress {
    fn get_address(&self) -> &Address {
        &self.0
    }
}

/// Generic struct for transferring value from Ethereum
struct TransferFromEthereum<Token: MintingAddress> {
    /// token address on Ethereum
    ethereum_address: Address,
    /// the address on Namada receiving the tokens
    receiver: Address,
    /// The Namada token that will be minted
    token: Token, 
    /// the amount of ETH token to mint
    amount: Amount,
    /// minimum number of confirmations needed for mints
    min_confirmations: u8,
    /// height of the block at which the message appeared
    height: u64,
    /// the hash & height of the last descendant block marked as `seen`
    latest_descendant: ([u8; 32], u64)
}

impl TransferFromEthereum {
    /// Update the hash and height of the block `B` marked as `seen` in Namada
    /// storage such that 
    ///   1. `B` is a descendant of the block containing the original message
    ///   2. `B` has the maximum height of all blocks satisfying 1.
    fn update_latest_descendant(&mut self, hash: [u8; 32], height: u64) {
        if height > self.latest_descendant.1 {
            self.latest_descendant = (hash, height);    
        }
    }
    
    /// Check if the number of confirmations for the block containing
    /// the original message exceeds the minimum number required to 
    /// consider the message confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.latest_descendant.1 - self.height >= self.min_confirmations
    }
}

/// Struct for minting wrapped ETH tokens on Namada
pub type MintEthToken = TransferFromEthereum<WrappedETHAddress>;
/// Struct for redeeming wrapped NAM tokens from Ethereum
pub type RedeemNam = TransferFromEthereum<NamAddress>;
```
Every time this validity predicate is called, it must perform the following
actions:
1. Add new messages from the input into the queue
2. For each message in the queue, update its number of confirmations. This
   can be done by finding Ethereum block headers marked as `seen` in the new
   storage data (the input from finalizing the block, it isn't necessary to
   access Namada storage) that are descendants of the `latest_descendant` field.

At the end of each `FinalizeBlock` call, validators should check this queue.
For each message that is confirmed, they should transfer the appropriate
tokens (as determined by the `get_address` method of the `token` field) to
the address in the `receiver` field.

Note that this means that a transfer initiated on Ethereum will automatically
be seen and acted upon by Namada. The appropriate transfers of tokens to the
given user will be included on chain free of charge and requires no
additional actions from the end user.

### Redeeming ETH by burning tokens on Namada

For redeeming wrapped ETH, the Namada side will need another validity predicate
that is called only when the appropriate user tx lands on chain. This validity
predicate will simply burn the tokens.

Once this transaction is approved, it is incumbent on the end user to
request an appropriate "proof" of the transaction. This proof must be
submitted to the appropriate Ethereum smart contract by the user to
redeem their ETH. This also means all Ethereum gas costs are the
responsibility of the end user.

The proofs to be used will be custom bridge headers that are calculated
deterministically from the block contents, including messages sent by Namada and
possibly validator set updates. They will be designed for maximally
efficient Ethereum decoding and verification.

For each block on Namada, validators must submit the corresponding bridge
header signed with a special secp256k1 key as part of their vote extension.
Validators must reject votes which do not contain correctly signed bridge
headers. The finalized bridge header with aggregated signatures will appear in the
next block as a protocol transaction. Aggregation of signatures is the
responsibility of the next block proposer.

The bridge headers need only be produced when the proposed block contains
requests to transfer value over the bridge to Ethereum. The exception is
when validator sets change.  Since the Ethereum smart contract should
accept any header signed by bridge header signed by 2 / 3 of the staking
validators, it needs up-to-date knowledge of:
- The current validators' public keys
- The current stake of each validator

This means the at the end of every Namada epoch, a special transaction must be
sent to the Ethereum contract detailing the new public keys and stake of the
new validator set. This message must also be signed by at least 2 / 3 of the
current validators as a "transfer of power". It is to be included in validators
vote extensions as part of the bridge header. Signing an invalid validator
transition set will be consider a slashable offense.

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

### Minting wrapped Namada tokens on Ethereum

If a user wishes to mint a wrapped token on Ethereum backed by a token on
Namada, (including NAM, Namada's native token), they first must submit a special transaction on Namada. This transaction
should be an instance of the following:

```rust
struct MintWrappedNam {
    /// The Namada address owning the token
    source: Address,
    /// The address on Ethereum receiving the wrapped tokens
    ethereum_address: Address,
    /// The address of the token to be wrapped 
    token: Address,
    /// The number of tokens to mint
    amount: Amount,
}
```
A special Namada validity predicate will be called on this transaction. If the
transaction is valid, the corresponding amount of the NAM token will be transferred
from the `source` address and deposited in an escrow account by the
validity predicate.

Just as in redeeming ETH above, it is incumbent on the end user to
request an appropriate proof of the transaction. This proof must be
submitted to the appropriate Ethereum smart contract by the user.
The corresponding amount of wrapped NAM tokens will be transferred to the
`ethereum_address` by the smart contract.

### Redeeming NAM tokens

Redeeming wrapped NAM tokens from Ethereum works much the same way as sending
ETH over the bridge. In fact, it may be handled by the same validity
predicate.

Every time Ethereum state is included, this validity predicate is called .
It keeps a queue of messages from the Ethereum bridge contracts that
indicate wrapped NAM tokens have been burned by said contract Ethereum side.

The messages should be instances of the `RedeemNam` struct defined in [the
above section](#minting-wrapped-eth-tokens-on-m1). Once such a message
has reached the requisite number of confirmations, a free protocol
transaction should be included by the next block proposer. This transaction
should transfer the appropriate amount of NAM tokens from the Namada escrow account
to the address of the recipient.

## Namada Bridge Relayers

Validator changes must be turned into a message that can be communicated to
smart contracts on Ethereum. These smart contracts need this information
to verify proofs of actions taken on Namada.

Since this is protocol level information, it is not user prompted and thus
should not be the responsibility of any user to submit such a transaction.
However, any user may choose to submit this transaction anyway.

This necessitates a Namada node whose job it is to submit these transactions on
Ethereum at the conclusion of each Namada epoch. This node is called the
__Designated Relayer__. In theory, since this message is publicly available on the blockchain,
anyone can submit this transaction, but only the Designated Relayer will be
directly compensated by Namada.

All Namada validators will have an option to serve as bridge relayer and
the Namada ledger will include a process that does the relaying. Since all
Namada validators are running Ethereum full nodes, they can monitor
that the message was relayed correctly by the Designated Relayer.

During the `FinalizeBlock` call in the ledger, if the epoch changes, a
flag should be set alerting the next block proposer that they are the
Designated Relayer for this epoch. If their message gets accepted by the
Ethereum state inclusion onto Namada, new NAM tokens will be minted to reward
them. The reward amount shall be a protocol parameter that can be changed
via governance. It should be high enough to cover necessary gas fees.

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


## Resources which may be helpful:
- [Gravity Bridge Solidity contracts](https://github.com/Gravity-Bridge/Gravity-Bridge/tree/main/solidity)
- [ICS20](https://github.com/cosmos/ibc/tree/master/spec/app/ics-020-fungible-token-transfer)
- [Rainbow Bridge contracts](https://github.com/aurora-is-near/rainbow-bridge/tree/master/contracts)
- [IBC in Solidity](https://github.com/hyperledger-labs/yui-ibc-solidity)

Operational notes:
1. We should bundle the Ethereum full node with the `namada` daemon executable.
