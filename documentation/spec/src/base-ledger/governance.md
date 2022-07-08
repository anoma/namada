# Namada Governance

Anoma introduce a governance mechanism to propose and apply protocol changes with and without the need for an hard fork. Anyone holding some `NAM` will be able to prosose some changes to which delegators and validator will cast their `yay` or `nay` votes. Governance on Anoma supports both `signaling` and `voting` mechanism. The difference between the the two, is that the former is needed when the changes require an hard fork. In cases where the chain is not able to produce blocks anymore, Anoma relies on `off chain` signaling to agree on a common move.

## On-chain protocol

### Governance Address
Governance adds 2 internal addresses:
- GovernanceAddress
- TreasuryAddress

The first address contains all the proposals under his address space.
The second address holds the funds of rejected proposals.

### Governance storage
Each proposal will be stored in a sub-key under the internal proposal address. The storage keys involved are:
```
/$GovernanceAddress/proposal/$id/content : Vec<u8>
/$GovernanceAddress/proposal/$id/author : Address
/$GovernanceAddress/proposal/$id/start_epoch: Epoch
/$GovernanceAddress/proposal/$id/end_epoch: Epoch
/$GovernanceAddress/proposal/$id/grace_epoch: Epoch
/$GovernanceAddress/proposal/$id/proposal_code: Option<Vec<u8>>
/$GovernanceAddress/proposal/$id/funds: u64
```

`Author` address field will be used to credit the locked funds if the proposal is approved.

The `content` value should follow a standard format. We leverage something similar to what is described in the [BIP2](https://github.com/bitcoin/bips/blob/master/bip-0002.mediawiki#bip-format-and-structure) document:

```json
{
    "title": "<text>",
    "authors": "<authors email addresses> ",
    "discussions-to": "<email address / link>",
    "created": "<date created on, in ISO 8601 (yyyy-mm-dd) format>",
    "license": "<abbreviation for approved license(s)>",
    "abstract": "<text>",
    "motivation": "<text>",
    "details": "<AIP number(s)> - optional field",
    "requires": "<AIP number(s)> - optional field",
}
```

`GovernanceAddress` parameters and global storage keys are:

```
/$GovernanceAddress/?: Vec<u8> 
/$GovernanceAddress/counter: u64
/$GovernanceAddress/min_proposal_fund: u64
/$GovernanceAddress/max_proposal_code_size: u64
/$GovernanceAddress/min_proposal_period: u64
/$GovernanceAddress/max_proposal_content_size: u64
/$GovernanceAddress/min_proposal_grace_epochs: u64
/$GovernanceAddress/pending/$proposal_id: u64

```

`counter` is used to assign a unique, incremental ID to each proposal.\
`min_proposal_fund` represents the minimum amount of locked tokens to submit a proposal.\
`max_proposal_code_size` is the maximum allowed size (in bytes) of the proposal wasm code.\
`min_proposal_period` sets the minimum voting time window (in `Epoch`).\
`max_proposal_content_size` tells the maximum number of characters allowed in the proposal content.\
`min_proposal_grace_epochs` is the minimum required time window (in `Epoch`) between `end_epoch` and the epoch in which the proposal has to be executed.
`/$GovernanceAddress/pending/$proposal_id` this storage key is written only before the execution of the the code defined in `/$GovernanceAddress/proposal/$id/proposal_code` and deleted afterwards. Since this storage key can be written only by the protocol itself (and by no other means), VPs can check for the presence of this storage key to be sure that a a proposal_code has been executed by the protocol and not by a transaction.

The governance machinery also relies on a subkey stored under the `NAM` token address:

```
/$NAMAddress/balance/$GovernanceAddress: u64
```

This is to leverage the `NAM` VP to check that the funds were correctly locked.
The governance subkey, `/$GovernanceAddress/proposal/$id/funds` will be used after the tally step to know the exact amount of tokens to refund or move to Treasury.

### GovernanceAddress VP
Just like Pos, also governance has his own storage space. The `GovernanceAddress` validity predicate task is to check the integrity and correctness of new proposals. A proposal, to be correct, must satisfy the followings:
- Mandatory storage writes are:
    - counter
    - author
    - funds
    - voting_start epoch
    - voting_end epoch
    - grace_epoch
- Lock some funds >= `MIN_PROPOSAL_FUND`
- Contains a unique ID
- Contains a start, end and grace Epoch
- The difference between StartEpoch and EndEpoch should be >= `MIN_PROPOSAL_PERIOD` * constant.
- Should contain a text describing the proposal with length < `MAX_PROPOSAL_CONTENT_SIZE` characters.
- Vote can be done only by a delegator or validator
- Validator can vote only in the initial 2/3 of the whole proposal duration (`EndEpoch` - `StartEpoch`)
- Due to the previous requirement, the following must be true,`(EndEpoch - StartEpoch) % 3 == 0` 
- If defined `proposalCode`, should be the wasm bytecode rappresentation of the changes. This code is triggered in case the proposal has a position outcome.
- `GraceEpoch` should be greater than `EndEpoch` of at least `MIN_PROPOSAL_GRACE_EPOCHS`

`MIN_PROPOSAL_FUND`, `MAX_PROPOSAL_CODE_SIZE`, `MIN_PROPOSAL_GRACE_EPOCHS`, `MAX_PROPOSAL_CONTENT_SIZE` and `MIN_PROPOSAL_PERIOD` are parameters of the protocol.
Once a proposal has been created, nobody can modify any of its fields.
If `proposalCode`  is `Emtpy` or `None` , the proposal upgrade will need to be done via hard fork.

It is possible to check the actual implementation [here](https://github.com/anoma/anoma/blob/master/shared/src/ledger/governance/mod.rs#L69).

Example of `proposalCode` could be:
- storage writes to change some protocol parameter
- storage writes to restore a slash
- storage writes to change a non-native vp

This means that corresponding VPs need to handle these cases.

### Proposal Transactions

The proposal transaction will have the following structure, where `author` address will be the refund address.

```rust=
struct OnChainProposal {
    id: u64
    content: Vec<u8>
    author: Address
    votingStartEpoch: Epoch
    votingEndEpoch: Epoch
    graceEpoch: Epoch
    proposalCode: Option<Vec<u8>>
}
```

### Vote transaction

Vote transactions have the following structure:

```rust=
struct OnChainVote {
    id: u64
    voter: Address
    yay: bool
}
```

Vote transaction creates or modify the following storage key:

```
/$GovernanceAddress/proposal/id/vote/$address: Enum(yay|nay)
```

The storage key will only be created if the transaction is signed either by a validator or a delagator. 
Validators will be able to vote only for 2/3 of the total voting period, meanwhile delegators can vote until the end of the voting period.
If a delegator votes opposite to its validator this will *overri*de the corresponding vote of this validator (e.g. if a delegator has a voting power of 200 and votes opposite to the delegator holding these tokens, than 200 will be subtracted from the votig power of the involved validator).

### Tally
At the beginning of each new epoch (and only then), in the `FinalizeBlock` event, talling will occur for all the proposals ending at this epoch (specified via the `endEpoch` field).
The proposal has a positive outcome if 2/3 of the staked `NAM` total is voting `yay`. Tallying is compute with the following rules
- Sum all the voting power of validators that voted `yay`
- For any validator that voted `yay`, subtract the voting power of any delegation that voted `nay`
- Add voting power for any delegation that voted `yay` (whose corresponding validator didn't vote `yay`)
- If the aformentioned sum divided by the total voting power is >= 0.66, the proposal outcome is positive otherwise negative.

All the computation above must be made at the epoch specified in the  `start_epoch` field of the proposal.

It is possible to check the actual implementation [here](https://github.com/anoma/anoma/blob/master/shared/src/ledger/governance/utils.rs#L68).

### Refund and Proposal Execution mechanism
Together with the talling, in the first block at the beginning of each epoch, in the `FinalizeBlock` event, the protocol will manage the execution of accepted proposals and refunding. For each ended proposal with a positive outcome, will refund the locked funds from `GovernanceAddress` to the proposal author address (specified in the proposal `author` field). For each proposal that has been rejected, instead, the locked funds will be moved to the `TreasuryAddress`. Moreover, if the proposal had a positive outcome and `proposalCode` is defined, these changes will be executed right away.

If the proposal outcome is positive and current epoch is equal to the proposal `grace_epoch`, in the `FinalizeBlock` event:
- transfer the locked funds to the proposal author
- execute any changes to storage specified by `proposalCode`

In case the proposal was rejected or if any error, in the `FinalizeBlock` event:
- transfer the locked funds to `TreasuryAddress`

**NOTE**: we need a way to signal the fulfillment of an accepted proposal inside the block in which it is applied to the state. We could do that by using `Events` https://github.com/tendermint/tendermint/blob/ab0835463f1f89dcadf83f9492e98d85583b0e71/docs/spec/abci/abci.md#events (see https://github.com/anoma/anoma/issues/930).

## TreasuryAddress
Funds locked in `TreasuryAddress` address should be spendable only by proposals.

### TreasuryAddress storage
```
/$TreasuryAddress/max_transferable_fund: u64
/$TreasuryAddress/?: Vec<u8>
```

The funds will be stored under:
```
/$NAMAddress/balance/$TreasuryAddress: u64
```

### TreasuryAddress VP
The treasury validity predicate will approve a trasfer only if:
- the transfer has been made by the protocol (by checking the existence of `/$GovernanceAddress/pending/$proposal_id` storage key)
- the transfered amount is <= `MAX_SPENDABLE_SUM`

`MAX_SPENDABLE_SUM` is a parameter of the treasury native vp.

It is possible to check the actual implementation [here](https://github.com/anoma/anoma/blob/master/shared/src/ledger/treasury/mod.rs#L55).


## ParameterAddress
Protocol parameter are described under the `$ParameterAddress` internal address. 

### ParameterAddress storage
```
/$ParamaterAddress/<param>: String
/$ParamaterAddress/?: Vec<u8>
```

At the moment there are 5 parameters:
- `max_expected_time_per_block`
- `vp_whitelist`
- `tx_whitelist`
- `epoch_duration`

### ParameterAddress VP
The parameter validity predicate will approve changes to the protocol parameter only if:
- the changes have been made by the protocol (by checking the existence of `/$GovernanceAddress/pending/$proposal_id` storage key)

It is possible to check the actual implementation [here](https://github.com/anoma/anoma/blob/master/shared/src/ledger/parameters/mod.rs#L53).


## Off-chain protocol

### Create proposal
A CLI command to create a signed JSON rappresentation of the proposal. The JSON will have the following structure:
```
{
  content: Base64<Vec<u8>>,
  author: Address,
  votingStart: TimeStamp,
  votingEnd: TimeStamp,
  signature: Base64<Vec<u8>>
}
```

The signature is produced over the hash of the concatenation of `content`, `author`, `votingStart` and `votingEnd`.

### Create vote

A CLI command to create a signed JSON rappresentation of a vote. The JSON will have the following structure:
```
{
  proposalHash: Base64<Vec<u8>>,
  voter: Address,
  signature: Base64<Self.proposalHash>,
  vote: Enum(yay|nay)
}
```

The proposalHash is produced over the concatenation of `content`, `author`, `votingStart`, `votingEnd`, `voter` and `vote`.

### Tally
Same mechanism as OnChain tally but instead of reading the data from storage it will require a list of serialized json votes.

## Interfaces

- Ledger CLI
- Wallet
