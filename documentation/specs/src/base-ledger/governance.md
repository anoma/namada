# Namada Governance

Namada introduces a governance mechanism to propose and apply protocol changes with  or without the need for a hard fork. Anyone holding some `NAM` will be able to propose some changes to which delegators and validators will cast their `yay` or `nay` votes. Governance on Namada supports both `signaling` and `voting` mechanisms. The difference between the the two is that the former is needed when the changes require a hard fork. In cases where the chain is not able to produce blocks anymore, Namada relies on [off chain](#off-chain-protocol) signaling to agree on a common move.

## On-chain protocol

### Governance Address
Governance adds 2 internal addresses:
- `GovernanceAddress`
- `SlashFundAddress`

The first internal address contains all the proposals under its address space.
The second internal address holds the funds of rejected proposals.

### Governance storage
Each proposal will be stored in a sub-key under the internal proposal address. The storage keys involved are:

```
/\$GovernanceAddress/proposal/$id/content: Vec<u8>
/\$GovernanceAddress/proposal/$id/author: Address
/\$GovernanceAddress/proposal/$id/start_epoch: Epoch
/\$GovernanceAddress/proposal/$id/end_epoch: Epoch
/\$GovernanceAddress/proposal/$id/grace_epoch: Epoch
/\$GovernanceAddress/proposal/$id/proposal_code: Option<Vec<u8>>
/\$GovernanceAddress/proposal/$id/funds: u64
/\$GovernanceAddress/proposal/epoch/$id: u64
```

- `Author` address field will be used to credit the locked funds if the proposal is approved.
- `/$GovernanceAddress/proposal/$epoch/$id` is used for easing the ledger governance execution. `$epoch` refers to the same value as the on specific in the `grace_epoch` field.
- The `content` value should follow a standard format. We leverage a similar format to what is described in the [BIP2](https://github.com/bitcoin/bips/blob/master/bip-0002.mediawiki#bip-format-and-structure) document:

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
/\$GovernanceAddress/counter: u64
/\$GovernanceAddress/min_proposal_fund: u64
/\$GovernanceAddress/max_proposal_code_size: u64
/\$GovernanceAddress/min_proposal_period: u64
/\$GovernanceAddress/max_proposal_content_size: u64
/\$GovernanceAddress/min_proposal_grace_epochs: u64
/\$GovernanceAddress/pending/\$proposal_id: u64

```

`counter` is used to assign a unique, incremental ID to each proposal.\
`min_proposal_fund` represents the minimum amount of locked tokens to submit a proposal.\
`max_proposal_code_size` is the maximum allowed size (in bytes) of the proposal wasm code.\
`min_proposal_period` sets the minimum voting time window (in `Epoch`).\
`max_proposal_content_size` tells the maximum number of characters allowed in the proposal content.\
`min_proposal_grace_epochs` is the minimum required time window (in `Epoch`) between `end_epoch` and the epoch in which the proposal has to be executed.
`/$GovernanceAddress/pending/$proposal_id` this storage key is written only before the execution of the code defined in `/$GovernanceAddress/proposal/$id/proposal_code` and deleted afterwards. Since this storage key can be written only by the protocol itself (and by no other means), VPs can check for the presence of this storage key to be sure that a proposal_code has been executed by the protocol and not by a transaction.

The governance machinery also relies on a subkey stored under the `NAM` token address:

```
/\$NAMAddress/balance/\$GovernanceAddress: u64
```

This is to leverage the `NAM` VP to check that the funds were correctly locked.
The governance subkey, `/\$GovernanceAddress/proposal/\$id/funds` will be used after the tally step to know the exact amount of tokens to refund or move to SlashFund.

### GovernanceAddress VP
Just like Pos, also governance has his own storage space. The `GovernanceAddress` validity predicate task is to check the integrity and correctness of new proposals. A proposal, to be correct, must satisfy the following:
- Mandatory storage writes are:
    - counter
    - author
    - funds
    - voting_start epoch
    - voting_end epoch
    - grace_epoch
- Lock some funds >= `min_proposal_fund`
- Contains a unique ID
- Contains a start, end and grace Epoch
- The difference between StartEpoch and EndEpoch should be >= `min_proposal_period`.
- Should contain a text describing the proposal with length < `max_proposal_content_size` characters.
- Vote can be done only by a delegator or validator
- Validator can vote only in the initial 2/3 of the whole proposal duration (`end_epoch` - `start_epoch`)
- Due to the previous requirement, the following must be true,`(EndEpoch - StartEpoch) % 3 == 0` 
- If defined, `proposalCode` should be the wasm bytecode representation of 
  the changes. This code is triggered in case the proposal has a position outcome.
- The difference between `grace_epoch` and `end_epoch` should be of at least `min_proposal_grace_epochs`

Once a proposal has been created, nobody can modify any of its fields.
If `proposal_code`  is `Empty` or `None` , the proposal upgrade will need to be done via hard fork.

It is possible to check the actual implementation [here](https://github.com/anoma/namada/blob/master/shared/src/ledger/governance/mod.rs#L69).

Example of `proposalCode` could be:
- storage writes to change some protocol parameter
- storage writes to restore a slash
- storage writes to change a non-native vp

This means that corresponding VPs need to handle these cases.

### Proposal Transactions

The proposal transaction will have the following structure, where `author` address will be the refund address.

```rust
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

```rust
struct OnChainVote {
    id: u64
    voter: Address
    yay: bool
}
```

Vote transaction creates or modifies the following storage key:

```
/\$GovernanceAddress/proposal/\$id/vote/\$delegation_address/\$voter_address: Enum(yay|nay)
```

The storage key will only be created if the transaction is signed either by 
a validator or a delegator. 
Validators will be able to vote only for 2/3 of the total voting period, while delegators can vote until the end of the voting period.

If a delegator votes opposite to its validator, this will *override* the 
corresponding vote of this validator (e.g. if a delegator has a voting power of 200 and votes opposite to the delegator holding these tokens, than 200 will be subtracted from the voting power of the involved validator).

As a small form of space/gas optimization, if a delegator votes accordingly to its validator, the vote will not actually be submitted to the chain. This logic is applied only if the following conditions are satisfied:

- The transaction is not being forced
- The vote is submitted in the last third of the voting period (the one exclusive to delegators). This second condition is necessary to prevent a validator from changing its vote after a delegator vote has been submitted, effectively stealing the delegator's vote.   

### Tally
At the beginning of each new epoch (and only then), in the `FinalizeBlock` event, tallying will occur for all the proposals ending at this epoch (specified via the `grace_epoch` field of the proposal).
The proposal has a positive outcome if 2/3 of the staked `NAM` total is voting `yay`. Tallying is computed with the following rules:

- Sum all the voting power of validators that voted `yay`
- For any validator that voted `yay`, subtract the voting power of any delegation that voted `nay`
- Add voting power for any delegation that voted `yay` (whose corresponding validator didn't vote `yay`)
- If the aformentioned sum divided by the total voting power is >= `2/3`, the proposal outcome is positive otherwise negative.

All the computation above must be made at the epoch specified in the `start_epoch` field of the proposal.

It is possible to check the actual implementation [here](https://github.com/anoma/namada/blob/master/shared/src/ledger/governance/utils.rs#L68).

### Refund and Proposal Execution mechanism
Together with tallying, in the first block at the beginning of each epoch, in the `FinalizeBlock` event, the protocol will manage the execution of accepted proposals and refunding. For each ended proposal with a positive outcome, it will refund the locked funds from `GovernanceAddress` to the proposal author address (specified in the proposal `author` field). For each proposal that has been rejected, instead, the locked funds will be moved to the `SlashFundAddress`. Moreover, if the proposal had a positive outcome and `proposal_code` is defined, these changes will be executed right away.
To summarize the execution of governance in the `FinalizeBlock` event:

If the proposal outcome is positive and current epoch is equal to the proposal `grace_epoch`, in the `FinalizeBlock` event:
- transfer the locked funds to the proposal `author`
- execute any changes specified by `proposal_code`

In case the proposal was rejected or if any error, in the `FinalizeBlock` event:
- transfer the locked funds to `SlashFundAddress`

The result is then signaled by creating and inserting a [`Tendermint Event`](https://github.com/tendermint/tendermint/blob/ab0835463f1f89dcadf83f9492e98d85583b0e71/docs/spec/abci/abci.md#events.


## SlashFundAddress
Funds locked in `SlashFundAddress` address should be spendable only by proposals.

### SlashFundAddress storage
```
/\$SlashFundAddress/?: Vec<u8>
```

The funds will be stored under:
```
/\$NAMAddress/balance/\$SlashFundAddress: u64
```

### SlashFundAddress VP
The slash_fund validity predicate will approve a transfer only if the transfer has been made by the protocol (by checking the existence of `/$GovernanceAddress/pending/$proposal_id` storage key)

It is possible to check the actual implementation [here](https://github.com/anoma/namada/blob/main/shared/src/ledger/slash_fund/mod.rs#L70).

## Off-chain protocol

### Create proposal
A CLI command to create a signed JSON representation of the proposal. The 
JSON will have the following structure:
```
{
  content: Base64<Vec<u8>>,
  author: Address,
  votingStart: TimeStamp,
  votingEnd: TimeStamp,
  signature: Base64<Vec<u8>>
}
```

The signature is produced over the hash of the concatenation of: `content`, `author`, `votingStart` and `votingEnd`.

### Create vote

A CLI command to create a signed JSON representation of a vote. The JSON 
will have the following structure:
```
{
  proposalHash: Base64<Vec<u8>>,
  voter: Address,
  signature: Base64<Self.proposalHash>,
  vote: Enum(yay|nay)
}
```

The proposalHash is produced over the concatenation of: `content`, `author`, `votingStart`, `votingEnd`, `voter` and `vote`.

### Tally
Same mechanism as [on chain](#tally) tally but instead of reading the data from storage it will require a list of serialized json votes.

## Interfaces

- Ledger CLI
- Wallet