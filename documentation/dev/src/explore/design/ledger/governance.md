# Governance

Namada introduces a governance mechanism to propose and apply protocol changes with and without the need for a hard fork. Anyone holding some NAM will be able to propose some changes to which delegators and validators will cast their yay or nay votes. Governance on Namada supports both signaling and voting mechanism. The difference between the two, is that the former is needed when the changes require a hard fork. In cases where the chain is not able to produce blocks anymore, Namada relies on an off-chain signaling mechanism to agree on a common strategy.

## Governance & SlashFund addresses

Governance introduces two internal addresses with their corresponding native vps:

- Governance address, which is in charge of validating on-chain proposals and votes
- SlashFund address, which is in charge of holding slashed funds

Also, it introduces some protocol parameters:

- `min_proposal_fund`
- `max_proposal_code_size`
- `min_proposal_voting_period`
- `max_proposal_period`
- `max_proposal_content_size`
- `min_proposal_grace_epochs`

## On-chain proposals

On-chain proposals are created under the `governance_address` storage space and, by default, this storage space is initialized with the following storage keys:

```
/$GovernanceAddress/counter: u64
/$GovernanceAddress/min_proposal_fund: u64
/$GovernanceAddress/max_proposal_code_size: u64
/$GovernanceAddress/min_proposal_voting_period: u64
/$GovernanceAddress/max_proposal_period: u64
/$GovernanceAddress/max_proposal_content_size: u64
/$GovernanceAddress/min_proposal_grace_epochs: u64
```

In order to create a valid proposal, a transaction needs to modify these storage keys:

```
/$GovernanceAddress/proposal/$id/content: Vec<u8>
/$GovernanceAddress/proposal/$id/author: Address
/$GovernanceAddress/proposal/$id/type: ProposalType
/$GovernanceAddress/proposal/$id/startEpoch: Epoch
/$GovernanceAddress/proposal/$id/endEpoch: Epoch
/$GovernanceAddress/proposal/$id/graceEpoch: Epoch
/$GovernanceAddress/proposal/$id/proposalCode: Option<Vec<u8>>
/$GovernanceAddress/proposal/$id/funds: u64
```

and follow these rules:

- `$id` must be equal to `counter + 1`.
- `startEpoch` must:
  - be greater than `currentEpoch`, where current epoch is the epoch in which the transaction is executed and included in a block
  - be a multiple of `min_proposal_voting_period`.
- `endEpoch` must:
  - be at least `min_proposal_voting_period` epochs greater than `startEpoch`
  - be at most `max_proposal_period` epochs greater than `startEpoch`
  - be a multiple of `min_proposal_voting_period`
- `graceEpoch` must:
  - be at least `min_grace_epoch` epochs greater than `endEpoch`
- `proposalCode` can be empty and must be a valid transaction with size less than `max_proposal_code_size` kibibytes.
- `funds` must be equal to `min_proposal_fund` and should be moved to the `governance_address`.
- `content` should follow the `Namada Improvement Proposal schema` and must be less than `max_proposal_content_size` kibibytes.
- `author` must be a valid address on-chain
- `type` defines:
  - the optional payload (memo) attached to the vote
  - which actors should be allowed to vote (delegators and validators or validators only)
  - the threshold to be used in the tally process
  - the optional wasm code attached to the proposal

A proposal gets accepted if enough `yay` votes (net of the voting power) to match the threshold specified by `ProposalType` (computed at the epoch defined in the `endEpoch` field) are reached. If the proposal is accepted, the locked funds are returned to the address defined in the `proposal_author` field, otherwise are moved to the slash fund address.

The `proposal_code` field can execute arbitrary code in the form of a wasm transaction. If the proposal gets accepted, the code is executed in the first block of the epoch following the `graceEpoch`.

Proposals can be submitted by any address as long as the above rules are respected. Votes can be cast only by active validators and delegators (at epoch `endEpoch` or less): the proposal type could impose more constraints on this.
Moreover, if delegators are allowed to vote, validators can vote only during the first 2/3 of the voting period (from `startEpoch` and 2/3 of `endEpoch` - `startEpoch`).

The preferred content template (`Namada Improvement Proposal schema`) is the following:

```json
{
    "title": "<string>",
    "authors": "<authors email addresses> ",
    "discussions-to": "<email address / link>",
    "created": "<date created on, in ISO 8601 (yyyy-mm-dd) format>",
    "license": "<abbreviation for approved license(s)>",
    "abstract": "<string>",
    "motivation": "<string>",
    "details": "<string - optional field",
    "requires": "<AIP number(s)> - optional field",
}
```

In order to vote on a proposal, a transaction should modify the following storage key:

```
/$GovernanceAddress/proposal/$id/vote/$validator_address/$voter_address: ProposalVote
```

where `ProposalVote` is an enum representing a `Yay` or `Nay` vote: the yay variant also contains the specific memo (if any) required for that proposal. `$validator_address` is the delegation validator address and the `$voter_address` is the address of who is voting. A voter can be cast for each delegation.

Vote is valid if it follows these rules:

- vote can be sent only by validator or delegators (also depending on the proposal type)
- if delegators can vote, validators can vote only during the first 2/3 of the total voting period, delegators can vote for the whole voting period

The outcome of a proposal is computed at the epoch specific in the `endEpoch` field and executed at `graceEpoch` field (if it contains a non-empty `proposalCode` field).
A proposal is accepted only if enough `yay` votes (net of the voting power) to match the threshold set in `ProposalType` is reached.
If a proposal gets accepted, the locked funds will be reimbursed to the author. In case it gets rejected, the locked funds will be moved to slash fund.

## Off-chain proposal

In cases where it's not possible to run a proposal online (for example, when the chain is halted), an offline mechanism can be used.
The ledger offers the possibility to create and sign proposals that are verified against a specific chain epoch.
