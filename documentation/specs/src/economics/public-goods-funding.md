# PGF specs

## Motivation

**Public goods** are non-excludable non-rivalrous items which provide benefits of some sort to their users. Examples include languages, open-source software, research, designs, Earth's atmosphere, and art (conceptually - a physical painting is excludable and rivalrous, but the painting as-such is not). Namada's software stack, supporting research, and ecosystem tooling are all public goods, as are the information ecosystem and education which provide for the technology to be used safety, the hardware designs and software stacks (e.g. instruction set, OS, programming language) on which it runs, and the atmosphere and biodiverse environment which renders its operation possible. Without these things, Namada could not exist, and without their continued sustenance it will not continue to. Public goods, by their nature as non-excludable and non-rivalrous, are mis-modeled by economic systems (such as payment-for-goods) built upon the assumption of scarcity, and are usually either under-funded (relative to their public benefit) or funded in ways which require artificial scarcity and thus a public loss. For this reason, it is in the interest of Namada to help out, where possible, in funding the public goods upon which its existence depends in ways which do not require the introduction of artificial scarcity, balancing the costs of available resources and operational complexity. 

### Design precedent

There is a lot of existing research into public-goods funding to which justice cannot be done here. Most mechanisms fall into two categories: need-based and results-based, where need-based allocation schemes attempt to pay for particular public goods on the basis of cost-of-resources, and results-based allocation schemes attempt to pay (often retroactively) for particular public goods on the basis of expected or assessed benefits to a community and thus create incentives for the production of public goods providing substantial benefits (for a longer exposition on retroactive PGF, see [here](https://medium.com/ethereum-optimism/retroactive-public-goods-funding-33c9b7d00f0c), although the idea is [not new](https://astralcodexten.substack.com/p/lewis-carroll-invented-retroactive)). Additional constraints to consider include the cost-of-time of governance structures (which renders e.g. direct democracy on all funding proposals very inefficient), the necessity of predictable funding in order to make long-term organisational decision-making, the propensity for bike-shedding and damage to the information commons in large-scale public debate (especially without an identity layer or Sybil resistance), and the engineering costs of implementations.


### Funding focuses

> Note that the following is _social consensus_, precedent which can be set at genesis and ratified by governance but does not require any protocol changes.

_Areas of public goods Namada may be interested in funding_

These are intended to permit a great degree of flexibility and are in no way meant to represent strict guidelines.

- Technical research
  _Technical research_ covers funding for technical research topics related to Namada and Namada, such as cryptography, distributed systems, programming language theory, and human-computer interface design, both inside and outside the academy. Possible funding forms could include PhD sponsorships, independent researcher grants, institutional funding, funding for experimental resources (e.g. compute resources for benchmarking), funding for prizes (e.g. theoretical cryptography optimisations), and similar.
- Engineering
  _Engineering_ covers funding for engineering projects related to Namada and Namada, including libraries, optimisations, tooling, alternative interfaces, alternative implementations, integrations, etc. Possible funding forms could include independent developer grants, institutional funding, funding for bug bounties, funding for prizes (e.g. practical performance optimisations), and similar.
- Social research, art, and philosophy
  _Social research, art, and philosophy_ covers funding for artistic expression, philosophical investigation, and social/community research (_not_ marketing) exploring the relationship between humans and technology. Possible funding forms could include independent artist grants, institutional funding, funding for specific research resources (e.g. travel expenses to a location to conduct a case study), and similar.
- Education
  _Education_ covers the funding for open and free to use knowledge, compiled and/or produced by educators in various forms. This can include authors of books, blog-posts, podcasts websites and other educational materials. In a sense, this is a type of *meta public good*, as open knowledge often sparks more open knowledge, although not necessarily

- Meta Public Goods
_Meta public goods_ covers funding for any good that increases the production or existence of other public goods. The management of forums, libraries, quadratic funding protocols, dominant assurance contracts, etc. are good examples of this.

- External public goods
  _External public goods_ covers funding for public goods explicitly external to the Namada and Namada ecosystem, including carbon sequestration, independent journalism, direct cash transfers, legal advocacy, etc. Possible funding forms could include direct purchase of tokenised assets such as carbon credits, direct cash transfers (e.g. GiveDirectly), institutional funding (e.g. Wikileaks), and similar.

## The Public Goods Stewards

The funding of public goods on Namada will be conducted through a structure we call "Public Goods Stewards".

Each steward is elected by governance through separate governance proposals. Each steward will be responsible for covering a specific area of public goods, which they describe during their election. Stewards can then "propose" funding of various public goods, which will pass by default. However, Governance retains the power to veto any proposal, which would result in the Steward being removed from the set of Stewards.

## Voting for the Steward

### What is a Steward (technically)?
All valid PGF stewards will be established multisignature account addresses. These must be created by the intdended parties (which may very well be just one person, but could be more) that wish to represent the Steward entity. For example, if David Alice and Bob wish to represent the combined steward DAB, they may do so as a common entity. But likewise, Alice can create her own 1-out-of-1 multisig that to just represent herself.


### Becoming a Steward
The first step towards becoming a Steward is to instantiate a multisignature account. This is done through the CLI.

In order to propose candidacy as a PGF Steward, the Steward must initiate a custom governance proposal. At the cost of deposited NAM, the governance proposal is broadcasted on-chain and governance is able to vote on whether the Steward-applicant will be accepted or not. Together with this proposal, the applicant is encouraged to provide a motivational statement as to why they should be entrusted with the responsibility of proposing public goods candidates. This will also include a commitment to at least one of the categories of public goods funding that social consensus has established (or propose their own category, which would inherintly introduce a new category into social consensus, should the proposal be accepted).

Proposing candidacy as a PGF Steward is something that is done at any time.

### Losing Stewardship Status

There are 3 ways that a Steward be removed from the Steward Set:

1. Resign as a steward
2. Have a failed funding proposal
3. Become voted out through a governance proposal

Resigning as a Steward is straight-forward. A simple CLI is implemented to allow for this so that the established account representing the Steward loses their priveleges as a PG Steward.

If the Steward's PGF proposal receives a significant number of `Nay` votes ($\frac{2}{3}$ as a fraction of voting-power), they will be removed from the Steward set. It is likely that there would only be such wide-speread disagreement if the proposal was misaligned with the users the Stewards is attempting to cater to. This is described in more detail under [its section](#proposing-funding).

Finally, the Steward can be "voted-out" from its responsibility through a custom governance proposal similar to the one used to elect the Steward in the first place!

#### "Voting-out" the Steward

In the same way that a Steward can be voted in by Namada governance through a custom proposal, the equal and opposite force exists. Hence, any governance member (validator or delegate), is able to initiate a vote (for the relevant cost) in order to remove an arbitrary number of current PGF Stewards. If this proposal passes, it signals that the Steward(s) has/have not fulfilled their duty to the public, which the Stewards are meant to serve (hence the name).

### Initiating the vote

Before a new PGF Steward can either be elected or removed, a governance proposal that specifies this objective must pass. The voting on this proposal is handled by the governance proposal type `StewardProposal`, which is a Custom Proposal type.

The struct of `StewardProposal` is constructed as follows, and is explained in more detail in the [governance specs](../base-ledger/governance.md)

```rust
struct StewardProposal{
  id: u64
  content: Vec<u8>,
  author: Address,
  r#type: PGFSteward,
  votingStartEpoch: Epoch,
  votingEndEpoch: Epoch,
  graceEpoch: Epoch,
}
```

 In order for a new PGF Steward to be elected (or removed), $\frac{2}{3}$ of validating power must vote on the `StewardProposal` and more than half of the votes must be in favor. If more than half of the votes are against the proposal, the Steward set is kept the same, and the proposer of the proposal loses their escrowed funds.

See the example below for more detail, as it may serve as the best medium for explaining the mechanism.

### Voting on the Steward
After the `StewardProposal` has been submitted, and once the Steward's address has been constructed and broadcasted, the Steward address can be voted on by governance particpants. All voting must occur between `votingStartEpoch` and `votingEndEpoch`.

The vote for a Steward addresses's membership will be constructed as follows:

Each participant submits a vote through governance:
```rust
struct OnChainVote {
    id: u64,
    voter: Address,
    yay: proposalVote,
}
```

Where the proposalVote is simply an enum dictating whether the voter voted `Yay` or `Nay` to the proposed candidate change.


#### Dealing with ties
In the rare occurance of a tie, the Steward retains membership by default.


### Electing the Steward

Once the decision has been made on whether to elect (or remove) the intended Steward, the established address corresponding to the multisig is added to (removed from) the `PGF` internal address.

### Example

The below example hopefully demonstrates the mechanism more clearly.

````admonish note
The governance set consists of Alice, Bob, Charlie, Dave, and Elsa. Each member has 20% voting power.

The current PGF Stewards are Dave and Elsa.

- At epoch 42, Bob and Charlie decide to put themselves forward as a joint PGF Steward. They construct a multisig with address `0xBobCharlieMultisig`. 
- At epoch 42, Bob proposes his and Charlie's candidacy through a `StewardProposal`:

```rust
struct StewardProposal{
  id: 2
  content: Vec<32,54,01,24,13,37>, // (Just the byte representation of the content (description) of the proposal)
  author: 0xCharlie,
  r#type: StewardProposal,
  votingStartEpoch: Epoch(45),
  votingEndEpoch: Epoch(54),
  graceEpoch: Epoch(57),
}
```

This proposal proposes the candidate 0xBobCharlieMultisig as a Steward. 

- At epoch 49, Alice submits the vote:

```rust
struct OnChainVote {
    id: 2,
    voter: 0xalice,
    yay: proposalVote,
}
```
Where the proposalVote is simply the enum `Yay` with an empty memo field.

- At epoch 49, Bob and Elsa submit an identical transaction.

- At epoch 50, Dave votes `Nay` on the proposal.

- At epoch 54, the voting period ends and the votes are tallied. Since 80% > 66% of the voting power voted on this proposal (everyone except Charlie, who forgot to vote on her own proposal), the intitial condition is passed and the Proposal is active. Further, because out of the total votes, most were `Yay`, (75% > 50% threshold), the new Steward consisting of Bob and Charlie will be added to the Steward set. 

- At epoch 57, Bob and Charlie have the effective power to propose Public Goods Funding transactions (that may or may not be vetoed).
````

## Mechanism

Once elected and instantiated, PGF Stewards will then unilaterally be able to sign transactions that propose either RPGF or CPGF funding. The PGF Stewards as a whole will have an "allowance" to spend up to the `PGF` internal address's balance.

### Proposing Funding
In order to propose funding, any Steward will be able to propose a PGFProposal through governance. Only Stewards will be valid authors of these proposals. There will be a minimum voting period set specifically for these types of proposals and can be changed by Governance. 

This governance proposal will be such that it passes by default **unless** the following conditions are met:

Conditions to veto a PGF proposal:
1. Out of the votes that voted for the proposal, more than $50\%$ voted `Nay` on the proposal
2. At least $\frac{1}{3}$ of voting power voted on the proposal.
  - Further, if at least $\frac{2}{3}$ of voting power voted `Nay` on the proposal, and the proposal was rejected, the Steward is removed from the set of stewards.


The PGF Stewards should be able to propose both retroactive and continuous public funding transactions. Retroactive public funding transactions are straightforward and implement no additional logic to a normal transfer.

However, for continuous PGF (cPGF), the Stewards should be able to submit a one time transaction which indicates the recipient addresses that should be eligble for receiveing cPGF. 

The following data is attached to the PGF transaction and will allow the Stewards to represent the projects they wish to be continously funded. Each tuple represent the address of the recipient and the respective amount of NAM that the recipient will receive every epoch.

```rust
struct cPgfRecipients {
    recipients: HashSet<(Address, u64)>
}
```
The mechanism for these transfers will be implemented in `finalize-block.rs`, which will send the addresses their respective amounts each end-of-epoch.
Further, the following transactions:
- add (recipient, amount) to cPgfRecipients (inserts the pair into the hashset above)
- remove recipient from cPgfRecipients (removes the address and corresponding amount pair from the hashset above)
 should be added in order to ease the management of cPGF recipients.

```rust
impl addRecipient for cPgfRecipients

impl remRecipient for cPgfRecipients
```


## Addresses
Governance adds 1 internal address:

`PGF` internal address

The internal address VP will hold the allowance the 10% inflation of NAM. This funding will be allocated to the internal address at the start of each epoch. It is important to note that it is this internal address which holds the funds, rather than any of the Stewards' multisigs.

The Stewards should be able to propose the burning of funds, but this hopefully should not require additional functionality beyond what currently exists.

### VP checks

The VP must check that the Stewards spending does not exceed the balance of the VP (in aggregate).

The VP must also check that the any spending is only done by a the active correctly elected PGF Stewards.

## Storage

### Storage keys

Each recipient will be listed under this storage space (for cPGF)
- `/PGFAddress/cPGF_recipients/Address = Amount`
- `/PGFAddress/active_stewards/address = Address`
### Struct

```rust
struct Stewards {
    addresses: Vec<Address>,
}
```
