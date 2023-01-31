# PGF specs

## Motivation

**Public goods** are non-excludable non-rivalrous items which provide benefits of some sort to their users. Examples include languages, open-source software, research, designs, Earth's atmosphere, and art (conceptually - a physical painting is excludable and rivalrous, but the painting as-such is not). Namada's software stack, supporting research, and ecosystem tooling are all public goods, as are the information ecosystem and education which provide for the technology to be used safety, the hardware designs and software stacks (e.g. instruction set, OS, programming language) on which it runs, and the atmosphere and biodiverse environment which renders its operation possible. Without these things, Namada could not exist, and without their continued sustenance it will not continue to. Public goods, by their nature as non-excludable and non-rivalrous, are mis-modeled by economic systems (such as payment-for-goods) built upon the assumption of scarcity, and are usually either under-funded (relative to their public benefit) or funded in ways which require artificial scarcity and thus a public loss. For this reason, it is in the interest of Namada to help out, where possible, in funding the public goods upon which its existence depends in ways which do not require the introduction of artificial scarcity, balancing the costs of available resources and operational complexity. 

### Design precedent

There is a lot of existing research into public-goods funding to which justice cannot be done here. Most mechanisms fall into two categories: need-based and results-based, where need-based allocation schemes attempt to pay for particular public goods on the basis of cost-of-resources, and results-based allocation schemes attempt to pay (often retroactively) for particular public goods on the basis of expected or assessed benefits to a community and thus create incentives for the production of public goods providing substantial benefits (for a longer exposition on retroactive PGF, see [here](https://medium.com/ethereum-optimism/retroactive-public-goods-funding-33c9b7d00f0c), although the idea is [not new](https://astralcodexten.substack.com/p/lewis-carroll-invented-retroactive)). Additional constraints to consider include the cost-of-time of governance structures (which renders e.g. direct democracy on all funding proposals very inefficient), the necessity of predictable funding in order to make long-term organisational decision-making, the propensity for bike-shedding and damage to the information commons in large-scale public debate (especially without an identity layer or Sybil resistance), and the engineering costs of implementations.


### Funding categories

> Note that the following is _social consensus_, precedent which can be set at genesis and ratified by governance but does not require any protocol changes.

_Categories of public-goods funding_

Namada groups public goods into four categories, with earmarked pools of funding:

- Technical research
  _Technical research_ covers funding for technical research topics related to Namada and Namada, such as cryptography, distributed systems, programming language theory, and human-computer interface design, both inside and outside the academy. Possible funding forms could include PhD sponsorships, independent researcher grants, institutional funding, funding for experimental resources (e.g. compute resources for benchmarking), funding for prizes (e.g. theoretical cryptography optimisations), and similar.
- Engineering
  _Engineering_ covers funding for engineering projects related to Namada and Namada, including libraries, optimisations, tooling, alternative interfaces, alternative implementations, integrations, etc. Possible funding forms could include independent developer grants, institutional funding, funding for bug bounties, funding for prizes (e.g. practical performance optimisations), and similar.
- Social research, art, and philosophy
  _Social research, art, and philosophy_ covers funding for artistic expression, philosophical investigation, and social/community research (_not_ marketing) exploring the relationship between humans and technology. Possible funding forms could include independent artist grants, institutional funding, funding for specific research resources (e.g. travel expenses to a location to conduct a case study), and similar.
- External public goods
  _External public goods_ covers funding for public goods explicitly external to the Namada and Namada ecosystem, including carbon sequestration, independent journalism, direct cash transfers, legal advocacy, etc. Possible funding forms could include direct purchase of tokenised assets such as carbon credits, direct cash transfers (e.g. GiveDirectly), institutional funding (e.g. Wikileaks), and similar.

### Funding amounts

In Namada, up to 10% inflation per annum of the NAM token is directed to this public goods mechanism. The division of these funds is entirely the discretion of the elected PGF council.

Namada encourages the public goods council to adopt a default social consensus of an equal split between categories, meaning 1.25% per annum inflation for each category (e.g. 1.25% for technical research continuous funding, 1.25% for technical research retroactive PGF). If no qualified recipients are available, funds may be redirected or burnt.

Namada also encourages the PGF council to allocate the PGF council members up to 5% of these funds (0.5% inflation) as a payment for value added from the council itself.

## Voting for the Council

### Constructing the council
All valid PGF councils will be established multisignature account addresses. These must be created by the intdended parties that wish to create a council. The council will therefore have the discretion to decide what threshold will be required for their multisig (i.e the "k" in the "k out of n").

A new multisignature address will be constructed through the CLI with the following command

```bash!
namada client init-account \
--alias my-multisig \
--publickeys pk1,pk2,pk3... \
--signers signer1,signer2,signer3... \
--threshold k
```

### Proposing Candidacy
The council will be responsible to publish this address to voters and express their desired `spending_cap`. This will be done directly to the ledger through the following CLI command:

```bash!
namadac pgf-broadcast \
--council my-multisig \
--spending-cap 1.0
```
The `--spending-cap` argument is a `float` $0 < x \leq 1$, which indicates the maximum proportion of the total funds available to the PGF council that the PGF council is able to spend during their term.

A council consisting of the same members should also be able to propose multiple spending caps (with the same multisig address). These will be voted on as separate councils and votes counted separately.

Proposing candidacy as a PGF council is something that is done at any time. This simply signals to the rest of Governance that a given established multisignature account address is willing to be voted on during a PGF council election in the future.

Candidacy proposals last a default of 31 epochs. There is no limit to the number of times a council can be proposed for candidacy. This helps ensure that no PGF council is elected that does not intend to become one.

The structure of the candidacy proposal should be 

```rust
struct Candidacy {
    candidacy : Map< council: Council, (epoch: Epoch, attestation: Url)>
}
```

### Initiating the vote

Before a new PGF council can be elected, a governance proposal that suggests a new PGF council must pass. This vote is handled by the governancea proposal type `PgfProposal`.

The the struct of `PgfProposal` is constructed as follows, and is explained in more detail in the [governance specs](../base-ledger/governance.md)

```rust
struct PgfProposal{
  id: u64
  content: Vec<u8>,
  author: Address,
  r#type: PGFCouncil,
  votingStartEpoch: Epoch,
  votingEndEpoch: Epoch,
  graceEpoch: Epoch,
}
```

The above proposal type exists in order to determine *whether* a new PGF council will be elected. In order for a new PGF council to be elected (and hence halting the previous council's power), $\frac{1}{3}$ of validating power must vote on the `PgfProposal`. [Approval voting](https://en.wikipedia.org/wiki/Approval_voting#:~:text=Approval%20voting%20allows%20voters%20to,consider%20to%20be%20reasonable%20choices.) is employed in order to elect the new PGF council, *whilst* the `PgfProposal` is active. In other words, voters may vote for multiple PGF councils, and the council with the greatest proportion of votes will be elected.

See the example below for more detail, as it may serve as the best medium for explaining the mechanism.

### Voting on the council
After the `PgfProposal` has been submitted, and once the council has been constructed and brodcasted, the council address can be voted on by governance particpants. All voting must occur between `votingStartEpoch` and `votingEndEpoch`.

The vote for a set of PGF council addresses will be constructed as follows.

Each participant submits a vote through governance:
```rust
struct OnChainVote {
    id: u64,
    voter: Address,
    yay: proposalVote,
}
```

In turn, the proposal vote will include the structure:

```rust
HashSet<(address: Address, spending_cap: u64)>
```

The structure contains all the counsils voted, where each cousil is specified as a pair `Address` (the enstablished address of the multisig account) and `u64` (spending cap).

These votes will then be used in order to vote for various PGF councils. Multiple councils can be voted on through a vector as represented above.

#### Dealing with ties
In the rare occurance of a tie, the council with the lower spending_cap will win the tiebreak.

In the case of equal tiebreaks, the addresses with lower alphabetical order will be chosen. This is very arbitrary due to the expected low frequency.

### Electing the council

Once the elected council has been decided upon, the established address corresponding to the multisig is added to the `PGF` internal address, and the `spending_cap` variable is stored.

### Example

The below example hopefully demonstrates the mechanism more clearly.

````admonish note
The governance set consists of Alice, Bob, Charlie, Dave, and Elsa. Each member has 20% voting power.

The current PGF council consits of Dave and Elsa.

- At epoch 42, Alice proposes the `PgfProposal` with the following struct:

```rust
struct PgfProposal{
  id: 2
  content: Vec<32,54,01,24,13,37>,
  author: 0xalice,
  r#type: PGFCouncil,
  votingStartEpoch: Epoch(45),
  votingEndEpoch: Epoch(54),
  graceEpoch: Epoch(57),
}
```

- At epoch 47, after seeing this proposal go live, Bob and Charlie decide to put themselves forward as a PGF council. They construct a multisig with address `0xBobCharlieMultisig` and broadcast it on Namada using the CLI. They set their `spending_cap` to `1.0`.

- At epoch 48, Elsa submits a broadcasts a multisig PGF council address which includes herself and her sister.

- At epoch 49, Alice submits the vote:

```rust
struct OnChainVote {
    id: 2,
    voter: 0xalice,
    yay: proposalVote,
}
```

Whereby the `proposalVote` includes
```rust
HashSet<(address: 0xBobCharlieMultisig, spending_cap: 1.0)>
```

- At epoch 49, Bob and Charlie submit identical transactions. Charlie also 

- At epoch 50, Dave votes `Nay` on the proposal.

- At epoch 51, Elsa votes `Yay` but on the multisigs `0xElsaAndSisterMultisig` AND `0xBobCharlieMultisig`.

- At epoch 54, the voting period ends and the votes are tallied. Since 80% > 33% of the voting power voted `Yay` on this proposal, a new council will be elected. The council that received the most votes, in this case `0xBobCharlieMultisig` is elected the new PGF council.

- At epoch 57, Bob and Charlie have the effective power to carry out Public Goods Funding transactions.
````

### End of Term Summary

At the end of each term, the council is encouraged to submit a "summary"  which describes the funding decisions the councils have made and their reasoning for these decisions. This summary will act as an assessment of the council and will be the information point for governance to decide whether to re-elect the council.

## Mechanism

Once elected and instantiated, members of the PGF council will then unilaterally be able to propose and sign transactions for this purpose. The PGF council multisig will have an "allowance" to spend up to the `PGF` internal address's balance multiplied by the `spending_cap` variable.  Consensus on these transactions, in addition to motivation behind them will be handled off-chain, and should be recorded for the purposes of the "End of Term Summary".


### PGF council transactions
The PGF council members will be responsible for collecting signatures offline. One member will then be responsinble for submitting a transaction containing at least $k $ out of the signatures.

The collecting member of the council will then be responsible for submitting this tx through the multisig. The multisig will only accept the tx if this is true.

Note that there is no cap to $n$ in $k$-out-of-$n$ apart from the limitations of the multisig account.

The PGF council should be able to make both retroactive and continuous public funding transactions. Retroactive public funding transactions should be straightforward and implement no additional logic to a normal transfer.

However, for continuous PGF (cPGF), the council should be able to submit a one time transaction which indicates the recipient addresses that should be eligble for receiveing cPGF. 

The following data is attached to the PGF transaction and will allow the counsil to decide which projects will be continously funded. Each tuple represent the address and the respecting amount of NAM that will receive every epoch. The list of funding recipients will be stored in storage under the PGF internal address substorage space.

```rust
struct cPgfRecipients {
    recipients: HashSet<(Address, u64)>
}
```

The mechanism for these transfers will be implemented in `finalize-block.rs`, which will send the addresses their respective amounts each end-of-epoch.

## Addresses
Governance adds 1 internal address:

`PGF` internal address

The internal address VP will hold the allowance the 10% inflation of NAM. This will be added in addition to what was unspent by the previous council. It is important to note that it is this internal address which holds the funds, rather than the PGF council multisig.

The council should be able to burn funds (up to their spending cap), but this hopefully should not require additional functionality beyond what currently exists.

Further, the VP should contain the parameter that dictates the number of epochs a candidacy is valid for once it has been broadcasted and before it needs to be renewed.

### VP checks

The VP must check that the council does not exceed its spending cap.

The VP must also check that the any spending is only done by a the correctly elected PGF council multisig address.

## Storage

### Storage keys

Each recipient will be listed under this storage space (for cPGF)
- `/PGFAddress/cPGF_recipients/Address = Amount`
- `/PGFAddress/spending_cap = Amount`
- `/PGFAddress/spent_amount = Amount`
- `/PGFAddress/candidacy_length = u8`
- `/pgf/counsil_candidates/epoch = HashSet<Council>` (This is one solution, another would be to use a )
- `/pgf/candidacy = Candidacy` (Alternate solution: Candidacy defined above)

```admonish note
Marco: if we cannot delete the candidates, then I think the Map (second solution) is better. If instead we can prune the candidates, then I think the first solution is better. The first solution is faster at pruning (which ideally we’ll perform at every Epoch) and a bit slower at checking a vote (but we can assume votes for pgf will happen a bunch of times a year)
```

### Struct

```rust
struct Council {
    address: Address,
    spending_cap_amount: u64,
    spent_amount: u64,
}
```
The spending cap amount here is different from the `spending_cap` float. This is an actual NAM value that is calculated through `spending_cap * PGF_VP.balance`














