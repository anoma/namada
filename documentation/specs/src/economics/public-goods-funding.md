### Motivation

**Public goods** are non-excludable non-rivalrous items which provide benefits of some sort to their users. Examples include languages, open-source software, research, designs, Earth's atmosphere, and art (conceptually - a physical painting is excludable and rivalrous, but the painting as-such is not). Namada's software stack, supporting research, and ecosystem tooling are all public goods, as are the information ecosystem and education which provide for the technology to be used safety, the hardware designs and software stacks (e.g. instruction set, OS, programming language) on which it runs, and the atmosphere and biodiverse environment which renders its operation possible. Without these things, Namada could not exist, and without their continued sustenance it will not continue to. Public goods, by their nature as non-excludable and non-rivalrous, are mis-modeled by economic systems (such as payment-for-goods) built upon the assumption of scarcity, and are usually either under-funded (relative to their public benefit) or funded in ways which require artificial scarcity and thus a public loss. For this reason, it is in the interest of Namada to help out, where possible, in funding the public goods upon which its existence depends in ways which do not require the introduction of artificial scarcity, balancing the costs of available resources and operational complexity. 

### Design precedent

There is a lot of existing research into public-goods funding to which justice cannot be done here. Most mechanisms fall into two categories: need-based and results-based, where need-based allocation schemes attempt to pay for particular public goods on the basis of cost-of-resources, and results-based allocation schemes attempt to pay (often retroactively) for particular public goods on the basis of expected or assessed benefits to a community and thus create incentives for the production of public goods providing substantial benefits (for a longer exposition on retroactive PGF, see [here](https://medium.com/ethereum-optimism/retroactive-public-goods-funding-33c9b7d00f0c), although the idea is [not new](https://astralcodexten.substack.com/p/lewis-carroll-invented-retroactive)). Additional constraints to consider include the cost-of-time of governance structures (which renders e.g. direct democracy on all funding proposals very inefficient), the necessity of predictable funding in order to make long-term organisational decision-making, the propensity for bike-shedding and damage to the information commons in large-scale public debate (especially without an identity layer or Sybil resistance), and the engineering costs of implementations.

# On chain mechanism



### Mechanism

Namada instantiates a dual proactive/retroactive public-goods funding model, stewarded by a public-goods council elected by limited liquid democracy.

This requires the following protocol components:
- Limited liquid democracy / targeted delegation: Namada's current voting mechanism is altered to add targeted delegation. By default, each delegator delegates their vote in governance to their validator, but they can set an alternative governance delegate who can instead vote on their behalf (but whose vote can be overridden as usual). Validators can also set governance delegates, in which case those delegates can vote on their behalf, and on the behalf of all delegators to that validator who do not override the vote, unless the validator overrides the vote. This is a limited form of liquid democracy which could be extended in the future. 
- Funding council: bi-annually (every six months), Namada governance elects a public goods funding council by stake-weighted approval vote (see below). Public goods funding councils run as groups. The public goods funding council decides according to internal decision-making procedures (practically probably limited to a k-of-n multisignature) how to allocate continuous funding and retroactive funding during their term. Namada genesis includes an initial funding council, and the next election will occur six months after launch.
- Continuous funding: Namada prints an amount of inflation fixed on a percentage basis dedicated to continuous funding. Each quarter, the public goods funding council selects recipients and amounts (which in total must receive all of the funds, although they could burn some) and submits this list to the protocol. Inflation is distributed continuously by the protocol to these recipients during that quarter.
- Retroactive funding: Namada prints an amount of inflation fixed on a percentage basis dedicated to retroactive funding. Each quarter, the public goods funding council selects recipients and amounts (which in total must receive all of the funds) and submits this list to the protocol. Amounts are distributed immediately as lump sums. The public goods funding council is instructed to use this funding to fund public goods retroactively, proportional to assessed benefit.
- Privacy of council votes: in order to prevent targeting of individual public goods council members, it is important that council acts only as a group. Whatever internal decision-making structure it uses is up the council; Namada governance should evaluate councils as opaque units. We may need a simple threshold public key to provide this kind of privacy - can we evaluate the implementation difficulty of that?
- Stake-weighted approval voting: as public goods councils are exclusive, we can use a stake-weighted form of approval voting. Governance voters include all public goods council candidates of which they approve, and the council candidate with the most stake approving it wins. This doesn't have game-theoretic properties as nice as ranked-choice voting (especially when votes are public, as they are at the moment), but it is _much_ simpler ([background](https://en.wikipedia.org/wiki/Condorcet_method)), and in practice I do not think there will be too many public goods council candidates.
- Interface support: the interface should support limited liquid democracy for delegate selection and approval voting for public goods council candidates. The interface or explorer should display past retroactive PGF winners and past/current continuous funding recipients. Proposal submission for continuous and retroactive funding will happen separately, in whatever manner the public goods council deems fit.

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

In Namada, 10% inflation per annum of the NAM token is directed to this public goods mechanism, 5% to continuous funding and 5% to retroactive funding. This is a genesis default and can be altered by governance.

Namada encourages the public goods council to adopt a default social consensus of an equal split between categories, meaning 1.25% per annum inflation for each category (e.g. 1.25% for technical research continuous funding, 1.25% for technical research retroactive PGF). If no qualified recipients are available, funds may be redirected or burnt.

Namada also pays the public goods council members themselves (in total) a default of 0.1% inflation per annum.