## Shielded pool incentives

### Rationale

Private transactions made by individual users using the MASP increase the 
privacy set for other users, so even if the individual doesn't care whether a particular transaction is private, others benefit from their choice to do the transaction in private instead of in public. In the absence of a subsidy (the computation required for private state transitions is likely more expensive) or other incentives, users may not elect to make their transactions private when they do not need to because the benefits do not directly accrue to them. This provides grounds for a protocol subsidy of shielded transactions (relative to the computatation required), so that users who do not have a strong preference on whether or not to make their transaction private will be "nudged" by the fee difference to do so.

Separately, and additionally, a privacy set which is very small in absolute terms does not provide much privacy, and transactions increasing the privacy set provide more additional privacy if the privacy set is small. Compare, for example, the doubled privacy set from 10 to 20 transactions to the minor increase from 1010 to 1020 transactions. This provides grounds for some sort of incentive mechanism for _making_ shielded transactions which pays in inverse proportion to the size of the current privacy set (so shielded transactions when the privacy set is small receive increased incentives in accordance with their increased contributions to privacy).

Incentive mechanisms are also dangerous, as they give users reason to craft particular transactions when they might not otherwise have done so, and they must satisfy certain constraints in order not to compromise state machine throughput, denial-of-service resistance, etc. A few constraints to keep in mind:

- Fee subsidies cannot reduce fees to zero, or reduce fees so much that inexpensive transaction spam can fill blocks and overload validators.
- Incentives for contributing to the privacy set should not incentivise transactions which do not meaningfully contribute to the privacy set or merely repeat a previous action (shielded and unshielding the same assets, repeatedly transferring the same assets, etc.)
- Incentives for contributing to the privacy set, since the MASP supports many assets, will need to be adjusted over time according to actual conditions of use.

### Design

Namada enacts a shielded pool incentive which pays users a variable rate for keeping assets in the shielded pool. Assets do not need to be locked in any way. Users may claim rewards while remaining in the shielded pool using the convert circuit, and unshield the rewards (should they wish to) at some later point in time. The protocol uses a PD-controller to target particular minimum amounts of particular assets being shielded. Rewards accumulate automatically over time, so claiming rewards more frequently does not result in additional funds.

### Implementation

When users deposit assets into the shielded pool, the current epoch is appended to the asset type. Users can use these "epoched assets" as normal within the shielded pool. When epochs advance, users can use the [convert circuit](../masp/convert-circuit.md) to convert assets tagged with the old epoch to assets tagged with the new epoch, receiving shielded rewards in NAM proportional to the amount of the asset they had shielded, which automatically compound while the assets are shielded and the epochs progressing. When unshielding from the shielded pool, assets must be first converted to the current epoch (claiming any rewards), after which they can be converted back to the normal (un-epoched) unshielded asset denomination.

Namada allocates up to 10% per annum inflation of NAM to pay for shielded pool rewards. This inflation is kept in a temporary shielded rewards pool, which is then allocated according to a set of PD (proportional-derivative) controllers for assets and target shielded amounts configured by Namada governance. Each epoch, subject to available rewards, each controller calculates the reward rate for its asset in this epoch, which is then used to compute entries into the conversion table. Entries from epochs before the previous one are recalculated based on cumulative rewards. Users may then asynchronously claim their rewards by using the convert circuit at some future point in time.
