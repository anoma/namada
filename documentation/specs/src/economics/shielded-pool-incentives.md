# Shielded pool incentives

Private transactions made by individual users using the MASP increase the privacy set for other users, so even if the individual doesn't care whether a particular transaction is private, others benefit from their choice to do the transaction in private instead of in public. In the absence of a subsidy (the computation required for private state transitions is likely more expensive) orother incentives, users may not elect to make their transactions private when they do not need to because the benefits do not directly accrue to them. This provides grounds for a protocol subsidy of shielded transactions (relative to the computatation required), so that users who do not have a strong preference on whether or not to make their transaction private will be "nudged" by the fee difference to do so.

Separately, and additionally, a privacy set which is very small in absolute terms does not provide much privacy, and transactions increasing the privacy set provide more additional privacy if the privacy set is small. Compare, for example, the doubled privacy set from 10 to 20 transactions to the minor increase from 1010 to 1020 transactions. This provides grounds for some sort of incentive mechanism for _making_ shielded transactions which pays in inverse proportion to the size of the current privacy set (so shielded transactions when the privacy set is small receive increased incentives in accordance with their increased contributions to privacy).

Incentive mechanisms are also dangerous, as they give users reason to craft particular transactions when they might not otherwise have done so, and they must satisfy certain constraints in order not to compromise state machine throughput, denial-of-service resistance, etc. A few constraints to keep in mind:

- Fee subsidies cannot reduce fees to zero, or reduce fees so much that inexpensive transaction spam can fill blocks and overload validators.
- Incentives for contributing to the privacy set should not incentivise transactions which do not meaningfully contribute to the privacy set or merely repeat a previous action (shielded and unshielding the same assets, repeatedly transferring the same assets, etc.)
- Incentives for contributing to the privacy set, since the MASP supports many assets, will need to be adjusted over time according to actual conditions of use.

(to be written up: formal definition of "privacy set" used for the incentives here)

<!--(to be written up: Joe's proposal)-->
The total incetives that are paid out, $I_L$, is minted each epoch based on the current parameters and are calculated according to the [inflation model](./inflation-system.md). This total is then distributed evenly among recipients. 
