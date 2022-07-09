## Fee system

In order to be accepted by the Namada ledger, transactions must pay fees in NAM. Transaction fees serve two purposes: first, the efficient allocation of block space given permissionless transaction submission and varying demand, and second, incentive-compatibility to encourage block producers to add transactions to the blocks which they create and publish.

Namada follows a [tipless version](https://arxiv.org/pdf/2106.01340.pdf) of the EIP 1559 scheme. In contrast with the original EIP 1559, the transaction fee of this tipless version consists solely of a base fee, with no tip. The base fee increases whenever blocks are fuller than the desired capacity and decreases when the blocks haven't reached this capacity (i.e. a P-controller). Namada uses a target block fullness of 0.5 (adjustable by governance).

To provide an incentive for the inclusion of transactions by proposers, Namada transfers 50% of the base fee to the next few block proposers, proportional to block fullness. For example, if the block is 100% full, the proposer will receive full fees, whereas if the block is only 25% full, they will only receive 25% of the fees. These fees are kept in a temporary account, with at most a tenth used to pay out the current proposer. 

The other 50% of the base fee is immediately burned, reducing the total supply of NAM by the amount burned.

Base fees are changed to reflect changes in demand, with a smoothing rate to reduce the frequency at which transaction authors need to calculate required fees. Namada requires a minimum of twenty (20) blocks between base fee changes and a delay of ten (10) blocks before a base fee change is applied. Each change of the base fee follows the function below:

$$
Tx_{fee}'=Tx_{fee}*(1+ch_{max}(F-0.5))
$$
where $Tx_{fee}$ is the previous transaction fee, $Tx_{fee}'$ is the new transcation fee, $ch_{max}$ is the max change the transaction fee can have, and $F$ is the block fullness. We decided that our target block fullness is 50 %.  

![](https://i.imgur.com/p3qeWw3.jpg)

In Namada, the base fee is applied as a gas price, where the total fee of a particular transaction will be equal to the product of the base fee and consumed gas.