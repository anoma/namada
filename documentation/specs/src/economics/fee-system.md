## Fee system

In order to be accepted by the Namada ledger, transactions must pay fees. Transaction fees serve two purposes: first, the efficient allocation of block space given permissionless transaction submission and varying demand, and second, incentive-compatibility to encourage block producers to add transactions to the blocks which they create and publish.

Namada transaction fees can be paid in any fungible token which is a member of a whitelist controlled by Namada governance. Governance also sets minimum fee rates (which can be periodically updated so that they are usually sufficient) which transactions must pay in order to be accepted (but they can always pay more to encourage the proposer to prioritise them). When using the shielded pool, transactions can also unshield tokens in order to pay the required fees.

The token whitelist consists of a list of $(T, GP_{min})$ pairs, where $T$ is a token identifier and $GP_{min}$ is the minimum price per unit gas which must be paid by a transaction paying fees using that asset. This whitelist can be updated with a standard governance proposal. All fees collected are paid directly to the block proposer (incentive-compatible, so that side payments are no more profitable).

todo: fees paid to block proposer??

The transaction whitelist held by governance associates to each
whitelisted transaction a fee $f_{tx}$ per "transaction unit". The
definition of a transaction unit may vary per VP; some transactions
may only ever cost the same amount, while a complex MASP transaction
with many spends, outputs, and converts counts as one unit for each of
these. The unit of these is the generic gas unit in which price-per-gas
for tokens is defined above. Whitelisted fees may be updated by
governance using a standard proposal.

When a transaction is submitted with $n$ units of data, its
responsibility is to pay the predictable flat fee $n * f_{tx} *
GP_{min}$, hereafter $F$, in some whitelisted token $T$. Generically,
this may be done by transferring the token (which may be a simple
transparent NAM transfer, a bridged multitoken transfer, or the
transparent output of a shielded transaction) to a native VP address
designated for fee burning. It shall be lawful for a block proposer to
include a transaction transferring fees from the fee address to its own
registered fee-receiving address.

todo: should we allow mixed-token fees? do they really go right to the
proposer?

It is the responsibility of consensus to do the above multiplication
using governance values and verify that each transaction pays fees of
at least that amount. This requires knowing how many transaction units
are included in a transaction by inspecting the transaction data
payload.

todo: can we literally just do this by size in bytes?
