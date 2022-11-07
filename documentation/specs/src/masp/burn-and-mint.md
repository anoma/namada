# Burn and Mint conversion transactions in MASP

## Introduction

Ordinarily, a MASP transaction that does not shield or unshield assets must achieve a homomorphic net value balance of 0. Since every asset type has a pseudorandomly derived asset generator, it is not ordinarily feasible to achieve a net value balance of 0 for the transaction without each asset type independently having a net value balance of 0. Therefore, intentional burning and minting of assets typically requires a public "turnstile" where some collection of assets are unshielded, burned or minted in a public transaction, and then reshielded. Since this turnstile publicly reveals asset types and amounts, privacy is affected.

The goal is to design an extension to MASP that allows for burning and minting assets according to a predetermined, fixed, public ratio, but without explicitly publicly revealing asset types or amounts in individual transactions.

## Approach

In the MASP, each Spend or Output circuit only verifies the integrity of spending or creation of a specific note, and does not verify the integrity of a transaction as a whole. To ensure that a transaction containing Spend and Output descriptions does not violate the invariants of the shielded pool (such as the total unspent balance of each asset in the pool) the value commitments are added homomorphically and this homomorphic sum is opened to reveal the transaction has a net value balance of 0. When assets are burned or minted in a MASP transaction, the homomorphic net value balance must be nonzero, and offset by shielding or unshielding a corresponding amount of each asset.

Instead of requiring the homomorphic sum of Spend and Output value commitments to sum to 0, burning and minting of assets can be enabled by allowing the homomorphic sum of Spend and Output value commitments to sum to either 0 or a multiple of an allowed conversion ratio. For example, if distinct assets A and B can be converted in a 1-1 ratio (meaning one unit of A can be burned to mint one unit of B) then the Spend and Output value commitments may sum to a nonzero value.

## Allowed conversions

Let $A_1, A_2, \ldots, A_n$ be distinct asset types. An _allowed conversion_ is a list of tuples $\{(A_1, V_1), (A_2, V_2), \ldots (A_n, V_n)\}$ where $V_1, \ldots, V_n$ are signed 64-bit integers.

The _asset generator_ of an allowed conversion is defined to be: $vb = [V_1] vb_1 + \ldots + [V_n] vb_n$ where $vb_i$ is the asset generator of asset $A_i$. 

Each allowed conversion is committed to a Jubjub point using a binding Bowe-Hopwood commitment of its asset generator (it is not necessary to be hiding). All allowed conversion commitments are stored in a public Merkle tree, similar to the Note commitment tree. Since the contents of this tree are entirely public, allowed conversions may be added, removed, or modified at any time.

## Convert circuit

In order for an unbalanced transaction containing burns and mints to get a net value balance of zero, one or more value commitments burning and minting assets must be added to the value balance. Similar to how Spend and Output circuits check the validity of their respective value commitments, the Convert circuit checks the validity and integrity of:

1.    There exists an allowed conversion commitment in the Merkle tree, and
1.    The imbalance in the value commitment is a multiple of an allowed conversion's asset generator

In particular, the Convert circuit takes public input:

$$(rt, cv^{mint})$$

and private input:

$$(path, pos, cm, v, rcv, vb)$$

and the circuit checks:

1. Merkle Path validity: $path, pos$ is a valid Merkle path from $cm$ to $rt$.
2. Allowed conversion commitment integrity: $cm$ opens to $repr(vb)$
3. Value commitment integrity: $cv^{mint} = [8*v] vb + [rcv] R$ where $R$ is the value commitment randomness base

Note that 8 is the cofactor of the Jubjub curve.

## Balance check

Previously, the transaction consisted of Spend and Output descriptions, and a value balance check that the value commitment $cv^{in} - cv^{out}$ opens to 0. Now, the transaction validity includes:

1. Checking the Convert description includes a valid and current $rt$
2. Checking the value commitment $cv^{in} + cv^{mint} - cv^{out}$ opens to 0

### Directionality

Directionality of allowed conversions must be enforced as well. That is, $v$ must be a non-negative 64 bit integer. If negative values of $v$ are allowed (or equivalently, unbounded large values of $v$ in the prime order scalar field of the Jubjub curve) then an allowed conversion could happen in the reverse direction, burning the assets intended to be minted and vice versa. 

### Cycles 

It is also critical not to allow cycles. For example, if $\{(A_1, -1), (A_2, 2)\}$ and $\{(A_1, 1), (A_2, -1)\}$ are allowed conversions, then an unlimited amount of $A_2$ may be minted from a nonzero amount of $A_1$. Since 

## Alternative approaches

It may theoretically be possible to implement similar mechanisms with only the existing Spend and Output circuits. For example, a Merkle tree of many Notes could be created with asset generator $[-1] vb_1 + vb_2$ and many different values, allowing anyone to Spend these public Notes, which will only balance if proper amounts of asset type 1 are Spent and asset type 2 are Output.

However, the Nullifier integrity check of the Spend circuit reveals the nullifier of each of these Notes. This removes the privacy of the conversion as the public nullifier is linkable to the allowed conversion. In addition, each Note has a fixed value, preventing arbitrary value conversions.

## Conclusion

In principle, as long as the Merkle tree only contains allowed conversions, this should permit the allowed conversions while maintaining other invariants. Note that since the asset generators are not derived in the circuit, all sequences of values and asset types are allowed. 