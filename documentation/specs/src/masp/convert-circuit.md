# Convert Circuit

## Convert Circuit Description
The high-level description of `Convert` can be found [Burn and mint](./burn-and-mint.html).

The `Convert` provides a mechanism that burning and minting of assets can be 
enabled by adding `Convert Value Commitments` in transaction and ensuring the homomorphic sum of `Spend`, `Output` and `Convert` value commitments to be zero.

The Convert value commitment is constructed from `AllowedConversion` which was published earlier in `AllowedConversion Tree`. The `AllowedConversion` defines the allowed conversion assets. The `AllowedConversion Tree` is a merkle hash tree stored in the ledger.

## AllowedConversion
An `AllowedConversion` is a compound asset type in essence, which contains distinct asset types and the corresponding conversion ratios.

`AllowedConversion` is an array of tuple $\{(t_1, v_1^{ratio}),(t_2, v_2^{ratio})...(t_n, v_n^{ratio})\}$
* $t$: $\mathbb{B}^{\mathcal{l}_t}$ is a bytestring representing the asset identifier of the note.
* $v^{ratio}$: $v^{ratio}$ is a signed 64-bit integer in the range $\{−2^{63}
  ,\dots, 2^{63} − 1\}$.

Calculate:
 
* $vb_i := repr_{\mathbb{J}}(PRF^{vcgMASP}(t_i))$
* $vb^{allowedconversion} = \Sigma_1^n([v_i^{ratio}]vb_i)$
* $cm^{allowedconversion} = \mathsf{PedersenHashToPoint}(''MASP\_\_PH'', [1]^6||vb^{allowedconversion})$

Note that `PedersenHashToPoint` is used the same as in `NoteCommitment` for now.

An `AllowedConversion` can be issued, removed and modified as public conversion rule by consensus authorization and stored in `AllowedConversion Tree` as leaf node.

An `AllowedConversion` can be used by proving the existence in `AllowedConversion Tree`(must use the latest root anchor), and then generating a `Convert Value Commitment` to be used in transaction.

## Convert Value Commitment
`Convert Value Commitment` is a tuple $(vb^{allowedconversion}, v^{convert}, rcv^{convert})$
* $v^{convert}$: $v^{convert}$ is an unsigned integer representing the value 
  of conversion in range $[2^{64} − 1]$.

Choose independent uniformly random commitment trapdoors:
* $rcv^{convert}$ $\leftarrow \mathsf{ValueCommit}\mathsf{.GenTrapdoor}()$

Check that $h_\mathbb{J}repr_{\mathbb{J}}(PRF^{vcgMASP}(vb^{allowedconversion}))$ is of type $KA^{Sapling}.PublicPrimeOrder$, i.e. it is a valid ctEdwards Curve point on the JubjubCurve (as defined in the original Sapling specification) not equal to $O_{\mathbb{J}}$.  If it is equal to $O_{\mathbb{J}}$, $vb^{allowedconversion}$ is an invalid asset identifier.

Calculate
* $cv^{convert} = [v^{convert} h_\mathbb{J}]vb^{allowedconversion} + [rcv^{convert}]\mathsf{GroupHash}_{\mathsf{URS}}^{\mathsf{\mathbb{J}^{(r)*}}}(''MASP\_\_r\_'',''r'')$

Note that $\mathsf{GroupHash}_{\mathsf{URS}}^{\mathsf{\mathbb{J}^{(r)*}}}(''MASP\_\_r\_'',''r'')$ is used the same as in `NoteCommitment` for now.


## AllowedConversion Tree
`AllowedConversion Tree` has the same structure as `Note Commitment Tree` and is an independent tree stored in ledger.
* $\mathsf{MerkleDepth^{Convert}}$: 32(for now)
* leaf node: $cm^{allowedconversion}$

## Convert Statement 
The Convert circuit has 47358 constraints.

Let $l_{MerkleSapling}$, $l_{scalar}$, $\mathsf{ValueCommit}$, $\mathsf{PedersenHashToPoint}$, $\mathsf{GroupHash}_{\mathsf{URS}}^{\mathsf{\mathbb{J}^{(r)*}}}$, $\mathbb{J}$  be as defined in the original Sapling specification.

A valid instance of $\pi_{convert}$ assures that given a primary input:
* $rt^{convert}: \mathbb{B}^{l_{MerkleSapling}}$
* $cv^{convert}: \mathsf{ValueCommit.Output}$

the prover knows an auxiliary input:
* $path: \mathbb{B}^{[l_{Merkle}][MerkleDepth^{Convert}]}$
* $pos: (0..2^{MerkleDepth^{Convert}}-1)$
* $cm^{allowedconversion}: \mathbb{B}^{MerkleSapling}$
* $vb^{allowedconversion}: \mathbb{J}$
* $rcv^{convert}: \{0..2^{l_{scalar}}-1\})$
* $v^{convert}: \{0..2^{l_{convert\_value}}-1\}$

such that the following conditions hold:
* AllowedConversion cm integrity: $cm^{allowedconversion} = \mathsf{PedersenHashToPoint}(''MASP\_\_PH'', [1]^6||vb^{allowedconversion})$

* Merkle path validity: Either $v^{convert}$ is 0; or $(path, pos)$ is a valid Merkle path of depth $MerkleDepth^{Convert}$, as as defined in the original Sapling specification, from $cm^{allowedconversion}$ to the anchor $rt^{convert}$

* Small order checks: $vb^{allowedconversion}$ is not of small order, i.e.$[h_\mathbb{J}]vb^{allowedconversion} \neq O_\mathbb{J}$.

* Convert Value Commitment integrity: $cv^{convert} = [v^{convert} h_\mathbb{J}]vb^{allowedconversion} + [rcv^{convert}]\mathsf{GroupHash}_{\mathsf{URS}}^{\mathsf{\mathbb{J}^{(r)*}}}(''MASP\_\_r\_'',''r'')$

Return $(cv^{convert}, rt^{convert},\pi_{convert})$

Notes: 
* Public and auxiliary inputs MUST be constrained to have the types specified. In particular, see the original Sapling specification, for required validity checks on compressed representations of Jubjub curve points. The ValueCommit.Output type also represents points, i.e. $\mathbb{J}$.
* In the Merkle path validity check, each layer does not check that its 
  input bit sequence is a canonical encoding(in $[r_{\mathbb{S}} − 1]$) of 
  the integer from the previous layer.

## Incentive Description

Incentive system provide a mechanism in which the old asset(input) is burned, the new asset(output) is minted with the same quantity and incentive asset(reward) is minted with the convert ratio meanwhile.

### Incentive AllowedConversion Tree
As described in Convert circuit, the `AllowedConversion Tree` is an independent merkle tree in the ledger and contains all the Incentive AllowedConversions.

### Incentive AllowedConversion Struct
In general, there are three items in `Incentive AllowedConversion Struct`(but not mandatory？),i.e. input, output and reward. And each item has an asset type and a quantity(i64, for the convert ratio).

Note that the absolute value of input and output must be consistent in incentive system. The quantity of input is negative and the quantity of output is positive.

To guarantee the input and output to be open as the same asset type in 
future unshielding transactions, the input and output assets have the same 
prefix description(e.g. BTC_1, BTC_2...BTC_n). To prevent repeated 
shielding and unshielding and encourage long-term contribution to privacy 
pool, the postfix `timestamp` is used to distinguish the input and output 
assets. The `timestamp` depends on the update period and can be defined 
flexibly (e.g. date, epoch num). When a new `timestamp` occurs, the 
`AllowedConversion` will be updated to support all the "history asset" conversion to the latest one.  

### Incentive AllowedConversion Operation
`Incentive AllowedConversion` is governed by the incentive system, which 
will be in charge of issuing new incentive plan, updating(modifying) to the latest 
`timestamp`, and removing disabled conversion permissions.

* Issue 
    * Issue a new incentive plan for new asset. 
    * Issue for the last latest `AllowedConversion` when new `timestamp` occurs.
* Update
    * For every new `timestamp` that occurs, update the existing 
      `AllowedConversion`. Keep the input but update the output to the latest 
      asset and modify the reward quantity according to the ratio. 
* Destroy
    * Delete the `AllowedConversion` from the tree.
* Query Service
    * A service for querying the latest `AllowedConversion`, return (anchor, path, AllowedConversion).


### Workflow from User's Perspective 
* Shielding transaction 
    * Query the latest `timestamp` for target asset(non-latest will be rejected in tx execution)
    * Construct a target shielded note and shielding tx 
    * Add the note to shielded pool if tx executes successfully(check the prefix and the latest `timestamp`).
* Converting transaction
    * Construct spend notes from shielded notes 
    * Construct convert notes(query the latest `AllowedConversion`)
    * Construct output notes
    * Construct convert tx
    * Get incentive output notes with latest `timestamp` and rewards if tx executes successfully
* Unshielding transaction 
    * Construct unshielding transaction
    * Get unshielded note if tx executes successfully(check the prefix)

