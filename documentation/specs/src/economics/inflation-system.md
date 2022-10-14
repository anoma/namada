## Inflation system

The Namada protocol controls the Namada token NAM (the native staking token), which is programmatically minted to pay for algorithmically measurable public goods - proof-of-stake security and shielded pool usage - and out-of-band public goods. Proof-of-stake rewards are paid into the reward distribution mechanism in order to distribute them to validators and delegators. Shielded pool rewards are paid into the shielded pool reward mechanism, where users who kept tokens in the shielded pool can claim them asynchronously. Public goods funding is paid to the public goods distribution mechanism, which further splits funding between proactive and retroactive funding and into separate categories.

### Proof-of-stake rewards

The security of the proof-of-stake voting power allocation mechanism used by Namada is dependent in part upon locking (bonding) tokens to validators, where these tokens can be slashed should the validators misbehave. Funds so locked are only able to be withdrawn after an unbonding period. In order to reward validators and delegators for locking their stake and participating in the consensus mechanism, Namada pays a variable amount of inflation to all delegators and validators. The amount of inflation paid is varied on a PD-controller in order to target a particular bonding ratio (fraction of the NAM token being locked in proof-of-stake). Namada targets a bonding ratio of 2/3, paying up to 10% inflation per annum to proof-of-stake rewards. See [reward distribution mechanism](./proof-of-stake/reward-distribution.md) for details.

### Shielded pool rewards

Privacy provided by the MASP in practice depends on how many users use the shielded pool and what assets they use it with. To increase the likelihood of a sizeable privacy set, Namada pays a variable portion of inflation, up to 10% per annum, to shielded pool incentives, which are allocated on a per-asset basis by a PD-controller targeting specific amounts of each asset being locked in the shielded pool. See [shielded pool incentives](./shielded-pool-incentives.md) for details.

### Public goods funding

Namada provides 10% per annum inflation for other non-algorithmically-measurable public goods. See [public goods funding](./public-goods-funding.md) for details.

## Detailed inflation calculation model

Inflation is calculated and paid per-epoch as follows.

First, we start with the following fixed (governance-alterable) parameters:

- $Cap_{PoS}$ is the cap of proof-of-stake reward rate, in units of percent per annum (genesis default: 10%)
- $Cap_{SP-A}$ is the cap of shielded pool reward rate for each asset $A$, in units of percent per annum
- $I_{PGF}$ is the public goods funding reward rate, in units of percent per annum
- $R_{PoS-Target}$ is the target staking ratio (genesis default: 2/3)
- $R_{SP-A-Target}$ is the target amount of asset $A$ locked in the shielded pool (separate value for each asset $A$)
- ${KP}_{PoS}$ is the proportional gain of the proof-of-stake PD controller, as a fraction of the total input range
- ${KD}_{PoS}$ is the derivative gain of the proof-of-stake PD controller, as a fraction of the total input range
- ${KP}_{SP_A}$ is the proportional gain of the shielded pool reward controller for asset $A$, as a fraction of the total input range (separate value for each asset $A$)
- ${KD}_{SP_A}$ is the derivative gain of the shielded pool reward controller for asset $A$, as a fraction of the total input range (separate value for each asset $A$) 
- $EpochsPerYear$ is the number of epochs per year (genesis default: 365)

Second, we take as input the following state values:

- $S_{NAM}$ is the current supply of NAM
- $L_{NAM}$ is the current amount of NAM locked in proof-of-stake
- $I_{PoS}$ is the current proof-of-stake reward rate, in units of tokens per epoch
- $E_{PoS-last}$ is the error in proof-of-stake lock ratio (stored from the past epoch)
- $L_{SP_A}$ is the current amount of asset $A$ locked in the shielded pool (separate value for each asset $A$)
- $I_{SP_A}$ is the current shielded pool reward rate for asset $A$, in units of tokens per epoch
- $E_{SP_A-last}$ is the error in shielded pool lock amount for asset $A$ (stored from the past epoch) (separate value for each asset $A$)

Public goods funding inflation can be calculated and paid immediately (in terms of total tokens per epoch):

- $T_{PGF} := I_{PGF} * S_{NAM} / EpochsPerYear$

These tokens are distributed to the public goods funding validity predicate.

To run the PD-controllers for proof-of-stake and shielded pool rewards, we first calculate some intermediate values:

- Calculate the latest staking ratio $R_{PoS}$ as $L_{NAM} / S_{NAM}$
- Calculate the per-epoch cap on proof-of-stake and shielded pool reward rates
    - $Cap_{PoS-Epoch} := S_{NAM} * Cap_{PoS} / EpochsPerYear$
    - $Cap_{SP_A-Epoch} := S_{NAM} * Cap_{SP_A} / EpochsPerYear$ (separate value for each $A$)
    - ${KP}_{PoS} := {KP}_{PoS} * Cap_{PoS-Epoch}$
    - ${KD}_{PoS} := {KD}_{PoS} * Cap_{PoS-Epoch}$
    - ${KP}_{SP_A} := {KP}_{SP_A} * Cap_{SP_A-Epoch}$
    - ${KD}_{SP_A} := {KD}_{SP_A} * Cap_{SP_A-Epoch}$
- Calculate PD-controller constants to be used for this epoch

Then, for proof-of-stake first, run the PD-controller:

- Calculate the error $E_{PoS} := R_{PoS-Target} - R_{PoS}$
- Calculate the error derivative $E'_{PoS} := E_{PoS} - E_{PoS-last}$
- Calculate the control value $C_{PoS} := (KP_{PoS} * E_{PoS}) - (KD_{PoS} * E'_{PoS})$
- Calculate the new $I_{PoS} := max(0, min(I_{PoS} + C_{PoS}, Cap_{PoS}))$

These tokens are distributed to the proof-of-stake reward distribution validity predicate.

Similarly, for each asset $A$ for which shielded pool rewards are being paid:

- Calculate the error $E_{SP_A} := L_{SP_A-Target} - L_{SP_A}$
- Calculate the error derivative $E'_{SP_A} := E_{SP-A} - E_{SP_A-last}$
- Calculate the control value $C_{SP_A} := (KP_{SP_A} * E_{SP_A}) - (KD_{SP_A} * E'{SP_A})$
- Calculate the new $I_{SP_A} := max(0, min(I_{SP_A} + C_{SP_A}, Cap_{SP_A-Epoch}))$

These tokens are distributed to the shielded pool reward distribution validity predicate.

Finally, we store the current inflation and error values for the next controller round.