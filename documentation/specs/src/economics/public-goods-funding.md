# PGF specs

## Voting for the Council


### Initiating the vote
Voting for the council is handled by Governance in the PGFProposal type.

The governance proposal will include the following message

```rust!
struct PGFProposal{
id: u64
content: Vec<u8>,
author: Address,
r#type: PGFCouncil,
votingStartEpoch: Epoch,
votingEndEpoch: Epoch,
graceEpoch: Epoch,
}
```

### Constructing the council
All valid PGF councils will be established multisignature account addresses. These must be created by the intdended parties that wish to create a council. The council will therefore have the discretion to decide what threshold will be required for their multisig (i.e the "k" in the "k out of n").

The council will be resonsible to publish this address to voters and express their desired `spending_cap`. 

A council consisting of the same members should also be able to propose multiple spending caps (with the same multisig address). These will be voted on as separate councils and votes counted separately.


### Voting on the council
Once the council has been constructed, it can be voted on by governance particpants through a vote as structured below:

```rust
struct OnChainVote {
    id: u64,
    voter: Address,
    yay: proposalVote,
}
```

In turn the proposal vote will include the a structure like:

```rust
HashSet<(Address, u64)>
```

The structure contains all the counsils voted, where each cousil is specific as a pair `Address` (the enstablished address of the multisig account) and `u64` (spending cap)

These votes will then be used in order to vote for various PGF councils. Multiple councils can be voted on through a vector as represented above.


### CLI

TODOs:

- PGF Votes
- Construction of PGF council multisigs 

### Dealing with ties
In the rare occurance of a tie, the council with the lower spending_cap will win the tiebreak.

In the case of equal tiebreaks, the addresses with lower alphabetical order will be chosen. This is very arbitrary due to the expected low frequency.

### Ensuring enough votes 

In order for a new PGF council to be elected (and hence halting the previous council's power), $\frac{1}{3}$ of validating power must vote on the "New PGF Council Proposal". Once this condition has been met, majority vote will be decided as to which PGF council will be elected.

### Electing the council

Once the elected council has been decided upon, the established address corresponding to the multisig is added to the `PGF` internal address, and the `spending_cap` variable is stored.

### End of Term Summary

At the end of each term, the council is encouraged to submit a "summary"  which describes the funding decisions the councils have made and their reasoning for these decisions. This summary will act as an assessment of the council and will be the information point for governance to decide whether to re-elect the council. This summary should be made as transparant as pos

## Mechanism

The governance proposal PGFCouncil elects the multisignature account address of the PGF council.

The PGF council members will (by definition) be in charge of a "k of n" multisignature account whereby the $\text{10% inflation} * \text{spending_cap}$ is allocated and spent from the `PGF` internal address.

Members of the PGF council will then unilaterally be able to propose and sign transactions for this purpose. Consensus on these transactions, in addition to motivation behind them will be handled off-chain, and should be recorded for the purposes of the "End of Term Summary".


### cPGF (continuous PGF)

<!-- These transactions will be more involved than the rPGF transactions (which will act as simple transactions).


```rust
struct cPGFTx {
    // Source address - the multisig
    address: Address,
    // Asset identifier for this input - will always be NAM
    token: NAM,
    // Asset value in the input, will be distributed each epoch
    amount_epoch: u64,
    // A signature over the hash of the transaction
    sig: Signature,
    // Used to verify the owner's signature
    pk: PublicKey,
}
```

```rust!
struct TxOut {
    // Destination addresses (can be a vector)
    address: Vec<Address>,
    // Asset identifier for this output
    token: NAM,
    // Asset value in the output, will happen each epoch
    amount: u64,
}
``` -->

The following data is attached to the PGF transaction and will allow the counsil to decide which projects will be continously funded. Each tuple reppresent the address and the respecting amount of NAM that will receive every epoch. The list of project will be stored in storage under the PGF internal address substorage space.

```rust
struct PFGTxData {
    projects: HashSet<(Address, u64)>
}
```

### rPGF (retroactive PGF)
No different logic compared to normal `Transfer` txs, except that it should allow for multiple receivers (see above).


## Addresses
Governance adds 1 internal address:

`PGF` internal address

The internal address VP will be allocated the 10% inflation of NAM. This will be added in addition to what was unspent by the previous council.
It will also implement the logic required in order to allow the cPGF transactions to be made. I.e finalize-block, which will send the addresses their respective amounts each end-of-epoch.

The Governance address should also allow the burning of funds by the council.


## Storage

### Storage keys

Each project will be listed under this storage space (for cPGF)
- `/$PGFAddress/active_projects/$Address = $Amount`

### Data structure

PGF proposals will be governance proposals. See governance.


### Transaction signature
The PGF council members will be responsible for collecting signatures offline. One member will then be responsinble for submitting a transaction containing at least $k$ out of the signatures.

The collecting member of the council will then be responsible for submitting this tx through the multisig. The multisig will only accept the tx if this is true.

Note that there is no cap to $n$ in $k$-out-of-$n$ apart from the limitations of the multisig account.


## VP definition


The `PGF` VP should ensure that the amount specified to each address in a `cPGF` tx is received by the receiver at the end of each tx. This logic will be implemented in `finalize_block.rs`.

The VP must therefore store the following data structure

```rust!
struct cPGFReceviers{
    receivers_amount: Vec<Vec<Address, u8>> // where u8 is the amount to be sent to that address
}
```

In addition to this, the VP must ensure that no council exceeds their respective spending cap.

```rust!
pub fn(self) -> bool {
    if self.amount.iter().sum() > self.spending_cap {
        return false
    }
    else {
        turn true
    }
}
```









