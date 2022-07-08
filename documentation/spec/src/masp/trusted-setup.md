# Trusted setup

## Introduction
Trusted Setups Ceremonies (and not multi-party computation protocols) were born with the conception of zk-SNARKs - Zero-knowledge succinct non-interactive arguments of knowledge. These ceremonies or events allow one to generate, in a distributed and trustless manner, the hidden randomnesss that constructs the parameters of the zk-SNARK. 

The first historical ceremony was the one for Zcash Sprout and was totally manual. The participants transferred DVDs between computers and burnt them in the end. Until recently, Trusted Setups required a lot of time, coordination and weren't that much scalable - only a dozens of participants would be allowed. Thanks to the advances in MPC - multi-party computation - for this specific application, we are now able to run a ceremony for thousands of participants in an automatic and somehow "parellel" manner. The protocol we are going to use for our Ceremony is called "optimistic MMORPG MPC" and it's a slight improvement to the [original paper MMORPG MPC](https://eprint.iacr.org/2017/1050.pdf) implemented by Celo and Aleo.

## High-level overview

### What is the Anoma Setup?
To enable private asset-agnostic bartering among any number of parties, Anoma uses a Multi-Asset Shielded Pool (MASP) circuit which is an extension of the Sapling circuit used in Zcash. This relies on a specific class of zero-knowledge proofs called zk-SNARKs. The setup ceremony generates the public parameters for the zk-SNARKs. In order to ensure the random numbers that derive the parameters aren't known by anyone, we are running a MPC ceremony which allow multiple independent parties to construct the parameters. As long as one contributor is honest, the security of the overall system is guaranteed.

#### Who are the actors?

In a Trusted Setup, we have 3 distinct actors:
1. The **Coordinator** who orchestrates the ceremony by generating challenges and keeping track of each contributor's progress.
2. The **Operator** who controls and monitors the Coordinator - that's us that will type commands. 
3. The **Contributors or Participants** who receive challenges and send them back with added randomness.

![](./trusted-setup-assets/trusted-setup-actors.png)

### How exactly does the setup work?

#### The phases
A Trusted Setup consists in 2 phases:

**Phase 1 (aka the Powers of Tau)** is circuit-agnostic i.e anyone who want to build a zk-SNARK can reuse the output of this phase to bootstrap their zk-SNARK e.g. we are going to take the Zcash Powers of Tau as input for our MASP circuit.

1. A coordinator generates an accumulator
2. Participant downloads the latest accumulator
3. Participant contributes their randomness to the accumulator (randomness is permantently deleted after this step)
4. Participant uploads the accumulator back to the coordinator
5. Coordinator verifies the accumulator was transformed correctly and produces a new challenge

**Phase 2 (aka parameterization to Groth16)** is circuit-specific. It's where we construct our zk-SNARK circuit (MASP circuit) itself.

1. Coordinator "prepares" the parameters from Phase 1 and converts them to Lagrange Coefficients
2. Participant downloads the latest state of the parameters
3. Participant contributes their randomness to the parameters (randomness is permantently deleted after this step)
4. Participant uploads the parameters back to the coordinator
5. Coordinator verifies the accumulator was transformed correctly
6. Loop from 2 for all participants

This produces parameters which can then be used for constructing Groth16 SNARKs for that circuit. The setup is sound so long as 1 party was honest and destroyed their randomness or "toxic waste" in step 3.


#### MMORPG MPC

Independently from the phase, the actors and the steps to run the protocol are the same. Without going into the cryptographic details in this section, the operator generates a challenge called a *Structured Reference String (SRS)* sends it to the first participant who takes it as input, does some computation and then sends the output back to the coordinator. The coordinator verifies the correctness of the processed challenge and sends it to the next participant in the queue. This is done sequentially.

#### Optimistic MMORPG MPC
In order to facilitate multiple participants in a round, the SRS is split up into many *chunks*. It allows participants to acquire a lock on a given chunk where they process the computation, send it back to the coordinator and then acquire the next chunk. This makes the protocol somehow *parellel* where the number of particpants during the same timeframe is increased.

![](./trusted-setup-assets/optimistic-mmorpg-mpc-diagram.png)

#### Contribution Sequence Diagram
![](./trusted-setup-assets/contribution-sequence-diagram.png)