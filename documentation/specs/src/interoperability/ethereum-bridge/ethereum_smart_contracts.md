# Ethereum Smart Contracts

## Contracts

There are five smart contracts that make up an Ethereum bridge deployment.

- Proxy
- Bridge
- Governance
- Vault
- wNAM

### Proxy

The _Proxy_ contract serves as a dumb storage for holding the addresses of other
contracts, specifically the _Governance_ contract, the _Vault_ contract and the
current _Bridge_ contract. Once deployed, it is modifiable only by the
_Governance_ contract, to update the address for which contract is the current
_Bridge_ contract.

The _Proxy_ contract is fixed forever once the bridge has been deployed.

### Bridge

The _Bridge_ contract is the only contract that unprivileged users of the bridge
may interact with. It provides methods for transferring ERC20s to Namada
(holding them in escrow in the _Vault_), as well as releasing escrowed ERC20s
from the _Vault_ for transfers made from Namada to Ethereum. It holds a
whitelist of ERC20s that may cross the bridge, and this whitelist may be updated
by the _Governance_ contract.

### Governance

The _Governance_ contract may "upgrade" the bridge by updating the _Proxy_
contract to point to a new _Bridge_ contract and/or a new _Governance_ contract.
It may also withdraw all funds from the _Vault_ to any specified Ethereum
address, if a quorum of validators choose to do so.

### wNAM

The _wNAM_ contract is a simple ERC20 token with a fixed supply, which is all
minted when the bridge is first deployed. After initial deployment, the entire
supply of _wNAM_ belongs to the _Vault_ contract. As NAM is transferred from
Namada to Ethereum, wNAM may be released from the _Vault_ by the _Bridge_.

The _wNAM_ contract is fixed forever once the bridge has been deployed.

### Vault

The _Vault_ contract holds in escrow any ERC20 tokens that have been sent over
the bridge to Namada, as well as a supply of _wNAM_ ERC20s to represent NAM that
has been sent from Namada to Ethereum. Funds held by the _Vault_ may only be
spendable by the current _Bridge_ contract. When ERC20 tokens are transferred
from Ethereum to Namada, they must be deposited to the _Vault_ via the _Bridge_
contract.

The _Vault_ contract is fixed forever once the bridge has been deployed.

## Namada-side configuration

When an account on Namada becomes a validator, they must provide two Ethereum
secp256k1 keys:

- the bridge key - a hot key for normal operations
- the governance key - a cold key for exceptional operations, like emergency
  withdrawal from the bridge

These keys are used to control the bridge smart contracts, via signing of
messages. Validators should be challenged periodically to prove they still retain
knowledge of their governance key, which is not regularly used.

## Deployment

The contracts should be deployable by anyone to any EVM chain using an automated
script. The following configuration should be agreed up front by Namada
governance before deployment:

- details of the initial consensus validator set that will control the bridge -
  specifically, for each validator:
  - their hot Ethereum address
  - their cold Ethereum address
  - their voting power on Namada for the epoch when the bridge will launch
- the total supply of the wNAM ERC20 token, which will represent Namada-native
  NAM on the EVM chain
- an initial whitelist of ERC20 tokens that may cross the bridge from Ethereum
  to Namada - specifically, for each whitelisted ERC20:
    - the Ethereum address of the ERC20 contract
    - a cap on the total amount that may cross the bridge, in units of ERC20

After a deployment has finished successfully, the deployer must not have any
privileged control of any of the contracts deployed. Any privileged actions must
only be possible via a message signed by a validator set that the smart
contracts are storing details of.

## Communication

### From Ethereum to Namada

A Namada chain's validators are configured to listen to events emitted by the
smart contracts pointed to by the _Proxy_ contract. The address of the _Proxy_
contract is set in a governance parameter in Namada storage. Namada validators
treat emitted events as authoritative and take action on them. Namada also knows
the address of the _wNAM_ ERC20 contract via a governance parameter, and treats
transfers of this ERC20 to Namada as an indication to release native NAM from
the `#EthBridge` account on Namada, rather than to mint a wrapped ERC20 as
is the case with all other ERC20s.

### From Namada to Ethereum

At any time, the _Governance_ and _Bridge_ contracts must store:

- a hash of the current Namada epoch's consensus validator set
- a hash of another epoch's consensus validator set. When the bridge is first
  deployed, this will also be the current Namada epoch's consensus validator set,
  but after the first validator set update is submitted to the _Governance_
  smart contract, this hash will always be an adjacent Namada epoch's consensus
  validator set i.e. either the previous epoch's, or the next epoch's

In the case of the _Governance_ contract, these are hashes of a map of
validator's _cold_ key addresses to their voting powers, while for the _Bridge_
contract it is hashes of a map of validator's _hot_ key addresses to their
voting powers. Namada validators may post signatures as on chain of relevant
messages to be relayed to the Ethereum bridge smart contracts (e.g. validator
set updates, pending transfers, etc.). Methods of the Ethereum bridge smart
contracts should generally accept:

- some message
- full details of some consensus validator set (i.e. relevant Ethereum addresses +
  voting powers)
- signatures over the message by validators from the this consensus validator set

Given this data, anyone should be able to make the relevant Ethereum smart
contract method call, if they are willing to pay the Ethereum gas. A call is
then authorized to happen if:

- The consensus validator set specified in the call hashes to *either* of the
  validator set hashes stored in the smart contract
- A quorum (i.e. more than 2/3 by voting power) of the signatures over the
  message are valid

### Validator set updates

Initial deployment aside, at the beginning of each epoch, the smart contracts
will contain details of the current epoch's validator set and the previous
epoch's validator set. Namada validators must endeavor to sign details of the
next epoch's validator set and post them on Namada chain in a protocol
transaction. Details of the next epoch's validator set and a quorum of
signatures over it by validators from the current epoch's validator set must
then be relayed to the _Governance_ contract before the end of the epoch, which
will update both the _Governance_ and _Bridge_ smart contracts to have the hash
of the next epoch's validator set rather than the previous epoch's validator
set. This should happen before the current Namada epoch ends. If this does not
happen, then the Namada chain must either halt or not progress to the next
epoch, to avoid losing control of the bridge.

When a validator set update is submitted, the hashes for the oldest validator
set are effectively "evicted" from the _Governance_ and _Bridge_ smart
contracts. At that point, messages signed by that evicted validator set will no
longer be accepted by the bridge.

#### Example flow

- Namada epoch `10` begins. Currently, the _Governance_ contract knows the
  hashes of the validator sets for epochs `9` and `10`, as does the _Bridge_
  contract.
- Validators for epoch `10` post signatures over the hash of details of the
  validator set for epoch `11` to Namada as protocol transactions
- A point is reached during epoch `10` at which a quorum of such signatures is
  present on the Namada chain
- A relayer submits a validator set update for epoch `11` to _Governance_, using
  a quorum of signatures from the Namada chain
- The _Governance_ and _Bridge_ contracts now know the hashes of the validator
  sets for epochs `10` and `11`, and will accept messages signed by either of
  them. It will no longer accept messages signed by the validator set for epoch
  `9`.
- Namada progresses to epoch `11`, and the flow repeats

NB: the flow for when the bridge has just launched is similar, except the
contracts know the details of only one epoch's validator set - the launch
epoch's. E.g. if the bridge launches at epoch `10`, then initially the contracts
know the hash only for epoch `10` and not epochs `10` and `11`, until the first
validator set update has been submitted
