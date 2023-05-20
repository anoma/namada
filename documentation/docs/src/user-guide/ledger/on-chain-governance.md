# On-chain proposals

## Create a proposal

Assuming you have an account with at least 500 NAM token (in this example we are going to use `my-new-acc`), lets get the corresponding address

```shell
namada wallet address find --alias `my-new-acc`
```

Now, we need to create a json file `proposal.json` holding the content of our proposal. Copy the below text into a json file.

```json
{
    "content": {
        "title": "One Small Step for Namada, One Giant Leap for Memekind",
        "authors": "email@proton.me",
        "discussions-to": "forum.namada.net/t/namada-proposal/1",
        "created": "2069-04-20T00:04:44Z",
        "license": "MIT",
        "abstract": "We present a proposal that will send our community to the moon. This proposal outlines all training necessary to accomplish this goal. All memers are welcome to join.",
        "motivation": "When you think about it, the moon isn't actually that far away.The moon is only 384,400 km. We have not yet brought Namada to the moon, so it is only natural to use 101 as the prime number for our modular arithmetic operations. 384,400 (mod 101) = 95. 95 km is a distance that can be easily covered by a single person in a single day. Namada was produced by more than 100 people. So 95/100 = 0, rounded to the nearest integer. This means that Namada can reach the moon in no time.",
        "details": "Bringing Namada to the moon in no time is easily achievable. We just need to pass this governance proposal and set the plan in action",
        "requires": "420"
    },
    "author": "bengt",
    "voting_start_epoch": 3,
    "voting_end_epoch": 6,
    "grace_epoch": 12,
    "type": {
        "Default":null
        }
}
```

In the content field, most of the fields are self-explanatory. The `requires` field references a proposal id that must be passed before this proposal can be executed. The `created` field must be in the format `YYYY-MM-DDTHH:MM:SSZ`.

You should change the value of:

- `Author` field with the address of `my-new-acc`.
- `voting_start_epoch` with a future epoch (must be a multiple of 3) for which you want the voting to begin
- `voting_end_epoch` with an epoch greater than `voting_start_epoch`, a multiple of 3, and by which no further votes will be accepted
- `grace_epoch` with an epoch greater than `voting_end_epoch` + 6, in which the proposal, if passed, will come into effect
- `type` with the correct type for your proposal, which can be one of the followings:
    - `"type": {"Default":null}` for a default proposal without wasm code
    - `"type": {"Default":"$PATH_TO_WASM_CODE"}` for a default proposal with an associated wasm code
    - `"type": "PGFCouncil"` to initiate a proposal for a new council
    - `"type": "ETHBridge"` for an ethereum bridge related proposal


As soon as your `proposal.json` file is ready, you can submit the proposal with (making sure to be in the same directory as the `proposal.json` file):

```shell
namada client init-proposal --data-path proposal.json 
```

The transaction should have been accepted. You can query all the proposals with:

```shell
namada client query-proposal
```

or a single proposal with

```shell
namada client query-proposal --proposal-id 0
```

where `0` is the proposal id.

## Vote a proposal

Only validators and delegators can vote. Assuming you have a validator or a delegator account (in this example we are going to use `validator`), you can send a vote with the following command:

```shell
namada client vote-proposal \
    --proposal-id 0 \
    --vote yay \
    --signer validator
```

where `--vote` can be either `yay` or `nay`. An optional `memo` field can be attached to the vote for pgf and eth bridge proposals.

## Check the result

As soon as the ledger reaches the epoch defined in the json as `voting_end_epoch`, no votes will be accepted. The code definied in `proposal_code` json field will be executed at the beginning of `grace_epoch` epoch. You can use the following commands to check the status of a proposal:

```shell
namada client query-proposal --proposal-id 0
```

or to just check the result:

```shell
namada client query-proposal-result --proposal-id 0
```
