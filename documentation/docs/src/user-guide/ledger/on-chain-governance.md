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
        "title": "Proposal title",
        "authors": "email@proposal.n",
        "discussions-to": "www.github.com/anoma/aip/1",
        "created": "2022-03-10T08:54:37Z",
        "license": "MIT",
        "abstract": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
        "motivation": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
        "details": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
        "requires": "2"
    },
    "author": "TODO",
    "voting_start_epoch": 3,
    "voting_end_epoch": 6,
    "grace_epoch": 12,
    "proposal_code_path": "./wasm_for_tests/tx_no_op.wasm"
}
```

You should change the value of:

- `Author` field with the address of `my-new-acc`.
- `voting_start_epoch` with a future epoch (must be a multiple of 3) for which you want the voting to begin
- `voting_end_epoch` with an epoch greater than `voting_start_epoch`, a multiple of 3, and by which no further votes will be accepted
- `grace_epoch` with an epoch greater than `voting_end_epoch` + 6, in which the proposal, if passed, will come into effect
- `proposal_code_path` with the absolute path of the wasm file to execute (or remove the field completely)

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

where `--vote` can be either `yay` or `nay`.

## Check the result

As soon as the ledger reaches the epoch defined in the json as `voting_end_epoch`, no votes will be accepted. The code definied in `proposal_code` json field will be executed at the beginning of `grace_epoch` epoch. You can use the following commands to check the status of a proposal:

```shell
namada client query-proposal --proposal-id 0
```

or to just check the result:

```shell
namada client query-proposal-result --proposal-id 0
```
