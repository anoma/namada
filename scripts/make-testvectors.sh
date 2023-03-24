#!/usr/bin/env bash

# A script to generate some transaction test vectors. It must be executed at the
# root of the Namada repository. All transaction types except vote-proposal are
# tested. This is because vote-proposal needs to query RPC for delegation. This
# script assumes that the WASM scripts have already been built using
# `make build-wasm-scripts`.

NAMADA_DIR="$(pwd)"
export NAMADA_DEV=true
export NAMADA_TEST_VECTOR_PATH="$(pwd)/testvectors.json"

echo '{
    "content": {
        "title": "TheTitle",
        "authors": "test@test.com",
        "discussions-to": "www.github.com/anoma/aip/1",
        "created": "2022-03-10T08:54:37Z",
        "license": "MIT",
        "abstract": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
        "motivation": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
        "details": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
        "requires": "2"
    },
    "author": "atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw",
    "voting_start_epoch": 12,
    "voting_end_epoch": 24,
    "grace_epoch": 30,
    "proposal_code_path": "'"$NAMADA_DIR"'/wasm_for_tests/tx_no_op.wasm"
}
' > valid_proposal.json

cargo run --bin namadac -- utils init-network --genesis-path genesis/e2e-tests-single-node.toml --wasm-checksums-path wasm/checksums.json --chain-prefix local --unsafe-dont-encrypt --localhost --allow-duplicate-ip

# A node is started in order to force WASM scripts to be copied into chain data.
# The node can be killed once it is running.

cargo run --bin namada -- ledger

echo $'[' > $NAMADA_TEST_VECTOR_PATH

cargo run --bin namadac -- transfer --source bertha --target christel --token btc --amount 23 --unchecked --signing-key bertha --epoch 5

cargo run --bin namadac -- bond --validator bertha --amount 25 --unchecked --signing-key bertha --epoch 6

cargo run --bin namadac -- reveal-pk --public-key albert --epoch 7 --unchecked

cargo run --bin namadac -- update --code-path vp_user.wasm --address bertha --signing-key bertha --epoch 8 --unchecked

cargo run --bin namadac -- init-validator --source bertha --commission-rate 0.05 --max-commission-rate-change 0.01 --signing-key bertha --epoch 9 --unsafe-dont-encrypt --unchecked

cargo run --bin namadac -- unbond --validator christel --amount 5 --unchecked --signing-key christel --epoch 2

cargo run --bin namadac -- withdraw --validator albert --epoch 3 --unchecked --signing-key albert

cargo run --bin namadac -- init-account --source albert --public-key albert --signing-key albert --epoch 4 --unchecked

cargo run --bin namadac -- tx --code-path ../../../wasm_for_tests/tx_no_op.wasm --data-path README.md --signing-key albert --epoch 5 --unchecked

cargo run --bin namadac -- ibc-transfer --source bertha --receiver christel  --token btc --amount 24 --channel-id channel-141 --signing-key bertha --unchecked --epoch 1

cargo run --bin namadac -- init-proposal --data-path valid_proposal.json --epoch 2 --unchecked --signing-key bertha

rm valid_proposal.json

perl -0777 -i.original -pe 's/,\s*$//igs' testvectors.json

echo $'\n]' >> $NAMADA_TEST_VECTOR_PATH
