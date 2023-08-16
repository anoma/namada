#!/usr/bin/env bash

# A script to generate some transaction test vectors. It must be executed at the
# root of the Namada repository. All transaction types except vote-proposal are
# tested. This is because vote-proposal needs to query RPC for delegation. This
# script assumes that the WASM scripts have already been built using
# `make build-wasm-scripts`. Run `./scripts/online_generator server` to start a
# server and then run `./scripts/online_generator client` to generate the test
# vectors.

NAMADA_DIR="$(pwd)"
export NAMADA_LEDGER_LOG_PATH="$(pwd)/vectors.json"
export NAMADA_TX_LOG_PATH="$(pwd)/debugs.txt"

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
elif [ "$1" = "server" ]; then
    cp genesis/e2e-tests-single-node.toml genesis/test-vectors-single-node.toml
    
    sed -i 's/^epochs_per_year = 31_536_000$/epochs_per_year = 262_800/' genesis/test-vectors-single-node.toml
    
    NAMADA_GENESIS_FILE=$(cargo run --bin namadac -- utils init-network --genesis-path genesis/test-vectors-single-node.toml --wasm-checksums-path wasm/checksums.json --chain-prefix e2e-test --unsafe-dont-encrypt --localhost --allow-duplicate-ip | grep 'Genesis file generated at ' | sed 's/^Genesis file generated at //')
    
    rm genesis/test-vectors-single-node.toml

    NAMADA_BASE_DIR=${NAMADA_GENESIS_FILE%.toml}

    cp wasm/*.wasm $NAMADA_BASE_DIR/wasm/

    cp wasm/*.wasm $NAMADA_BASE_DIR/setup/validator-0/.namada/$(basename $NAMADA_BASE_DIR)/wasm/

    cp $NAMADA_BASE_DIR/setup/other/wallet.toml $NAMADA_BASE_DIR/wallet.toml

    cargo run --bin namadan -- --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada/ ledger
elif [ "$1" = "client" ]; then
    echo > $NAMADA_TX_LOG_PATH

    echo $'[' > $NAMADA_LEDGER_LOG_PATH

    ALBERT_ADDRESS=$(cargo run --bin namadaw -- address find --alias albert | sed 's/^Found address Established: //')

    echo '{
     "author":"'$ALBERT_ADDRESS'",
     "content":{
        "abstract":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
        "authors":"test@test.com",
        "created":"2022-03-10T08:54:37Z",
        "details":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
        "discussions-to":"www.github.com/anoma/aip/1",
        "license":"MIT",
        "motivation":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
        "requires":"2",
        "title":"TheTitle"
    },
    "grace_epoch":30,
    "type":{
        "Default":"'$NAMADA_DIR'/wasm_for_tests/tx_proposal_code.wasm"
    },
    "voting_end_epoch":24,
    "voting_start_epoch":12
}
' > proposal_submission_valid_proposal.json

    echo '{
  "content": {
    "abstract": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
    "authors": "test@test.com",
    "created": "2022-03-10T08:54:37Z",
    "details": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
    "discussions-to": "www.github.com/anoma/aip/1",
    "license": "MIT",
    "motivation": "Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
    "requires": "2",
    "title": "TheTitle"
  },
  "author": "'$ALBERT_ADDRESS'",
  "tally_epoch": 18,
  "signature": {
    "Ed25519": {
      "R_bytes": [
        113,
        196,
        231,
        134,
        101,
        191,
        75,
        17,
        245,
        19,
        50,
        231,
        183,
        80,
        162,
        38,
        108,
        72,
        72,
        2,
        116,
        112,
        121,
        33,
        197,
        67,
        64,
        116,
        21,
        250,
        196,
        121
      ],
      "s_bytes": [
        87,
        163,
        134,
        87,
        42,
        156,
        121,
        211,
        189,
        19,
        255,
        5,
        23,
        178,
        143,
        39,
        118,
        249,
        37,
        53,
        121,
        136,
        59,
        103,
        190,
        91,
        121,
        95,
        46,
        54,
        168,
        9
      ]
    }
  },
  "address": "'$ALBERT_ADDRESS'"
}
' > proposal_offline_proposal

    echo '{
     "author":"'$ALBERT_ADDRESS'",
     "content":{
        "abstract":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
        "authors":"test@test.com",
        "created":"2022-03-10T08:54:37Z",
        "details":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
        "discussions-to":"www.github.com/anoma/aip/1",
        "license":"MIT",
        "motivation":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
        "requires":"2",
        "title":"TheTitle"
    },
    "grace_epoch":18,
    "type":{
        "Default":null
    },
    "voting_end_epoch":9,
    "voting_start_epoch":3
}' > proposal_offline_valid_proposal.json

    echo '{
     "author":"'$ALBERT_ADDRESS'",
     "content":{
        "abstract":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
        "authors":"test@test.com",
        "created":"2022-03-10T08:54:37Z",
        "details":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
        "discussions-to":"www.github.com/anoma/aip/1",
        "license":"MIT",
        "motivation":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
        "requires":"2",
        "title":"TheTitle"
    },
    "grace_epoch":30,
    "type":"ETHBridge",
    "voting_end_epoch":24,
    "voting_start_epoch":12
}' > eth_governance_proposal_valid_proposal.json

    echo '{
     "author":"'$ALBERT_ADDRESS'",
     "content":{
        "abstract":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros. Nullam sed ex justo. Ut at placerat ipsum, sit amet rhoncus libero. Sed blandit non purus non suscipit. Phasellus sed quam nec augue bibendum bibendum ut vitae urna. Sed odio diam, ornare nec sapien eget, congue viverra enim.",
        "authors":"test@test.com",
        "created":"2022-03-10T08:54:37Z",
        "details":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices. Quisque viverra varius cursus. Praesent sed mauris gravida, pharetra turpis non, gravida eros.",
        "discussions-to":"www.github.com/anoma/aip/1",
        "license":"MIT",
        "motivation":"Ut convallis eleifend orci vel venenatis. Duis vulputate metus in lacus sollicitudin vestibulum. Suspendisse vel velit ac est consectetur feugiat nec ac urna. Ut faucibus ex nec dictum fermentum. Morbi aliquet purus at sollicitudin ultrices.",
        "requires":"2",
        "title":"TheTitle"
    },
    "grace_epoch":30,
    "type":"PGFCouncil",
    "voting_end_epoch":24,
    "voting_start_epoch":12
}' > pgf_governance_proposal_valid_proposal.json

    # proposal_submission
    
    cargo run --bin namadac --features std -- bond --validator validator-0 --source Bertha --amount 900 --gas-amount 0 --gas-limit 0 --gas-token NAM --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Bertha --commission-rate 0.02 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    PROPOSAL_ID_0=$(cargo run --bin namadac --features std -- init-proposal --force --data-path proposal_submission_valid_proposal.json --node 127.0.0.1:27657 | grep -o -P '(?<=/proposal/).*(?=/author)')

    cargo run --bin namadac --features std -- --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --address validator-0 --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote nay --address Bertha --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --address Albert --node 127.0.0.1:27657

    # proposal_offline

    cargo run --bin namadac --features std -- bond --validator validator-0 --source Albert --amount 900 --gas-amount 0 --gas-limit 0 --gas-token NAM --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Albert --commission-rate 0.05 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- init-proposal --force --data-path proposal_offline_valid_proposal.json --offline --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --data-path proposal_offline_proposal --vote yay --address Albert --offline --node 127.0.0.1:27657

    # eth_governance_proposal

    cargo run --bin namadac --features std -- bond --validator validator-0 --source Bertha --amount 900 --gas-amount 0 --gas-limit 0 --gas-token NAM --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Bertha --commission-rate 0.07 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    PROPOSAL_ID_0=$(cargo run --bin namadac --features std -- init-proposal --force --data-path eth_governance_proposal_valid_proposal.json --ledger-address 127.0.0.1:27657 | grep -o -P '(?<=/proposal/).*(?=/author)')

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id 0 --vote yay --eth '011586062748ba53bc53155e817ec1ea708de75878dcb9a5713bf6986d87fe14e7 fd34672ab5' --address Bertha --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --eth '011586062748ba53bc53155e817ec1ea708de75878dcb9a5713bf6986d87fe14e7 fd34672ab5' --address validator-0 --ledger-address 127.0.0.1:27657

    # pgf_governance_proposal

    cargo run --bin namadac --features std -- bond --validator validator-0 --source Bertha --amount 900 --gas-amount 0 --gas-limit 0 --gas-token NAM --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Bertha --commission-rate 0.09 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    PROPOSAL_ID_0=$(cargo run --bin namadac --features std -- init-proposal --force --data-path pgf_governance_proposal_valid_proposal.json --ledger-address 127.0.0.1:27657 | grep -o -P '(?<=/proposal/).*(?=/author)')

    PROPOSAL_ID_1=$(cargo run --bin namadac --features std -- init-proposal --force --data-path pgf_governance_proposal_valid_proposal.json --ledger-address 127.0.0.1:27657 | grep -o -P '(?<=/proposal/).*(?=/author)')

    cargo run --bin namadac --features std -- --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --pgf "$ALBERT_ADDRESS 1000" --address validator-0 --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --pgf "$ALBERT_ADDRESS 900" --address Bertha --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_1 --vote yay --pgf "$ALBERT_ADDRESS 900" --address Bertha --ledger-address 127.0.0.1:27657

    # non-proposal tests
    
    cargo run --bin namadac --features std -- transfer --source bertha --target christel --token btc --amount 23 --force --signing-keys bertha-key --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- bond --validator bertha --amount 25 --signing-keys bertha-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Bertha --commission-rate 0.11 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- reveal-pk --public-key albert-key --gas-payer albert-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- update-account --code-path vp_user.wasm --address bertha --signing-keys bertha-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- init-validator --alias bertha-validator --account-keys bertha --commission-rate 0.05 --max-commission-rate-change 0.01 --signing-keys bertha-key --unsafe-dont-encrypt --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- unbond --validator christel --amount 5 --signing-keys christel-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- withdraw --validator albert --signing-keys albert-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- init-account --alias albert-account --public-keys albert-key --signing-keys albert-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- tx --code-path $NAMADA_DIR/wasm_for_tests/tx_no_op.wasm --data-path README.md --signing-keys albert-key --owner albert --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- ibc-transfer --source bertha --receiver christel  --token btc --amount 24 --channel-id channel-141 --signing-keys bertha-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadaw -- masp add --alias a_spending_key --value xsktest1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu69au6gn3su5ewneas486hdccyayx32hxvt64p3d0hfuprpgcgv2q9gdx3jvxrn02f0nnp3jtdd6f5vwscfuyum083cvfv4jun75ak5sdgrm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcvedhsv --unsafe-dont-encrypt
    
    cargo run --bin namadaw -- masp add --alias b_spending_key --value xsktest1qqqqqqqqqqqqqqpagte43rsza46v55dlz8cffahv0fnr6eqacvnrkyuf9lmndgal7c2k4r7f7zu2yr5rjwr374unjjeuzrh6mquzy6grfdcnnu5clzaq2llqhr70a8yyx0p62aajqvrqjxrht3myuyypsvm725uyt5vm0fqzrzuuedtf6fala4r4nnazm9y9hq5yu6pq24arjskmpv4mdgfn3spffxxv8ugvym36kmnj45jcvvmm227vqjm5fq8882yhjsq97p7xrwqqd82s0 --unsafe-dont-encrypt

    cargo run --bin namadaw -- masp add --alias ab_payment_address --value patest1dxj5kfjvm27rk5wg8ym0mjrhthz6whagdfj9krqfvyszffh4n0mx9f7cauvz6tr43vp22qgsefr

    cargo run --bin namadaw -- masp add --alias aa_payment_address --value patest1a8sfz9c6axdhn925e5qrgzz86msq6yj4uhmxayynucea7gssepk89dgqkx00srfkn4m6kt9jpau
    
    cargo run --bin namadaw -- masp add --alias bb_payment_address --value patest1vqe0vyxh6wmhahwa52gthgd6edgqxfmgyv8e94jtwn55mdvpvylcyqnp59595272qrz3zxn0ysg

    cargo run --bin namadac --features std -- transfer --source albert --target aa_payment_address --token btc --amount 20 --force --ledger-address 127.0.0.1:27657
    
    cargo run --bin namadac --features std -- transfer --source a_spending_key --target ab_payment_address --token btc --amount 7 --force --ledger-address 127.0.0.1:27657
    
    until  cargo run --bin namadac -- epoch --ledger-address 127.0.0.1:27657 | grep -m1 "Last committed epoch: 2" ; do sleep 10 ; done;
    
    cargo run --bin namadac --features std -- transfer --source a_spending_key --target bb_payment_address --token btc --amount 7 --force --ledger-address 127.0.0.1:27657
    
    cargo run --bin namadac --features std -- transfer --source a_spending_key --target bb_payment_address --token btc --amount 6 --force --ledger-address 127.0.0.1:27657
    
    cargo run --bin namadac --features std -- transfer --source b_spending_key --target bb_payment_address --token btc --amount 6 --force --ledger-address 127.0.0.1:27657

    rm proposal_submission_valid_proposal.json

    rm proposal_offline_proposal

    rm proposal_offline_valid_proposal.json

    rm eth_governance_proposal_valid_proposal.json

    rm pgf_governance_proposal_valid_proposal.json

    perl -0777 -i.original -pe 's/,\s*$//igs' $NAMADA_LEDGER_LOG_PATH

    echo $'\n]' >> $NAMADA_LEDGER_LOG_PATH
fi
