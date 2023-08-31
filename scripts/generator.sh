#!/usr/bin/env bash

# A script to generate some transaction test vectors. It must be executed at the
# root of the Namada repository. All transaction types except vote-proposal are
# tested. This is because vote-proposal needs to query RPC for delegation. This
# script assumes that the WASM scripts have already been built using
# `make build-wasm-scripts`. Run `./scripts/online_generator server` to start a
# server and then run `./scripts/online_generator client` to generate the test
# vectors.

NAMADA_DIR="$(pwd)"
NAMADA_BASE_DIR_FILE="$(pwd)/namada_base_dir"
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
    echo $NAMADA_BASE_DIR > $NAMADA_BASE_DIR_FILE

    cp wasm/*.wasm $NAMADA_BASE_DIR/wasm/

    cp wasm/*.wasm $NAMADA_BASE_DIR/setup/validator-0/.namada/$(basename $NAMADA_BASE_DIR)/wasm/

    cp $NAMADA_BASE_DIR/setup/other/wallet.toml $NAMADA_BASE_DIR/wallet.toml

    cargo run --bin namadan -- --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada/ ledger
elif [ "$1" = "client" ]; then
    if test -f "$NAMADA_BASE_DIR_FILE"; then
        NAMADA_BASE_DIR="$(cat $NAMADA_BASE_DIR_FILE)" 
    fi

    echo > $NAMADA_TX_LOG_PATH

    echo $'[' > $NAMADA_LEDGER_LOG_PATH

    ALBERT_ADDRESS=$(cargo run --bin namadaw -- address find --alias albert | sed 's/^Found address Established: //')

    echo '{
    "proposal": {
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
        "voting_end_epoch":24,
        "voting_start_epoch":12
    }
    }' > proposal_default.json

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
    "tally_epoch":1
    }' > proposal_offline.json

    echo '{
    "proposal": {
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
        "voting_end_epoch":24,
        "voting_start_epoch":12
    },
    "data": [{"action":"Add", "address": "'$ALBERT_ADDRESS'"}]
    }' > proposal_pgf_steward_add.json

    cargo run --bin namadac --features std -- transfer --source bertha --target christel --token nam --amount 115792089237316195423570985008687907853269984665640564039457584007913129.639935 --force --ledger-address 127.0.0.1:27657

    # proposal_default

    cargo run --bin namadac --features std -- bond --validator validator-0 --source Bertha --amount 900 --gas-amount 0 --gas-limit 0 --gas-token NAM --node 127.0.0.1:27657
    
    cargo run --bin namadac --features std -- unjail-validator --validator Bertha --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Bertha --commission-rate 0.02 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    PROPOSAL_ID_0=$(cargo run --bin namadac --features std -- init-proposal --force --data-path proposal_default.json --node 127.0.0.1:27657 | grep -o -P '(?<=/proposal/).*(?=/author)')

    cargo run --bin namadac --features std -- --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --address validator-0 --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote nay --address Bertha --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --address Albert --node 127.0.0.1:27657

    # proposal_offline

    cargo run --bin namadac --features std -- bond --validator validator-0 --source Albert --amount 900 --gas-amount 0 --gas-limit 0 --gas-token NAM --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Albert --commission-rate 0.05 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    PROPOSAL_OFFLINE_SIGNED=$(cargo run --bin namadac --features std -- init-proposal --force --data-path proposal_offline.json --signing-keys albert-key --offline --node 127.0.0.1:27657 | grep -o -P '(?<=Proposal serialized to:\s).*')

    cargo run --bin namadac --features std -- vote-proposal --data-path $PROPOSAL_OFFLINE_SIGNED --vote yay --address Albert --offline --node 127.0.0.1:27657

    # pgf_governance_proposal

    cargo run --bin namadac --features std -- bond --validator validator-0 --source Bertha --amount 900 --gas-amount 0 --gas-limit 0 --gas-token NAM --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Bertha --commission-rate 0.09 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    PROPOSAL_ID_0=$(cargo run --bin namadac --features std -- init-proposal --pgf-stewards --force --data-path proposal_pgf_steward_add.json --ledger-address 127.0.0.1:27657 | grep -o -P '(?<=/proposal/).*(?=/author)')

    PROPOSAL_ID_1=$(cargo run --bin namadac --features std -- init-proposal --pgf-stewards --force --data-path proposal_pgf_steward_add.json --ledger-address 127.0.0.1:27657 | grep -o -P '(?<=/proposal/).*(?=/author)')

    cargo run --bin namadac --features std -- --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --address validator-0 --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_0 --vote yay --address Bertha --signing-keys bertha-key --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- vote-proposal --force --proposal-id $PROPOSAL_ID_1 --vote yay --address Bertha --signing-keys bertha-key --ledger-address 127.0.0.1:27657

    # non-proposal tests
    
    cargo run --bin namadac --features std -- transfer --source bertha --target christel --token btc --amount 23 --force --signing-keys bertha-key --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- bond --validator bertha --amount 25 --signing-keys bertha-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- change-commission-rate --validator Bertha --commission-rate 0.11 --gas-amount 0 --gas-limit 0 --gas-token NAM --force --node 127.0.0.1:27657

    cargo run --bin namadac --features std -- reveal-pk --public-key albert-key --gas-payer albert-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- update-account --code-path vp_user.wasm --address bertha --signing-keys bertha-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- init-validator --alias bertha-validator --account-keys bertha-key --commission-rate 0.05 --max-commission-rate-change 0.01 --signing-keys bertha-key --unsafe-dont-encrypt --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- init-validator --alias validator-mult --account-keys albert-key,bertha-key --commission-rate 0.05 --max-commission-rate-change 0.01 --signing-keys albert-key,bertha-key --threshold 2 --unsafe-dont-encrypt --force --ledger-address 127.0.0.1:27657

    # TODO works but panics
    cargo run --bin namadac --features std -- unbond --validator christel --amount 5 --signing-keys christel-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- withdraw --validator albert --signing-keys albert-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- init-account --alias albert-account --public-keys albert-key --signing-keys albert-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- ibc-transfer --source bertha --receiver christel  --token btc --amount 24 --channel-id channel-141 --signing-keys bertha-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- ibc-transfer --source albert --receiver bertha  --token nam --amount 100000 --channel-id channel-0 --port-id transfer --signing-keys albert-key --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadac --features std -- ibc-transfer --source albert --receiver bertha  --token nam --amount 100000 --channel-id channel-0 --port-id transfer --signing-keys albert-key --timeout-sec-offset 5 --force --ledger-address 127.0.0.1:27657

    cargo run --bin namadaw -- masp add --alias a_spending_key --value xsktest1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu69au6gn3su5ewneas486hdccyayx32hxvt64p3d0hfuprpgcgv2q9gdx3jvxrn02f0nnp3jtdd6f5vwscfuyum083cvfv4jun75ak5sdgrm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcvedhsv --unsafe-dont-encrypt
    
    cargo run --bin namadaw -- masp add --alias b_spending_key --value xsktest1qqqqqqqqqqqqqqpagte43rsza46v55dlz8cffahv0fnr6eqacvnrkyuf9lmndgal7c2k4r7f7zu2yr5rjwr374unjjeuzrh6mquzy6grfdcnnu5clzaq2llqhr70a8yyx0p62aajqvrqjxrht3myuyypsvm725uyt5vm0fqzrzuuedtf6fala4r4nnazm9y9hq5yu6pq24arjskmpv4mdgfn3spffxxv8ugvym36kmnj45jcvvmm227vqjm5fq8882yhjsq97p7xrwqqd82s0 --unsafe-dont-encrypt

    cargo run --bin namadaw -- masp add --alias ab_payment_address --value patest1dxj5kfjvm27rk5wg8ym0mjrhthz6whagdfj9krqfvyszffh4n0mx9f7cauvz6tr43vp22qgsefr

    cargo run --bin namadaw -- masp add --alias aa_payment_address --value patest1a8sfz9c6axdhn925e5qrgzz86msq6yj4uhmxayynucea7gssepk89dgqkx00srfkn4m6kt9jpau
    
    cargo run --bin namadaw -- masp add --alias bb_payment_address --value patest1vqe0vyxh6wmhahwa52gthgd6edgqxfmgyv8e94jtwn55mdvpvylcyqnp59595272qrz3zxn0ysg

    # TODO vector produced only when epoch boundaries not straddled
    cargo run --bin namadac --features std -- transfer --source albert --target aa_payment_address --token btc --amount 20 --force --ledger-address 127.0.0.1:27657
    
    # TODO vector produced only when epoch boundaries not straddled
    cargo run --bin namadac --features std -- transfer --source a_spending_key --target ab_payment_address --token btc --amount 7 --force --ledger-address 127.0.0.1:27657
    
    # TODO fragile
    until cargo run --bin namadac -- epoch --ledger-address 127.0.0.1:27657 | grep -m1 "Last committed epoch: 2" ; do sleep 10 ; done;
    
    # TODO vector produced only when epoch boundaries not straddled
    cargo run --bin namadac --features std -- transfer --source a_spending_key --target bb_payment_address --token btc --amount 7 --force --ledger-address 127.0.0.1:27657
    
    # TODO vector produced only when epoch boundaries not straddled
    cargo run --bin namadac --features std -- transfer --source a_spending_key --target bb_payment_address --token btc --amount 6 --force --ledger-address 127.0.0.1:27657
    
    # TODO vector produced only when epoch boundaries not straddled
    cargo run --bin namadac --features std -- transfer --source b_spending_key --target bb_payment_address --token btc --amount 6 --force --ledger-address 127.0.0.1:27657

    rm -f proposal_default.json

    rm -f proposal_offline.json

    rm -f proposal_pgf_steward_add.json

    perl -0777 -i.original -pe 's/,\s*$//igs' $NAMADA_LEDGER_LOG_PATH

    echo $'\n]' >> $NAMADA_LEDGER_LOG_PATH
fi
