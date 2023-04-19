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

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
elif [ "$1" = "server" ]; then
    cp genesis/e2e-tests-single-node.toml genesis/test-vectors-single-node.toml
    
    sed -i 's/^epochs_per_year = 31_536_000$/epochs_per_year = 262_800/' genesis/test-vectors-single-node.toml
    
    NAMADA_GENESIS_FILE=$(cargo run --bin namadac -- --mode validator utils init-network --genesis-path genesis/test-vectors-single-node.toml --wasm-checksums-path wasm/checksums.json --chain-prefix e2e-test --unsafe-dont-encrypt --localhost --allow-duplicate-ip | grep 'Genesis file generated at ' | sed 's/^Genesis file generated at //')
    
    rm genesis/test-vectors-single-node.toml

    NAMADA_BASE_DIR=${NAMADA_GENESIS_FILE%.toml}

    cp wasm/*.wasm $NAMADA_BASE_DIR/wasm/

    cp wasm/*.wasm $NAMADA_BASE_DIR/setup/validator-0/$NAMADA_BASE_DIR/wasm/

    cp $NAMADA_BASE_DIR/setup/other/wallet.toml $NAMADA_BASE_DIR/wallet.toml

    cargo run --bin namada -- --mode validator --base-dir $NAMADA_BASE_DIR/setup/validator-0/.namada/ ledger
elif [ "$1" = "client" ]; then
    echo > $NAMADA_TX_LOG_PATH

    echo $'[' > $NAMADA_LEDGER_LOG_PATH
    
    cargo run --bin namadac -- transfer --source bertha --target christel --token btc --amount 23 --unchecked --signing-key bertha-key --epoch 5

    cargo run --bin namadac -- bond --validator bertha --amount 25 --unchecked --signing-key bertha-key --epoch 6

    cargo run --bin namadac -- reveal-pk --public-key albert-key --epoch 7 --unchecked

    cargo run --bin namadac -- update --code-path vp_user.wasm --address bertha --signing-key bertha-key --epoch 8 --unchecked

    cargo run --bin namadac -- init-validator --source bertha --commission-rate 0.05 --max-commission-rate-change 0.01 --signing-key bertha-key --epoch 9 --unsafe-dont-encrypt --unchecked

    cargo run --bin namadac -- unbond --validator christel --amount 5 --unchecked --signing-key christel-key --epoch 2

    cargo run --bin namadac -- withdraw --validator albert --epoch 3 --unchecked --signing-key albert-key

    cargo run --bin namadac -- init-account --source albert --public-key albert-key --signing-key albert-key --epoch 4 --unchecked

    cargo run --bin namadac -- tx --code-path ../../../wasm_for_tests/tx_no_op.wasm --data-path README.md --signing-key albert-key --epoch 5 --unchecked

    cargo run --bin namadac -- ibc-transfer --source bertha --receiver christel  --token btc --amount 24 --channel-id channel-141 --signing-key bertha-key --unchecked --epoch 1

    cargo run --bin namadac -- init-proposal --data-path valid_proposal.json --epoch 2 --unchecked --signing-key bertha-key

    cargo run --bin namadaw -- masp add --alias a_spending_key --value xsktest1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu69au6gn3su5ewneas486hdccyayx32hxvt64p3d0hfuprpgcgv2q9gdx3jvxrn02f0nnp3jtdd6f5vwscfuyum083cvfv4jun75ak5sdgrm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcvedhsv --unsafe-dont-encrypt
    
    cargo run --bin namadaw -- masp add --alias b_spending_key --value xsktest1qqqqqqqqqqqqqqpagte43rsza46v55dlz8cffahv0fnr6eqacvnrkyuf9lmndgal7c2k4r7f7zu2yr5rjwr374unjjeuzrh6mquzy6grfdcnnu5clzaq2llqhr70a8yyx0p62aajqvrqjxrht3myuyypsvm725uyt5vm0fqzrzuuedtf6fala4r4nnazm9y9hq5yu6pq24arjskmpv4mdgfn3spffxxv8ugvym36kmnj45jcvvmm227vqjm5fq8882yhjsq97p7xrwqqd82s0 --unsafe-dont-encrypt

    cargo run --bin namadaw -- masp add --alias ab_payment_address --value patest1dxj5kfjvm27rk5wg8ym0mjrhthz6whagdfj9krqfvyszffh4n0mx9f7cauvz6tr43vp22qgsefr

    cargo run --bin namadaw -- masp add --alias aa_payment_address --value patest1a8sfz9c6axdhn925e5qrgzz86msq6yj4uhmxayynucea7gssepk89dgqkx00srfkn4m6kt9jpau
    
    cargo run --bin namadaw -- masp add --alias bb_payment_address --value patest1vqe0vyxh6wmhahwa52gthgd6edgqxfmgyv8e94jtwn55mdvpvylcyqnp59595272qrz3zxn0ysg

    cargo run --bin namadac -- --mode full transfer --source albert --target aa_payment_address --token btc --amount 20 --ledger-address 127.0.0.1:27657
    
    cargo run --bin namadac -- --mode full transfer --source a_spending_key --target ab_payment_address --token btc --amount 7 --ledger-address 127.0.0.1:27657
    
    until  cargo run --bin namadac -- --mode full epoch --ledger-address 127.0.0.1:27657 | grep -m1 "Last committed epoch: 2" ; do sleep 10 ; done;
    
    cargo run --bin namadac -- --mode full transfer --source a_spending_key --target bb_payment_address --token btc --amount 7 --ledger-address 127.0.0.1:27657
    
    cargo run --bin namadac -- --mode full transfer --source a_spending_key --target bb_payment_address --token btc --amount 6 --ledger-address 127.0.0.1:27657
    
    cargo run --bin namadac -- --mode full transfer --source b_spending_key --target bb_payment_address --token btc --amount 6 --ledger-address 127.0.0.1:27657

    perl -0777 -i.original -pe 's/,\s*$//igs' $NAMADA_LEDGER_LOG_PATH

    echo $'\n]' >> $NAMADA_LEDGER_LOG_PATH
fi

rm valid_proposal.json
