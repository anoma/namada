#!/usr/bin/env bash

# A script to generate some transaction test vectors. It must be executed at the
# root of the Namada repository. All transaction types except vote-proposal are
# tested. This is because vote-proposal needs to query RPC for delegation. This
# script assumes that the WASM scripts have already been built using
# `make build-wasm-scripts`. Run `./scripts/online_generator server` to start a
# server and then run `./scripts/online_generator client` to generate the test
# vectors.

NAMADA_DIR="$(pwd)"
export NAMADA_LEDGER_LOG_PATH="$(pwd)/testvectors.json"
export NAMADA_TX_LOG_PATH="$(pwd)/debugouts.txt"

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

    perl -0777 -i.original -pe 's/,\s*$//igs' testvectors.json

    echo $'\n]' >> $NAMADA_LEDGER_LOG_PATH
fi
