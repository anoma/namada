#!/bin/sh

set -e

trap 'cleanup' EXIT INT TERM QUIT

main() {
    cd "$(dirname "$0")"/..
    _tmp="$(mktemp -d)"

    cp -r genesis/localnet "${_tmp}/"

    # import validator key and addr into the wallet
    ./target/debug/namadaw \
        --pre-genesis \
        --base-dir "${_tmp}/localnet/src" \
        add \
        --unsafe-dont-encrypt \
        --alias validator-1-account-key \
        --value 00f1425456539dd53adbeda8c6d64b11c71c40c3d41fe17082a3dd89bc72cc26ae
    ./target/debug/namadaw \
        --pre-genesis \
        --base-dir "${_tmp}/localnet/src" \
        add \
        --unsafe-dont-encrypt \
        --alias validator-1 \
        --value tnam1qyq850fy0tdk8wkp40hhwu8a9wp2wn8stq3ldqrg

    # create validator txs and sign them
    ./target/debug/namadac \
        --pre-genesis \
        --base-dir "${_tmp}/localnet/src" \
        utils init-genesis-established-account \
        --aliases validator-1-account-key \
        --path "${_tmp}/unsigned.toml"
    ./target/debug/namadac \
        --pre-genesis \
        --base-dir "${_tmp}/localnet/src" \
        utils init-genesis-validator \
        --path "${_tmp}/unsigned.toml" \
        --alias validator-1 \
        --address tnam1qyq850fy0tdk8wkp40hhwu8a9wp2wn8stq3ldqrg \
        --net-address 127.0.0.1:42042 \
        --commission-rate 0.10 \
        --max-commission-rate-change 0.01 \
        --unsafe-dont-encrypt \
        --self-bond-amount 100000 \
        --email bing@bong.us
    ./target/debug/namadac \
        --pre-genesis \
        --base-dir "${_tmp}/localnet/src" \
        utils sign-genesis-txs \
        --path "${_tmp}/unsigned.toml" \
        --output "${_tmp}/signed.toml" \
        --alias validator-1
    cat "${_tmp}/signed.toml" >>"${_tmp}/localnet/transactions.toml"

    # generate localnet
    ./scripts/gen_localnet.py \
        --full-nodes '{"fullnode-0":12340}' \
        --templates "${_tmp}/localnet" \
        --validator-aliases '{"validator-0":"tnam1q9vhfdur7gadtwx4r223agpal0fvlqhywylf2mzx","validator-1":"tnam1qyq850fy0tdk8wkp40hhwu8a9wp2wn8stq3ldqrg"}' \
        --pre-genesis-path "${_tmp}/localnet/src/pre-genesis" \
        --edit '{"balances.toml":{"token":{"NAM":"insert_dict(it,tnam1qyq850fy0tdk8wkp40hhwu8a9wp2wn8stq3ldqrg=\"200000\",tnam1qr8l7l6rywucdarxg9q0zpggfe0jxddk6u09e8ez=\"1000000\")"}}}' \
        --eval \
        "$@"
}

cleanup() {
    rm -rf "$_tmp"
}

main "$@"
