#!/bin/sh
#
# Script for initializing a Namada chain for local development and joining it.
# Note that this script trashes any existing local chain directories!
#
# ## Prerequisites
# - Python 3
# - toml Python pip library <https://pypi.org/project/toml/> (this is the
#   `python3-toml` package on Ubuntu distributions)
#
# ## How to run
# This script should be run from the root of a Namada source code repo
# (https://github.com/anoma/namada). *.wasm files must already have been built
# and be present under the `wasm/` directory of the Namada repo. This can be
# achieved by running `make build wasm-scripts`. 

# The shell script takes two required arguments (and one optional argument): 
# The first argument is the path to 
# a network config toml compatible with the version of Namada being used.
# You can find example network config tomls in the `templates/` directory 
# of the anoma-network-configs repo (https://github.com/heliaxdev/anoma-network-configs)` 
# The second argument is the path to the directory containing the Namada binaries
# The third OPTIONAL argument is the BASE_DIR of the chain. This will depend on your setup.
# 
# Example command:
# ```shell
# ./scripts/build_network.sh anoma-network-configs/templates/devnet-0.17.toml ./target/debug
# ````
#
# Once the script is finished, it should be possible to straight away start
# running a ledger node e.g. the command assuming binaries have been built is:
#
# ```shell
# target/debug/namadan ledger run
# ````

# After running the ledger, you can run the following command to kill an underlying process
# ```shell
# pkill -f ".hack/chains"
# ```
# and also delete the chain data by running
# ```shell
# rm -r .hack/chains
# ```

set +x
# set -eoux pipefail

show_help() {
    echo "Usage: script.sh <namada_dir>, OPTIONAL:<base_dir>, OPTIONAL:<genesis_file>"
    echo ""
    echo "Arguments:"
    echo "  namada_dir - The path to the directory containing the Namada binaries"
    echo "  base_dir - The path to the base directory (BASE_DIR), which is the directory where the chain's information will be stored. If the default base dir has not been changed, this does not need to be provided."
    echo "  genesis_file - The path to the genesis file. Otherwise, it will default to the genesis file in the genesis/e2e-tests-single-node.toml."
    echo "  The script should be smart enough to recognise if the second argument is a base dir or a genesis file, so order of last two arguments does not matter."
    echo ""
}

check_toml_file() {
    toml_file="$NETWORK_CONFIG_PATH"  # Get the file path from the first argument
    section_prefix="validator.validator"
    # Search for the section name in the TOML file
    section_count=$(awk -F'[][]' -v prefix="$section_prefix" '/^\[.*\]$/ && $2 ~ "^" prefix { count++ } END { print count }' "$toml_file")
    if [ ! "$(expr "$section_count" : '^[0-9]*$')" -eq 0 ]; then
        echo "At least one validator ($section_count, in fact) has been found in the toml file. Please delete all occurrences of the section '[$section_prefix]' in the TOML file and try again."
        exit 1
    fi
}



check_wasm_files() {
    wasm_files=$(find wasm -type f -name "*.wasm")

    count=$(echo "$wasm_files" | wc -l)

    if [ ! "$count" -ge 5 ]; then
        echo "You must run make build-wasm-scripts in the namada directory before running this script."
        exit 1
    fi
}
cleanup() {
    # Kill the Python process
    pkill -f ".hack/chains"
    rm -r .hack/chains
    rm -f local.*.tar.gz
}
validate_arguments() {
    # The script expects 2 arguments:
    # 1. The path to the directory containing the Namada binaries
    # 2. The BASE_DIR of the chain
    
    if [ "$#" -gt 3 ] || [ "$#" -lt 1 ]; then
        echo "Error: Invalid number of arguments. Expected 1 or 2 or 3 arguments."
        echo "See the help page by running --help for more information."
        exit 1
    fi

    # Get absolute path of where the script is being run from
    CURRENT_DIR="$(pwd)"
    # Get the absolute directory of where the script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
    NETWORK_CONFIG_PATH="$SCRIPT_DIR/../genesis/e2e-tests-single-node.toml"
    NAMADA_BIN_DIR="$1"

    if [ "$#" -eq 1 ]; then
        BASE_DIR="$($NAMADA_BIN_DIR/namadac utils default-base-dir)"
        echo "Using default BASE_DIR: $BASE_DIR"
    elif [ "$#" -eq 2 ]; then
        # Check if the second argument is a directory or a file
        if [ -f "$2" ]; then
            NETWORK_CONFIG_PATH="$(readlink -f "$CURRENT_DIR/$2")"
        else 
            BASE_DIR="$2"
        fi
    else
        if [ -f "$2" ]; then
            NETWORK_CONFIG_PATH="$(readlink -f "$CURRENT_DIR/$2")"
            BASE_DIR="$3"
        else 
            BASE_DIR="$2"
            NETWORK_CONFIG_PATH="$(readlink -f "$CURRENT_DIR/$3")"
        fi
    fi

    if [ ! -d "$CURRENT_DIR/wasm" ]; then
        echo "Error: Directory 'wasm' does not exist in the current directory."
        exit 1
    fi

    # The first argument should be a path to a network config toml
    if [ ! -f "$NETWORK_CONFIG_PATH" ]; then
        echo "Error: Invalid network config path. Expected a path to a network config toml, yet found no file in the location."
        echo "Check so that there exists a file in the location: $NETWORK_CONFIG_PATH"
        exit 1
    fi
    file="$NETWORK_CONFIG_PATH"  # Get the file path from the first argument
    extension="${file##*.}"
    if [ "$extension" != "toml" ]; then
        echo "Error: The first argument provided is not a .toml file."
        exit 1
    fi

    cp "$NETWORK_CONFIG_PATH" "$SCRIPT_DIR/utils/network-config.toml"
    NETWORK_CONFIG_PATH="$SCRIPT_DIR/utils/network-config.toml"

    # Delete the section [validator.validator] from the network config toml
    python3 $SCRIPT_DIR/utils/clean_config.py "$NETWORK_CONFIG_PATH"

    check_toml_file "$NETWORK_CONFIG_PATH"

    local directory="$NAMADA_BIN_DIR"

    if [ ! -d "$directory" ]; then
        echo "Error: Invalid directory. The specified directory does not exist."
        exit 1
    fi

    local namadac_path="$directory/namadac"

    if [ ! -x "$namadac_path" ]; then
        echo "Error: Missing executable 'namadac' in the specified directory."
        exit 1
    fi

    check_wasm_files
}

package() {

    # Clean up any existing chain data
    rm -rf "$BASE_DIR" || true
    git checkout --ours -- wasm/checksums.json
    rm -f nohup.out || true

    mkdir -p "$BASE_DIR"

    CHAIN_DIR='.hack/chains'
    mkdir -p $CHAIN_DIR

    ALIAS='validator-local-dev'

    $NAMADA_BIN_DIR/namadac --base-dir "$BASE_DIR" utils init-genesis-validator \
        --alias $ALIAS \
        --net-address 127.0.0.1:26656 \
        --commission-rate 0.01 \
        --max-commission-rate-change 0.05 \
        --unsafe-dont-encrypt

    # get the directory of this script
    SCRIPT_DIR="$(dirname $0)"
    NAMADA_NETWORK_CONFIG_PATH="${CHAIN_DIR}/network-config-processed.toml"
    python3 $SCRIPT_DIR/utils/add_validator_shard.py "$BASE_DIR"/pre-genesis/$ALIAS/validator.toml $NETWORK_CONFIG_PATH >$NAMADA_NETWORK_CONFIG_PATH

    python3 wasm/checksums.py

    NAMADA_CHAIN_PREFIX='local'

    $NAMADA_BIN_DIR/namadac --base-dir "$BASE_DIR" utils init-network \
        --chain-prefix "$NAMADA_CHAIN_PREFIX" \
        --genesis-path "$NAMADA_NETWORK_CONFIG_PATH" \
        --wasm-checksums-path wasm/checksums.json \
        --unsafe-dont-encrypt

    basename *.tar.gz .tar.gz >${CHAIN_DIR}/chain-id
    NAMADA_CHAIN_ID="$(cat ${CHAIN_DIR}/chain-id)"

    # We now need the keys of the faucet
    cp "$BASE_DIR/${NAMADA_CHAIN_ID}/setup/other/wallet.toml" "$BASE_DIR/wallet-temp.toml"

    rm -rf "$BASE_DIR/${NAMADA_CHAIN_ID}/*"
    mv "$BASE_DIR/wallet-temp.toml" "$BASE_DIR/${NAMADA_CHAIN_ID}/wallet-genesis.toml"
    mv "${NAMADA_CHAIN_ID}.tar.gz" $CHAIN_DIR
    rm -rf "$SCRIPT_DIR/utils/network-config.toml"
    
    # clean up the http server when the script exits
    trap cleanup EXIT

    export NAMADA_NETWORK_CONFIGS_SERVER='http://localhost:8123'
    nohup bash -c "python3 -m http.server --directory ${CHAIN_DIR} 8123 &" &&
        sleep 2 &&
        $NAMADA_BIN_DIR/namadac --base-dir "$BASE_DIR" utils join-network \
            --genesis-validator "$ALIAS" \
            --chain-id "${NAMADA_CHAIN_ID}" \
            --dont-prefetch-wasm

    cp wasm/*.wasm "$BASE_DIR/${NAMADA_CHAIN_ID}/wasm/"
    cp wasm/checksums.json "$BASE_DIR/${NAMADA_CHAIN_ID}/wasm/"

    tar -cvzf "${NAMADA_CHAIN_ID}.prebuilt.tar.gz" "$BASE_DIR"
    mv "${NAMADA_CHAIN_ID}.prebuilt.tar.gz" $CHAIN_DIR

    git checkout --ours -- wasm/checksums.json
    rm -rf nohup.out

    # don't delete namada - so we're ready to go with the chain
    echo "Run the ledger! (and when done follow the instructions to clean up)"
}

main() {    
    if expr "x$*x" : "x*--help*x" >/dev/null; then
        show_help
        return 0
    fi

    validate_arguments "$@"
    package "$@"
}

main "$@"
