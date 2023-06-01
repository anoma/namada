#!/usr/bin/env bash
#
# Script for initializing a Namada chain for local development and joining it.
# Note that this script trashes any existing local chain directories!
#
# ## Prerequisites
# - bash
# - Python 3
# - toml Python pip library <https://pypi.org/project/toml/> (this is the
#   `python3-toml` package on Ubuntu distributions)
# - trash CLI tool (`brew install trash` on macOS or `sudo apt-get install
#   trash-cli` on Ubuntu)
#
# ## How to run
# This script should be run from the root of a Namada source code repo
# (https://github.com/anoma/namada). *.wasm files must already have been built
# and be present under the `wasm/` directory of the Namada repo. This can be
# done by running `make build wasm-scripts`. The shell script takes three
# arguments: The first argument is the path to a network config toml compatible
# with the version of Namada being used. You can find example network config
# tomls in the `templates/` directory of the anoma-network-configs repo
# (https://github.com/heliaxdev/anoma-network-configs)` The second argument is
# the BASE_DIR of the chain. This will depend on your setup. The third argument
# is the path to the directory containing the Namada binaries
# 
# 
# Example command:
# ```shell
# ./scripts/build_network.sh network-configs/mainline-v0.12.1.toml '~/Library/Application Support/Namada'
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
IFS=$'\n\t'

show_help() {
    echo "Usage: script.sh <config_toml> <base_dir> <namada_dir>"
    echo ""
    echo "Arguments:"
    echo "  config_toml - The path to a network config toml compatible with the version of Namada being used"
    echo "  base_dir - The path to the base directory (BASE_DIR), which is the directory where the chain's information will be stored"
    echo "  namada_dir - The path to the directory containing the Namada binaries"
    echo ""
}

check_toml_file() {
    toml_file="$NETWORK_CONFIG_PATH"  # Get the file path from the first argument
    section_prefix="validator.validator"
    # Search for the section name in the TOML file
    section_count=$(awk -F'[][]' -v prefix="$section_prefix" '/^\[.*\]$/ && $2 ~ "^" prefix { count++ } END { print count }' "$toml_file")
    if [[ ! $section_count -eq 0 ]]; then
        echo "At least one validator ($section_count, in fact) has been found in the toml file. Please delete all occurrences of the section '[$section_prefix]' in the TOML file and try again."
        exit 1
    fi
}


check_wasm_files() {
    wasm_files=$(find wasm -type f -name "*.wasm")

    count=$(echo "$wasm_files" | wc -l)

    if [[ ! $count -ge 5 ]]; then
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
    # The script expects 3 arguments:
    # 1. The path to a network config toml
    # 2. The path to the directory containing the Namada binaries
    # 3. The BASE_DIR of the chain
    
    if [ "$#" -gt 3 ] || [ "$#" -lt 2 ]; then
        echo "Error: Invalid number of arguments. Expected 2 or 3 arguments."
        echo "See the help page by running --help for more information."
        exit 1
    fi

    NETWORK_CONFIG_PATH=$1
    NAMADA_BIN_DIR=$2

    local current_directory="$(pwd)"

    if [ ! -d "$current_directory/wasm" ]; then
        echo "Error: Directory 'wasm' does not exist in the current directory."
        exit 1
    fi

    # The first argument should be a path to a network config toml
    if [ ! -f "$NETWORK_CONFIG_PATH" ]; then
        echo "Error: Invalid network config path. Expected a path to a network config toml, yet found no file in the location."
        exit 1
    fi
    file="$NETWORK_CONFIG_PATH"  # Get the file path from the first argument
    extension="${file##*.}"
    if [ "$extension" != "toml" ]; then
        echo "Error: The first argument provided is not a .toml file."
        exit 1
    fi

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

    if [ "$#" -eq 2 ]; then
        BASE_DIR=$(echo $NAMADA_BIN_DIR/namadac utils default-base-dir)
        echo "Using default BASE_DIR: $BASE_DIR"
    else [ "$#" -eq 3 ];
        BASE_DIR=$3
    fi


    exit 1
}

package() {

    # Clean up any existing chain data
    trash $BASE_DIR || true
    git checkout --ours -- wasm/checksums.json
    trash nohup.out || true

    CHAIN_DIR='.hack/chains'
    mkdir -p $CHAIN_DIR

    ALIAS='validator-local-dev'

    $NAMADA_BIN_DIR/namadac --base-dir $BASE_DIR utils init-genesis-validator \
        --alias $ALIAS \
        --net-address 127.0.0.1:26656 \
        --commission-rate 0.1 \
        --max-commission-rate-change 0.1 \
        --unsafe-dont-encrypt

    # get the directory of this script
    SCRIPT_DIR="$(dirname $0)"
    NAMADA_NETWORK_CONFIG_PATH="${CHAIN_DIR}/network-config-processed.toml"
    $SCRIPT_DIR/utils/add_validator_shard.py $BASE_DIR/pre-genesis/$ALIAS/validator.toml $NETWORK_CONFIG_PATH >$NAMADA_NETWORK_CONFIG_PATH

    python3 wasm/checksums.py

    NAMADA_CHAIN_PREFIX='local'

    $NAMADA_BIN_DIR/namadac --base-dir $BASE_DIR utils init-network \
        --chain-prefix "$NAMADA_CHAIN_PREFIX" \
        --genesis-path "$NAMADA_NETWORK_CONFIG_PATH" \
        --wasm-checksums-path wasm/checksums.json \
        --unsafe-dont-encrypt

    basename *.tar.gz .tar.gz >${CHAIN_DIR}/chain-id
    NAMADA_CHAIN_ID="$(cat ${CHAIN_DIR}/chain-id)"
    trash "$BASE_DIR/${NAMADA_CHAIN_ID}"
    mv "${NAMADA_CHAIN_ID}.tar.gz" $CHAIN_DIR

    # clean up the http server when the script exits
    trap cleanup EXIT

    NAMADA_NETWORK_CONFIGS_SERVER='http://localhost:8123'
    nohup bash -c "python3 -m http.server --directory ${CHAIN_DIR} 8123 &" &&
        sleep 2 &&
        $NAMADA_BIN_DIR/namadac --base-dir $BASE_DIR utils join-network \
            --genesis-validator "$ALIAS" \
            --chain-id "${NAMADA_CHAIN_ID}" \
            --dont-prefetch-wasm

    cp wasm/*.wasm "$BASE_DIR/${NAMADA_CHAIN_ID}/wasm/"
    cp wasm/checksums.json "$BASE_DIR/${NAMADA_CHAIN_ID}/wasm/"

    tar -cvzf "${NAMADA_CHAIN_ID}.prebuilt.tar.gz" $BASE_DIR
    mv "${NAMADA_CHAIN_ID}.prebuilt.tar.gz" $CHAIN_DIR

    git checkout --ours -- wasm/checksums.json
    trash nohup.out

    # don't trash namada - so we're ready to go with the chain
    echo "Run the ledger! (and when done follow the instructions to clean up)"
}

main() {    
    if [[ "$*" == *"--help"* ]]; then
        show_help
        return 0
    fi

    validate_arguments "$@"
    package "$@"
}


main $@

