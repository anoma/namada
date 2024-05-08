import argparse
import datetime
import sys
import os
import subprocess
import shutil
import toml


def main():
    # Get the absolute path to the directory of the script
    script_dir = sys.path[0]
    # Get absolute path of parent directory
    namada_dir = script_dir[: script_dir.rfind("/")]

    # Create the parser
    parser = argparse.ArgumentParser(
        description="Builds a localnet for testing purposes"
    )

    # Add the arguments
    parser.add_argument(
        "--base-dir", type=str, help="The path to the base directory of the chain."
    )
    parser.add_argument(
        "--localnet-dir",
        type=str,
        help="The localnet directory containing the genesis templates.",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        help="The mode to run the localnet in. Can be release or debug, defaults to debug.",
    )
    parser.add_argument(
        "--epoch-length",
        type=int,
        help="The epoch length in seconds, defaults to parameters.toml value.",
    )
    parser.add_argument(
        "--max-validator-slots",
        type=int,
        help="The maximum number of validators, defaults to parameters.toml value.",
    )
    # Change any parameters in the parameters.toml file
    parser.add_argument(
        "--params",
        type=str,
        help="A string representation of a dictionary of parameters to update in the parameters.toml. Must be of the same format.",
    )

    # Parse the arguments
    args = parser.parse_args()

    # Access the arguments
    if args.localnet_dir:
        if args.localnet_dir[-1] == "/":
            args.localnet_dir = args.localnet_dir[:-1]
        # print(os.path.basename(args.localnet_dir))
        localnet_dir = namada_dir + "/" + os.path.basename(args.localnet_dir)
        shutil.copytree(args.localnet_dir, localnet_dir)

        if os.path.isdir(localnet_dir) and os.listdir(localnet_dir):
            info("Using localnet directory: " + localnet_dir)
        else:
            die("Cannot find localnet directory that is not empty")
    else:
        localnet_dir = namada_dir + "/genesis/localnet"

    if args.mode:
        mode = args.mode
    else:
        mode = "debug"

    if mode.lower() != "release":
        mode = "debug"

    params = {}
    if args.params:
        params = eval(args.params)
    if args.max_validator_slots:
        params["pos_params"] = {"max_validator_slots": args.max_validator_slots}
    if args.epoch_length:
        epochs_per_year = round(365 * 24 * 60 * 60 / args.epoch_length)
        params["parameters"] = {"epochs_per_year": epochs_per_year}
    if len(params.keys()) > 0:
        edit_parameters(localnet_dir + "/parameters.toml", **params)

    namada_bin_dir = namada_dir + "/target/" + mode + "/"

    # Check that namada_bin_dir exists and is not empty
    if not os.path.isdir(namada_bin_dir) or not os.listdir(namada_bin_dir):
        die("Cannot find namada binary directory that is not empty")

    namada_bin = namada_bin_dir + "namada"
    namadac_bin = namada_bin_dir + "namadac"
    namadan_bin = namada_bin_dir + "namadan"
    namadaw_bin = namada_bin_dir + "namadaw"

    bins = [namada_bin, namadac_bin, namadan_bin, namadaw_bin]
    # Check that each binary exists and is executable
    for bin in bins:
        if not os.path.isfile(bin) or not os.access(bin, os.X_OK):
            die(f"Cannot find the {bin.split('/')[-1]} binary or it is not executable")

    info(
        f"Using {bins[0].split('/')[-1]} version: {os.popen(bin + ' --version').read()}"
    )

    # Run namadac utils init_network with the correct arguments
    info("Running namadac utils init_network")
    CHAIN_PREFIX = "local"
    GENESIS_TIME = datetime.datetime.now(datetime.timezone.utc).isoformat()
    TEMPLATES_PATH = localnet_dir
    WASM_CHECKSUMS_PATH = namada_dir + "/wasm/checksums.json"
    WASM_PATH = namada_dir + "/wasm/"
    BASE_DIR = args.base_dir

    if not BASE_DIR:
        BASE_DIR = (
            subprocess.check_output([namadac_bin, "utils", "default-base-dir"])
            .decode()
            .strip()
        )

    # Delete the base dir
    if os.path.isdir(BASE_DIR):
        shutil.rmtree(BASE_DIR)
    os.mkdir(BASE_DIR)

    # Check that wasm checksums file exists
    if not os.path.isfile(WASM_CHECKSUMS_PATH):
        die(f"Cannot find the wasm checksums file at {WASM_CHECKSUMS_PATH}")

    # Check that wasm directory exists and is not empty
    if not os.path.isdir(WASM_PATH) or not os.listdir(WASM_PATH):
        die(f"Cannot find wasm directory that is not empty at {WASM_PATH}")

    system(
        f"{namadac_bin} --base-dir='{BASE_DIR}' utils init-network --chain-prefix {CHAIN_PREFIX} --genesis-time {GENESIS_TIME} --templates-path {TEMPLATES_PATH} --wasm-checksums-path {WASM_CHECKSUMS_PATH}"
    )

    base_dir_files = os.listdir(BASE_DIR)
    CHAIN_ID = ""
    for file in base_dir_files:
        if file.startswith(CHAIN_PREFIX):
            CHAIN_ID = file
            break

    # create a new directory within the base_dir
    temp_dir = BASE_DIR + "/tmp/"
    os.mkdir(temp_dir)
    shutil.move(BASE_DIR + "/" + CHAIN_ID, BASE_DIR + "/tmp/" + CHAIN_ID)
    shutil.move(
        namada_dir + "/" + CHAIN_ID + ".tar.gz", temp_dir + CHAIN_ID + ".tar.gz"
    )

    GENESIS_VALIDATOR = "validator-0"
    PRE_GENESIS_PATH = localnet_dir + "/src/pre-genesis/" + GENESIS_VALIDATOR
    if not os.path.isdir(PRE_GENESIS_PATH) or not os.listdir(PRE_GENESIS_PATH):
        die(
            f"Cannot find pre-genesis directory that is not empty at {PRE_GENESIS_PATH}"
        )

    system(
        f"NAMADA_NETWORK_CONFIGS_DIR='{temp_dir}' {namadac_bin} --base-dir='{BASE_DIR}' utils join-network --chain-id {CHAIN_ID} --genesis-validator {GENESIS_VALIDATOR} --pre-genesis-path {PRE_GENESIS_PATH} --dont-prefetch-wasm"
    )

    shutil.rmtree(BASE_DIR + "/" + CHAIN_ID + "/wasm/")
    shutil.move(temp_dir + CHAIN_ID + "/wasm/", BASE_DIR + "/" + CHAIN_ID + "/wasm/")

    # Move the genesis wallet to the base dir
    genesis_wallet_toml = localnet_dir + "/src/pre-genesis" + "/wallet.toml"
    wallet = BASE_DIR + "/" + CHAIN_ID + "/wallet.toml"
    move_genesis_wallet(genesis_wallet_toml, wallet)
    # Delete the temp dir
    shutil.rmtree(temp_dir)

    info(
        f"Run the ledger using the following command: {namada_bin} --base-dir='{BASE_DIR}' --chain-id '{CHAIN_ID}' ledger run"
    )


def log(descriptor, line):
    print(f"[{descriptor}]: {line}")


def info(msg):
    log("info", msg)


def warning(msg):
    log("warning", msg)


def die(msg):
    log("error", msg)
    sys.exit(1)


def system(cmd):
    log("exec-cmd", cmd)

    error_code = os.system(cmd)
    if error_code != 0:
        sys.exit(error_code)


def move_genesis_wallet(genesis_wallet_toml: str, wallet_toml: str):
    genesis_wallet = toml.load(genesis_wallet_toml)
    wallet = toml.load(wallet_toml)

    for key in genesis_wallet.keys():
        value_dict = genesis_wallet[key]
        if key in wallet.keys():
            wallet[key].update(value_dict)
    toml.dump(wallet, open(wallet_toml, "w"))


def edit_parameters(params_toml, **kwargs):
    # Make sure the kwargs are valid
    params = toml.load(params_toml)
    for k in kwargs.keys():
        if k not in params.keys():
            warning(f"Invalid parameter {k}")
            del kwargs[k]
        else:
            for key in kwargs[k].keys():
                if key not in params[k].keys():
                    warning(f"Invalid parameter {key} for {k}")
                    del kwargs[k][key]
                else:
                    params[k][key] = kwargs[k][key]

    toml.dump(params, open(params_toml, "w"))


if __name__ == "__main__":
    main()
