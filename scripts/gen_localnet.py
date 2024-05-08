import argparse
import datetime
import sys
import os
import subprocess
import shutil
import toml
import json

from pathlib import Path
from tempfile import TemporaryDirectory


def main():
    if os.name != "posix":
        die("This script only works on UNIX-like systems")

    args = parse_cli_args()

    with TemporaryDirectory() as working_directory:
        try:
            main_inner(args, working_directory)
        except Exception as e:
            error(str(e))


def main_inner(args, working_directory):
    templates, templates_path = load_base_templates(args.templates)
    edit_templates(templates, to_edit_from_args(args))

    binaries = target_binary_paths(args.mode)

    version_string = system(binaries[NAMADA], "--version").decode().strip()
    info(f"Using {version_string}")

    # Run namadac utils init_network with the correct arguments
    info("Creating network release archive with `init-network`")

    chain_prefix = "local"
    genesis_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    wasm_path = get_project_root() / "wasm"
    wasm_checksums_path = wasm_path / "checksums.json"
    base_dir = reset_base_dir(args)

    # Check that wasm checksums file exists
    if not os.path.isfile(wasm_checksums_path):
        die(f"Cannot find the wasm checksums file at {wasm_checksums_path}")

    # Check that wasm directory exists and is not empty
    if not os.path.isdir(wasm_path) or not os.listdir(wasm_path):
        die(f"Cannot find wasm directory that is not empty at {wasm_path}")

    init_network_output = system(
        binaries[NAMADAC],
        "utils",
        "init-network",
        "--chain-prefix",
        chain_prefix,
        "--genesis-time",
        genesis_time,
        "--templates-path",
        templates_path,
        "--wasm-checksums-path",
        wasm_checksums_path,
        "--archive-dir",
        working_directory,
    )
    chain_id = lookup_chain_id(init_network_output)

    info(f"Initialized chain with id {chain_id}")

    pre_genesis_path = (
        get_project_root() / "genesis" / "localnet" / "src" / "pre-genesis"
    )

    genesis_validator = "validator-0"
    genesis_validator_path = pre_genesis_path / genesis_validator

    if not genesis_validator_path.is_dir() or is_empty(
        genesis_validator_path.iterdir()
    ):
        die(
            f"Cannot find pre-genesis directory that is not empty at {genesis_validator_path}"
        )

    system(
        "env",
        f"NAMADA_NETWORK_CONFIGS_DIR={working_directory}",
        binaries[NAMADAC],
        "--base-dir",
        base_dir,
        "utils",
        "join-network",
        "--chain-id",
        chain_id,
        "--genesis-validator",
        genesis_validator,
        "--pre-genesis-path",
        genesis_validator_path,
        "--dont-prefetch-wasm",
    )

    info(
        f"Joined chain with id {chain_id} as a validator with alias {genesis_validator}"
    )

    # Move the genesis wallet to the base dir
    genesis_wallet_toml = pre_genesis_path / "wallet.toml"
    wallet = base_dir / chain_id / "wallet.toml"
    move_genesis_wallet(genesis_wallet_toml, wallet)

    info("Run the ledger using the command string below")

    print()
    print(
        f"{binaries[NAMADA]} --base-dir='{base_dir}' --chain-id '{chain_id}' ledger run"
    )


def log(descriptor, line):
    print(f"[{descriptor}]: {line}")


def info(msg):
    log("info", msg)


def warning(msg):
    log("warning", msg)


def error(msg):
    log("error", msg)


def die(msg):
    error(msg)
    sys.exit(1)


def system(*cmd_args):
    return subprocess.check_output(cmd_args)


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="Configure a localnet for testing purposes."
    )

    if sys.version_info.minor >= 9:
        parser.add_argument(
            "--force",
            action=argparse.BooleanOptionalAction,
        )
    else:
        parser.add_argument(
            "--force",
            action="store_true",
        )
        parser.set_defaults(feature=True)
    parser.add_argument(
        "--base-dir", type=str, help="Path to the base directory of the chain."
    )
    parser.add_argument(
        "--templates",
        type=str,
        help="Localnet directory containing genesis templates.",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        default="debug",
        choices=["debug", "release"],
        help="Mode to run the localnet in.",
    )
    parser.add_argument(
        "--epoch-length",
        type=int,
        help="Epoch length in seconds. Defaults to `parameters.toml` value, and overrides value from `--edit`.",
    )
    parser.add_argument(
        "--max-validator-slots",
        type=int,
        help="Maximum number of validators. Defaults to `parameters.toml` value, and overrides value from `--edit`.",
    )
    parser.add_argument(
        "--edit",
        default={},
        type=json_object,
        help='JSON object of k:v pairs to update in the templates (eg: `{"parameters.toml":{"parameters":{"epochs_per_year":5}}}`).',
    )

    return parser.parse_args()


def json_object(s):
    params = json.loads(s)

    if type(params) != dict:
        die("Only JSON objects allowed for param updates")

    return params


def move_genesis_wallet(genesis_wallet_toml, wallet_toml):
    genesis_wallet = toml.load(genesis_wallet_toml)
    wallet = toml.load(wallet_toml)

    for key in genesis_wallet.keys():
        value_dict = genesis_wallet[key]
        if key in wallet.keys():
            wallet[key].update(value_dict)

    with open(wallet_toml, "w") as f:
        toml.dump(wallet, f)


def to_edit_from_args(args):
    params = args.edit.setdefault(PARAMETERS_TEMPLATE, {})
    if args.max_validator_slots:
        params.setdefault("pos_params", {})[
            "max_validator_slots"
        ] = args.max_validator_slots
    if args.epoch_length:
        params.setdefault("parameters", {})["epochs_per_year"] = int(
            round(365 * 24 * 60 * 60 / args.epoch_length)
        )
    return args.edit


def edit_templates(templates, to_edit):
    def invalid_dict(tab):
        return type(tab) != dict or len(tab) == 0

    def edit(so_far, table, entries):
        if invalid_dict(table) or invalid_dict(entries):
            return

        for key, value in entries.items():
            if key not in table:
                warning(f"Skipping invalid parameters entry {so_far}/{key}")
                continue

            if type(value) == dict:
                edit(f"{so_far}/{key}", table[key], value)

            table[key] = value

    edit("/", templates, to_edit)


def get_project_root():
    # ../namada/scripts/<this>.py => ../../
    #      ^
    return Path(sys.argv[0]).absolute().parent.parent


def genesis_template_members():
    return [
        BALANCES_TEMPLATE,
        PARAMETERS_TEMPLATE,
        TOKENS_TEMPLATE,
        TRANSACTIONS_TEMPLATE,
        VALIDITY_PREDICATES_TEMPLATE,
    ]


def load_base_templates(base_templates):
    src_templates_dir = (
        base_templates
        if base_templates
        else get_project_root() / "genesis" / "localnet"
    )

    return {
        template_name: toml.load(src_templates_dir / template_name)
        for template_name in ALL_GENESIS_TEMPLATES
    }, src_templates_dir


def target_binary_paths(mode):
    bins = {}

    for bin_name in ALL_NAMADA_BINS:
        full_bin_path = get_project_root() / "target" / mode / bin_name

        if not os.path.isfile(full_bin_path) or not os.access(full_bin_path, os.X_OK):
            die(f"Cannot find {bin_name} binary or it is not executable")

        bins[bin_name] = full_bin_path

    return bins


def lookup_chain_id(init_network_output):
    needle = b"Derived chain ID: "
    start = init_network_output.find(needle)
    if start == -1:
        die("Could not find chain id in `init-network` output")
    init_network_output = init_network_output[start + len(needle) :]
    end = init_network_output.find(b"\n")
    if end == -1:
        die("Could not find chain id in `init-network` output")
    return init_network_output[:end].decode()


def is_empty(g):
    try:
        next(g)
        return False
    except StopIteration:
        return True


def reset_base_dir(args):
    base_dir = args.base_dir
    if not base_dir:
        base_dir = get_project_root() / ".namada"
    if os.path.isdir(base_dir):
        if not args.force:
            die(
                f"Base directory {base_dir} already exists. Try running this script with `--force`."
            )
        shutil.rmtree(base_dir)
    os.mkdir(base_dir)
    return Path(base_dir)


BALANCES_TEMPLATE = "balances.toml"
PARAMETERS_TEMPLATE = "parameters.toml"
TOKENS_TEMPLATE = "tokens.toml"
TRANSACTIONS_TEMPLATE = "transactions.toml"
VALIDITY_PREDICATES_TEMPLATE = "validity-predicates.toml"

ALL_GENESIS_TEMPLATES = [
    BALANCES_TEMPLATE,
    PARAMETERS_TEMPLATE,
    TOKENS_TEMPLATE,
    TRANSACTIONS_TEMPLATE,
    VALIDITY_PREDICATES_TEMPLATE,
]

NAMADA = "namada"
NAMADAC = "namadac"
NAMADAN = "namadan"
NAMADAW = "namadaw"

ALL_NAMADA_BINS = [
    NAMADA,
    NAMADAC,
    NAMADAN,
    NAMADAW,
]

if __name__ == "__main__":
    main()
