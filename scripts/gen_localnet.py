#!/usr/bin/env python3

import argparse
import datetime
import sys
import os
import subprocess
import shutil
import toml
import json
import re

from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import timedelta


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
    binaries = target_binary_paths(args.mode)

    version_string = system(binaries[NAMADA], "--version").decode().strip()
    info(f"Using {version_string}")

    chain_id, templates = init_network(
        working_directory=working_directory,
        binaries=binaries,
        args=args,
    )

    command_summary = {}
    base_dir_prefix = reset_base_dir_prefix(args)

    for validator_alias, validator_addr in args.validator_aliases.items():
        if not validator_exists(
            templates=templates,
            validator_alias=validator_alias,
            validator_addr=validator_addr,
        ):
            die(
                f"Could not find {validator_alias} with addr {validator_addr} in {TRANSACTIONS_TEMPLATE}"
            )

        join_network_with_validator(
            working_directory=working_directory,
            binaries=binaries,
            base_dir_prefix=base_dir_prefix,
            chain_id=chain_id,
            genesis_validator=validator_alias,
            pre_genesis_path=args.pre_genesis_path,
            command_summary=command_summary,
        )

    for fullnode_alias, full_node_base_port in args.full_nodes.items():
        join_network_with_fullnode(
            working_directory=working_directory,
            binaries=binaries,
            base_dir_prefix=base_dir_prefix,
            chain_id=chain_id,
            fullnode_alias=fullnode_alias,
            fullnode_base_port=full_node_base_port,
            pre_genesis_path=args.pre_genesis_path,
            command_summary=command_summary,
        )

    info("Run the ledger(s) using the command string(s) below")

    for validator_alias, cmd_str in command_summary.items():
        print(f"\n{Color.BOLD}{validator_alias}:{Color.END}\n{cmd_str}")


def init_network(
    working_directory,
    binaries,
    args,
):
    info("Creating network release archive with `init-network`")

    wasm_path = get_project_root() / "wasm"
    wasm_checksums_path = wasm_path / "checksums.json"

    # Check that wasm checksums file exists
    if not os.path.isfile(wasm_checksums_path):
        die(f"Cannot find the wasm checksums file at {wasm_checksums_path}")

    # Check that wasm directory exists and is not empty
    if not os.path.isdir(wasm_path) or not os.listdir(wasm_path):
        die(f"Cannot find wasm directory that is not empty at {wasm_path}")

    chain_prefix = "local"
    genesis_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000%f+00:00"
    )

    templates = setup_templates(working_directory, args)

    init_network_output = system(
        binaries[NAMADAC],
        "utils",
        "init-network",
        "--chain-prefix",
        chain_prefix,
        "--genesis-time",
        genesis_time,
        "--templates-path",
        working_directory,
        "--wasm-checksums-path",
        wasm_checksums_path,
        "--archive-dir",
        working_directory,
    )
    chain_id = lookup_chain_id(init_network_output)

    info(f"Initialized chain with id {chain_id}")

    return chain_id, templates


def join_network_with_validator(
    working_directory,
    binaries,
    base_dir_prefix,
    chain_id,
    genesis_validator,
    pre_genesis_path,
    command_summary,
):
    info(f"Attempting to join {chain_id} with {genesis_validator}")

    pre_genesis_wallet_path = pre_genesis_path / "wallet.toml"
    genesis_validator_path = pre_genesis_path / genesis_validator

    if not genesis_validator_path.is_dir() or is_empty(
        genesis_validator_path.iterdir()
    ):
        die(
            f"Cannot find pre-genesis directory that is not empty at {genesis_validator_path}"
        )
    if not pre_genesis_wallet_path.is_file():
        die(f"Cannot find pre-genesis wallet at {pre_genesis_wallet_path}")

    base_dir = reset_base_dir(
        prefix=base_dir_prefix,
        node_alias=genesis_validator,
        pre_genesis_wallet=pre_genesis_wallet_path,
    )

    system(
        "env",
        f"NAMADA_NETWORK_CONFIGS_DIR={working_directory}",
        binaries[NAMADAC],
        "--base-dir",
        base_dir,
        "utils",
        "join-network",
        "--add-persistent-peers",
        "--allow-duplicate-ip",
        "--chain-id",
        chain_id,
        "--genesis-validator",
        genesis_validator,
        "--pre-genesis-path",
        genesis_validator_path,
    )

    info(f"Validator {genesis_validator} joined {chain_id}")

    command_summary[genesis_validator] = (
        f"{binaries[NAMADA]} --base-dir='{base_dir}' ledger run"
    )


def join_network_with_fullnode(
    working_directory,
    binaries,
    base_dir_prefix,
    chain_id,
    fullnode_alias,
    fullnode_base_port,
    pre_genesis_path,
    command_summary,
):
    info(f"Attempting to join {chain_id} with {fullnode_alias}")

    pre_genesis_wallet_path = pre_genesis_path / "wallet.toml"

    base_dir = reset_base_dir(
        prefix=base_dir_prefix,
        node_alias=fullnode_alias,
        pre_genesis_wallet=pre_genesis_wallet_path,
    )

    system(
        "env",
        f"NAMADA_NETWORK_CONFIGS_DIR={working_directory}",
        binaries[NAMADAC],
        "--base-dir",
        base_dir,
        "utils",
        "join-network",
        "--add-persistent-peers",
        "--allow-duplicate-ip",
        "--chain-id",
        chain_id,
    )

    update_fullnode_config(
        full_node_base_port=fullnode_base_port,
        fullnode_config_path=base_dir_prefix
        / fullnode_alias
        / chain_id
        / "config.toml",
    )

    info(f"Full node {fullnode_alias} joined {chain_id}")

    command_summary[fullnode_alias] = (
        f"{binaries[NAMADA]} --base-dir='{base_dir}' ledger run"
    )


def update_fullnode_config(full_node_base_port, fullnode_config_path):
    config = toml.load(fullnode_config_path)

    config["ledger"]["cometbft"]["rpc"][
        "laddr"
    ] = f"tcp://127.0.0.1:{full_node_base_port}"
    config["ledger"]["cometbft"][
        "proxy_app"
    ] = f"tcp://127.0.0.1:{full_node_base_port + 1}"
    config["ledger"]["cometbft"]["p2p"][
        "laddr"
    ] = f"tcp://0.0.0.0:{full_node_base_port + 2}"

    with open(fullnode_config_path, "w") as output_file:
        toml.dump(config, output_file)


def log(color, descriptor, line):
    print(f"[{color}{Color.UNDERLINE}{descriptor}{Color.END}]: {line}")


def info(msg):
    log(Color.GREEN, "info", msg)


def warning(msg):
    log(Color.YELLOW, "warn", msg)


def error(msg):
    log(Color.RED, "error", msg)


def die(msg):
    error(msg)
    sys.exit(1)


def system(*cmd_args):
    return subprocess.check_output(cmd_args)


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="Configure a localnet for testing purposes."
    )

    group = parser.add_argument_group(
        title="Node config",
        description="Customize the validators and full nodes the localnet will run with.",
    )
    group.add_argument(
        "--templates",
        type=Path,
        help="Localnet directory containing genesis templates. Overrides the templates found in `genesis/localnet`.",
    )
    group.add_argument(
        "--validator-aliases",
        type=validator_aliases_json_object,
        help='JSON object of validators passed to `--templates` (eg: `{"validator-0":"tnam1..."`).',
    )
    group.add_argument(
        "--pre-genesis-path",
        type=Path,
        help="Path to pre-genesis directory. Must be present with custom `--templates`.",
    )
    group.add_argument(
        "--full-nodes",
        default={},
        type=full_nodes_object,
        help="JSON object of full node aliases to port numbers these will listen on.",
    )

    group = parser.add_argument_group(
        title="General config",
        description="General configuration of this script.",
    )
    if sys.version_info.minor >= 9:
        group.add_argument(
            "--force",
            action=argparse.BooleanOptionalAction,
        )
    else:
        group.add_argument(
            "--force",
            action="store_true",
        )
        parser.set_defaults(feature=True)
    group.add_argument(
        "--base-dir-prefix",
        type=Path,
        default=get_project_root() / ".namada",
        help="Prefix path to the base directory of each validator.",
    )
    group.add_argument(
        "-m",
        "--mode",
        type=str,
        default="debug",
        choices=["debug", "release"],
        help="Mode to run the localnet in.",
    )

    group = parser.add_argument_group(
        title="Parameters config",
        description="Configure chain parameters.",
    )
    group.add_argument(
        "--epoch-duration",
        type=parse_duration,
        help="Epoch duration (eg: `1hr`, `30m`, `15s`). Defaults to `parameters.toml` value, and overrides value from `--edit`.",
    )
    group.add_argument(
        "--max-validator-slots",
        type=int,
        help="Maximum number of validators. Defaults to `parameters.toml` value, and overrides value from `--edit`.",
    )
    group.add_argument(
        "--edit",
        action="append",
        default=[],
        type=params_json_object,
        help='JSON object of k:v pairs to update in the templates (eg: `{"parameters.toml":{"parameters":{"epochs_per_year":5}}}`).',
    )
    group.add_argument(
        "--eval",
        action=argparse.BooleanOptionalAction,
        help="Evaluate strings passed to `--edit` as Python code.",
    )

    args = parser.parse_args()
    exclusive = [args.templates, args.validator_aliases, args.pre_genesis_path]
    exclusivity_respected = all(map(lambda x: x != None, exclusive)) or all(
        map(lambda x: x == None, exclusive)
    )

    if not exclusivity_respected:
        die(
            "Validator aliases, genesis templates and a pre-genesis dir must be present simultaneously, consult `--help`"
        )

    args.templates = args.templates or get_project_root() / "genesis" / "localnet"
    args.validator_aliases = args.validator_aliases or {
        "validator-0": "tnam1q9vhfdur7gadtwx4r223agpal0fvlqhywylf2mzx"
    }
    args.pre_genesis_path = (
        args.pre_genesis_path
        or get_project_root() / "genesis" / "localnet" / "src" / "pre-genesis"
    )

    if not os.path.isdir(args.templates):
        die(f"Path to templates {args.templates} is not a directory")
    if not os.path.isdir(args.pre_genesis_path):
        die(f"Path to pre-genesis {args.pre_genesis_path} is not a directory")

    return args


def validator_aliases_json_object(s):
    aliases = load_json(s)

    if type(aliases) != dict:
        die("Only JSON objects allowed for validator")

    for k, v in aliases.items():
        valid_type = type(k) == str and type(v) == str and v.startswith("tnam1")
        if not valid_type:
            die("Must map from validator alias to their validator address")

    return aliases


def params_json_object(s):
    params = load_json(s)

    if type(params) != dict:
        die("Only JSON objects allowed for param updates")

    return params


def full_nodes_object(s):
    full_nodes = load_json(s)

    if type(full_nodes) != dict:
        die("Only JSON objects allowed for full nodes")

    for value in full_nodes.values():
        if type(value) != int:
            die(
                "Only JSON objects with a mapping between full node aliases and base ports (range 0-65535) allowed"
            )

    return full_nodes


def load_json(s):
    try:
        return json.loads(s)
    except json.decode.JSONDecodeError:
        # assume we're dealing with a file path
        with open(s, "r") as f:
            return json.load(f)


def to_edit_from_args(args):
    if args.max_validator_slots:
        templates = {}
        value = args.max_validator_slots
        if args.eval:
            value = repr(value)
        params = templates.setdefault(PARAMETERS_TEMPLATE, {})
        params.setdefault("pos_params", {})["max_validator_slots"] = value
        args.edit.append(templates)
    if args.epoch_duration:
        templates = {}
        value = int(round(365 * 24 * 60 * 60 / args.epoch_duration.total_seconds()))
        if args.eval:
            value = repr(value)
        params = templates.setdefault(PARAMETERS_TEMPLATE, {})
        params.setdefault("parameters", {})["epochs_per_year"] = value
        args.edit.append(templates)
    return args.edit


def edit_toml(data, to_edit_list, evaluate=False):
    def invalid_dict(tab):
        return type(tab) != dict or len(tab) == 0

    def edit(so_far, table, entries, evaluate):
        if invalid_dict(table) or invalid_dict(entries):
            return

        so_far_str = None

        for key, value in entries.items():
            if key not in table:
                if not so_far_str:
                    so_far_str = "/".join(so_far)
                warning(f"Skipping invalid parameters entry {so_far_str}/{key}")
                continue

            if type(value) == dict:
                so_far.append(key)
                edit(so_far, table[key], value, evaluate)
                so_far.pop()
                return

            if evaluate:
                it = table.get(key)
                table[key] = eval(value)
            else:
                table[key] = value

    for to_edit in to_edit_list:
        info(f"Applying provided args: {to_edit}")
        edit([], data, to_edit, evaluate)


def write_templates(working_directory, templates):
    template_path = lambda name: Path(working_directory) / name
    for name, template in templates.items():
        with open(template_path(name), "w") as output_file:
            toml.dump(template, output_file)


def setup_templates(working_directory, args):
    to_edit = to_edit_from_args(args)
    info(f"Updating templates")
    templates = load_base_templates(args.templates)
    edit_toml(templates, to_edit, evaluate=args.eval)
    write_templates(working_directory, templates)
    info("Templates have been updated")
    return templates


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
    return {
        template_name: toml.load(base_templates / template_name)
        for template_name in ALL_GENESIS_TEMPLATES
    }


def load_node_config(base_dir_prefix, chain_id, node_alias):
    config_path = base_dir_prefix / node_alias / chain_id / "config.toml"
    return toml.load(config_path)


def write_node_config(config, base_dir_prefix, chain_id, node_alias):
    config_path = base_dir_prefix / node_alias / chain_id / "config.toml"
    with open(config_path, "w") as output_file:
        toml.dump(config, output_file)


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


def reset_base_dir_prefix(args):
    prefix = args.base_dir_prefix
    if os.path.isdir(prefix):
        if not args.force:
            die(
                f"Base directory prefix {prefix} already exists. Try running this script with `--force`."
            )
        shutil.rmtree(prefix)
    os.mkdir(prefix)
    return prefix


def reset_base_dir(prefix, node_alias, pre_genesis_wallet):
    base_dir = prefix / node_alias
    pre_genesis_dir = base_dir / "pre-genesis"
    os.mkdir(base_dir)
    os.mkdir(pre_genesis_dir)
    shutil.copy(pre_genesis_wallet, pre_genesis_dir)
    return base_dir


def validator_exists(templates, validator_alias, validator_addr):
    transactions = templates[TRANSACTIONS_TEMPLATE]
    validators = transactions["validator_account"]

    for val in validators:
        if val["address"] == validator_addr:
            info(f"Validator {validator_alias} will listen at {val['net_address']}")
            return True

    return False


# https://stackoverflow.com/questions/5522031/convert-timedelta-to-total-seconds
def parse_duration(time_str):
    parts = PARSE_TIME_REGEX.match(time_str)
    if not parts:
        die(f"Invalid duration {time_str}")
    parts = parts.groupdict()
    time_params = {}
    for name, param in parts.items():
        if param:
            time_params[name] = int(param)
    dur = timedelta(**time_params)
    if dur.total_seconds() == 0:
        die(
            f"Duration {time_str} was parsed as zero, try using `hr`, `m` or `s` unit suffixes"
        )
    return dur


def append_list(l, *values):
    for x in values:
        l.append(x)
    return l


def insert_dict(d, **kwargs):
    for k, v in kwargs.items():
        d[k] = v
    return d


# https://stackoverflow.com/questions/8924173/how-can-i-print-bold-text-in-python
class Color:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARKCYAN = "\033[36m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


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

PARSE_TIME_REGEX = re.compile(
    r"((?P<hours>\d+?)hr)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?"
)

if __name__ == "__main__":
    main()
