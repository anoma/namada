import argparse
import sys
import os
import subprocess
import shutil
import toml

def system(cmd):
    if os.system(cmd) != 0:
        exit(1)

def move_genesis_wallet(genesis_wallet_toml : str, wallet_toml : str):
    genesis_wallet = toml.load(genesis_wallet_toml)
    wallet = toml.load(wallet_toml)

    for key in genesis_wallet.keys():
        value_dict = genesis_wallet[key]
        if key in wallet.keys():
            wallet[key].update(value_dict)
    toml.dump(wallet, open(wallet_toml, 'w'))

def edit_parameters(params_toml, **kwargs):
    # Make sure the kwargs are valid
    params = toml.load(params_toml)
    for k in kwargs.keys():
        if k not in params.keys():
            print(f"Invalid parameter {k}")
            del kwargs[k]
        else:
            for key in kwargs[k].keys():
                if key not in params[k].keys():
                    print(f"Invalid parameter {key} for {k}")
                    del kwargs[k][key]
                else:
                    params[k][key] = kwargs[k][key]
    
    toml.dump(params, open(params_toml, 'w'))



# Get the absolute path to the directory of the script
script_dir = sys.path[0]
# Get absolute path of parent directory
namada_dir = script_dir[:script_dir.rfind('/')]
current_dir = os.getcwd()
assert current_dir == namada_dir, 'Please run the script from the namada directory.'

# Create the parser
parser = argparse.ArgumentParser(description='Builds a localnet for testing purposes')

# Add the arguments
parser.add_argument('--base-dir', type=str, help='The path to the base directory of the chain.')
parser.add_argument('--localnet-dir', type=str, help='The localnet directory containing the genesis templates.')
parser.add_argument('-m', '--mode', type=str, help='The mode to run the localnet in. Can be release or debug, defaults to debug.')
parser.add_argument('--epoch-length', type=int, help='The epoch length in seconds, defaults to parameters.toml value.')
parser.add_argument('--max-validator-slots', type=int, help='The maximum number of validators, defaults to parameters.toml value.')
parser.add_argument('--num-nodes', type=int, help='Number of nodes to run, defaults to 1. If more than 1, base dirs will be under .namada-port. Number of chains must be less than 9.')
parser.add_argument('--num-vals', type=int, help='Number of validators to run, defaults to 1. If more than 1, base dirs will be under .namada-port. Number of validators must be less or equal to no-chains.')
# Change any parameters in the parameters.toml file
parser.add_argument('--params', type=str, help='A string representation of a dictionary of parameters to update in the parameters.toml. Must be of the same format.')


# Parse the arguments
args = parser.parse_args()

# Access the arguments
if args.localnet_dir:
    if args.localnet_dir[-1] == '/':
        args.localnet_dir = args.localnet_dir[:-1]
    print(os.path.basename(args.localnet_dir))
    localnet_dir = namada_dir + '/' + os.path.basename(args.localnet_dir)
    shutil.copytree(args.localnet_dir, localnet_dir)

    if os.path.isdir(localnet_dir) and os.listdir(localnet_dir):
        print('Using localnet directory: ' + localnet_dir)
    else:
        print('Cannot find localnet directory that is not empty')
        sys.exit(1)
else:
    localnet_dir = namada_dir + '/genesis/localnet'

if args.mode:
    mode = args.mode
else:
    mode = 'debug'

if mode.lower() != 'release':
    mode = 'debug'


print('Running namadac utils init_network')
CHAIN_PREFIX='local'
GENESIS_TIME='2021-12-31T00:00:00Z'
TEMPLATES_PATH=localnet_dir + '/tmp'
WASM_CHECKSUMS_PATH=namada_dir + '/wasm/checksums.json'
WASM_PATH=namada_dir + '/wasm/'
BASE_DIR = args.base_dir

BASE_DIRS=[]
system(f"rm -rf '{BASE_DIR}'")

if os.path.isdir(TEMPLATES_PATH):
    shutil.rmtree(TEMPLATES_PATH)
os.mkdir(TEMPLATES_PATH)

shutil.copy(localnet_dir + '/parameters.toml', TEMPLATES_PATH + '/parameters.toml')
shutil.copy(localnet_dir + '/transactions.toml', TEMPLATES_PATH + '/transactions.toml')
shutil.copy(localnet_dir + '/validity-predicates.toml', TEMPLATES_PATH + '/validity-predicates.toml')
shutil.copy(localnet_dir + '/tokens.toml', TEMPLATES_PATH + '/tokens.toml')
shutil.copy(localnet_dir + '/balances.toml', TEMPLATES_PATH + '/balances.toml')


if args.num_nodes and args.num_nodes > 1:
    BASE_DIRS = [f'.namada-2{(7+i) % 10}657' for i in range(args.num_nodes)]
    # if the base_dir exists, delete it
    system(f"rm -rf .namada-*")
    assert args.num_vals <= args.num_nodes, 'Number of validators must be less or equal to number of chains.'
    system(f"python3 {namada_dir}/scripts/make_localnet.py --num-vals {args.num_vals} --mode {mode}")
else:
    system("mkdir .localnet")
    system(f"cp -r {localnet_dir}/src .localnet/")
params = {}
if args.params:
    params = eval(args.params)
if args.max_validator_slots:
    params['pos_params'] = {'max_validator_slots': args.max_validator_slots}
if args.epoch_length:
    epochs_per_year = 365 * 24 * 60 * 60 // args.epoch_length
    params['parameters'] = {'epochs_per_year': epochs_per_year }
if len(params.keys())>0:
    edit_parameters(localnet_dir + '/parameters.toml', **params)
        
namada_bin_dir = namada_dir + '/target/' + mode + '/'

# Check that namada_bin_dir exists and is not empty
if not os.path.isdir(namada_bin_dir) or not os.listdir(namada_bin_dir):
    print('Cannot find namada binary directory that is not empty')
    sys.exit(1)

namada_bin = namada_bin_dir + 'namada'
namadac_bin = namada_bin_dir + 'namadac'
namadan_bin = namada_bin_dir + 'namadan'
namadaw_bin = namada_bin_dir + 'namadaw'

bins = [namada_bin, namadac_bin, namadan_bin, namadaw_bin]
# Check that each binary exists and is executable
for bin in bins:
    if not os.path.isfile(bin) or not os.access(bin, os.X_OK):
        print(f"Cannot find the {bin.split('/')[-1]} binary or it is not executable")
        sys.exit(1)



print(f"Using {bins[0].split('/')[-1]} version: {os.popen(bin + ' --version').read()}")

# Run namadac utils init_network with the correct arguments

if not BASE_DIR:
    BASE_DIR = subprocess.check_output([namadac_bin, "utils", "default-base-dir"]).decode().strip()

# Delete the base dir
if os.path.isdir(BASE_DIR):
    shutil.rmtree(BASE_DIR)
os.mkdir(BASE_DIR)



# Check that wasm checksums file exists
if not os.path.isfile(WASM_CHECKSUMS_PATH):
    print(f"Cannot find the wasm checksums file at {WASM_CHECKSUMS_PATH}")
    sys.exit(1)

# Check that wasm directory exists and is not empty
if not os.path.isdir(WASM_PATH) or not os.listdir(WASM_PATH):
    print(f"Cannot find wasm directory that is not empty at {WASM_PATH}")
    sys.exit(1)

system(f"{namadac_bin} --base-dir='{BASE_DIR}' utils init-network --chain-prefix {CHAIN_PREFIX} --genesis-time {GENESIS_TIME} --templates-path {TEMPLATES_PATH} --wasm-checksums-path {WASM_CHECKSUMS_PATH}")

base_dir_files = os.listdir(BASE_DIR)
CHAIN_ID=""
for file in base_dir_files:
    if file.startswith(CHAIN_PREFIX):
        CHAIN_ID = file
        break

# create a new directory within the base_dir 
temp_dir = BASE_DIR + '/tmp/'
os.mkdir(temp_dir)
shutil.move(BASE_DIR + '/' + CHAIN_ID, BASE_DIR + '/tmp/' + CHAIN_ID)
shutil.move(namada_dir + '/' + CHAIN_ID + '.tar.gz', temp_dir + CHAIN_ID + '.tar.gz')

def allow_duplicate_ips(config_toml):
    config = toml.load(config_toml)
    config['ledger']['cometbft']['p2p']['allow_duplicate_ip'] = True
    toml.dump(config, open(config_toml, 'w'))

def join_network(base_dir, genesis_validator):
    
    if genesis_validator:
        PRE_GENESIS_PATH = '.localnet' + '/src/pre-genesis/' + genesis_validator
        if not os.path.isdir(PRE_GENESIS_PATH) or not os.listdir(PRE_GENESIS_PATH):
            print(f"Cannot find pre-genesis directory that is not empty at {PRE_GENESIS_PATH}")
            sys.exit(1)

    if os.path.isdir(base_dir + '/' + CHAIN_ID):
        shutil.rmtree(base_dir + '/' + CHAIN_ID)
    if genesis_validator:
        system(f"NAMADA_NETWORK_CONFIGS_DIR='{temp_dir}' {namadac_bin} --base-dir='{base_dir}' utils join-network --chain-id {CHAIN_ID} --genesis-validator {genesis_validator} --pre-genesis-path {PRE_GENESIS_PATH} --dont-prefetch-wasm")
    else:
        system(f"NAMADA_NETWORK_CONFIGS_DIR='{temp_dir}' {namadac_bin} --base-dir='{base_dir}' utils join-network --chain-id {CHAIN_ID} --dont-prefetch-wasm")

    shutil.rmtree(base_dir + '/' + CHAIN_ID + '/wasm/')
    shutil.copytree(temp_dir + CHAIN_ID + '/wasm/', base_dir + '/' + CHAIN_ID + '/wasm/')
    # shutil.rmtree(temp_dir + '/' + CHAIN_ID + '/wasm/')
    genesis_wallet_toml = localnet_dir + '/src/pre-genesis' + '/wallet.toml'
    wallet = base_dir + '/' + CHAIN_ID + '/wallet.toml'
    move_genesis_wallet(genesis_wallet_toml, wallet)
    allow_duplicate_ips(base_dir + '/' + CHAIN_ID + '/config.toml')




if len(BASE_DIRS)> 0:
    print("Joining the network with the following base directories:")
    print(BASE_DIRS)
    val_count = 0
    for base_dir in BASE_DIRS:
        genesis_validator=None
        if val_count < args.num_vals:
            genesis_validator=f'validator-{val_count}'
            val_count += 1
        join_network(base_dir, genesis_validator)

else:
    GENESIS_VALIDATOR='validator-0'
    join_network(BASE_DIR, GENESIS_VALIDATOR)
# Delete the temp dir
shutil.rmtree(temp_dir)

# Move the genesis wallet to the base dir

# Remove the temporary transaction folder
shutil.rmtree(TEMPLATES_PATH)

if len(BASE_DIRS)> 0:
    for base_dir in BASE_DIRS:
        full_base_dir = namada_dir + '/' + base_dir
        print("---------------------------------------------------------------------------")
        print(f"{namada_bin} --base-dir='{full_base_dir}' --chain-id '{CHAIN_ID}' ledger run")
    print("---------------------------------------------------------------------------")
    print("Clean up everything by running:")
    print(f"rm -rf .namada-*")
else:
    print("Run the ledger using the following commands:")
    print("---------------------------------------------------------------------------")
    print(f"{namada_bin} --base-dir='{BASE_DIR}' --chain-id '{CHAIN_ID}' ledger run")
    print("---------------------------------------------------------------------------")
    print("Clean up everything by running:")
system(f"rm -rf .localnet")