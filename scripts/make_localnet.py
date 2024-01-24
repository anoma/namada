import toml
import os
import argparse
import subprocess
import sys
import shutil


# Create the parser
parser = argparse.ArgumentParser(description='Builds a localnet for testing purposes')

# Add the arguments
parser.add_argument('--num-vals', type=int, help='Number of validators to include.')
parser.add_argument('--mode', type=str, help='The mode to run the localnet in. Can be release or debug, defaults to debug.')

args = parser.parse_args()

MODE = 'release' if str(args.mode).lower() == 'release' else 'debug'

# Get the absolute path to the directory of the script
script_dir = sys.path[0]
# Get absolute path of parent directory
namada_dir = script_dir[:script_dir.rfind('/')]
namada_bin = f"{namada_dir}/target/{MODE}/namada"

def system(cmd):
    return os.system(cmd)

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def update_balances(localnet_dir, new_addresses):
    balances_file = f"{localnet_dir}/balances.toml"
    balances_toml = toml.load(balances_file)
    for addr in new_addresses:
        balances_toml["token"]["NAM"][addr] = "1000000"
    with open(f"{localnet_dir}/tmp/balances.toml", "w") as f:
        toml.dump(balances_toml, f)

def make_val_wallet(cmd):
    # Start the subprocess
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

    # Send 'p' followed by newline and then close stdin
    # If your command expects just 'p' without a newline, remove '\n'
    try:
    # Send 'p' followed by newline
    # If your command expects just 'p' without a newline, remove '\n'
        out, err = process.communicate(input='p\n')        
    
    finally:
        # Ensure that resources are freed and pipes are closed
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()

    # Check return code (0 usually means success)
    if process.returncode == 0:
        print("Command executed successfully")
    else:
        print("Command failed")

def make_transactions(num_vals):
    new_addresses = []
    for i in range(1, num_vals):
        val_alias = f"validator-{i}"
        unsigned_tx_file_path = f"{TXS_DIR}/{val_alias}-unsigned.toml"
        signed_tx_file_path = f"{TXS_DIR}/{val_alias}-signed.toml"
        # I get prompted to enter the letter p, I want to do that automatically
        make_val_wallet(f"{namada_bin}w --base-dir='{BASE_DIR}' --pre-genesis gen --alias {val_alias} --unsafe-dont-encrypt")

        output = run(f"{namada_bin}c --base-dir '{BASE_DIR}' utils init-genesis-established-account --path {unsigned_tx_file_path} --aliases {val_alias}")
        established_address = output[output.find('tnam'):].strip()[:45]
        assert len(established_address) == len('tnam1q9874ezwewthnq7yku6xgwve0fyh6cvd85j5dxee'), len('tnam1q9874ezwewthnq7yku6xgwve0fyh6cvd85j5dxee')
        new_addresses.append(established_address)
        system(f"{namada_bin}c --base-dir '{BASE_DIR}' utils init-genesis-validator --address {str(established_address).strip()} --alias {val_alias} --net-address 127.0.0.1:2{(7+i) % 10}657 --commission-rate 0.05 --max-commission-rate-change 0.01 --self-bond-amount 1000 --email validator{i}@gmail.com --path {unsigned_tx_file_path} --unsafe-dont-encrypt")
        system(f"{namada_bin}c --base-dir '{BASE_DIR}' utils sign-genesis-txs --path {unsigned_tx_file_path} --output {signed_tx_file_path} --alias {val_alias}")
    update_balances(LOCALNET_DIR, new_addresses)

if __name__ == "__main__":

    # Temp_dir
    TMP_LOCAL = ".localnet"
    system(f"mkdir -p {TMP_LOCAL}")
    # Get the localnet directory
    LOCALNET_DIR = f'{namada_dir}/genesis/localnet'
    # Parse the arguments

    if args.num_vals and args.num_vals > 1:
        num_vals = args.num_vals
    else:
        exit(0)
    
    BASE_DIR = f"{LOCALNET_DIR}/src"
    system(f"cp -r {BASE_DIR} {TMP_LOCAL}")
    BASE_DIR = TMP_LOCAL + "/src"
    # Create txs directory
    TXS_DIR=f"{TMP_LOCAL}/pre-genesis/txs"
    system(f"mkdir -p {TXS_DIR}")

    make_transactions(num_vals)
        
    # Concatenate tx_tomls
    bigass_unsigned_toml = {"established_account": [], "validator_account": [], "bond": []}
    bigass_signed_toml = {"established_account": [], "validator_account": [], "bond": []}
    print(f"Writing to {TXS_DIR}/unsigned_transactions.toml")
    for file in os.listdir(TXS_DIR):
        if file.endswith("-unsigned.toml"):
            tx_toml = toml.load(f"{TXS_DIR}/{file.split('/')[-1]}")
            bigass_unsigned_toml["established_account"].extend(tx_toml["established_account"])
            bigass_unsigned_toml["validator_account"].extend(tx_toml["validator_account"])
            bigass_unsigned_toml["bond"].extend(tx_toml["bond"])
        elif file.endswith("-signed.toml"):
            tx_toml = toml.load(f"{TXS_DIR}/{file.split('/')[-1]}")
            bigass_signed_toml["established_account"].extend(tx_toml["established_account"])
            bigass_signed_toml["validator_account"].extend(tx_toml["validator_account"])
            bigass_signed_toml["bond"].extend(tx_toml["bond"])
    with open(f"{TXS_DIR}/unsigned-transactions.toml", "w") as f:
        toml.dump(bigass_unsigned_toml, f)
    with open(f"{TXS_DIR}/signed-transactions.toml", "w") as f:
        toml.dump(bigass_signed_toml, f)

    shutil.rmtree(f"{TXS_DIR}")

    # Concatenate transactions.toml
    toml_old = toml.load(f"{LOCALNET_DIR}/transactions.toml")
    toml_old["established_account"].extend(bigass_signed_toml["established_account"])
    toml_old["validator_account"].extend(bigass_signed_toml["validator_account"])
    toml_old["bond"].extend(bigass_signed_toml["bond"])
    with open(f"{LOCALNET_DIR}/tmp/transactions.toml", "w") as f:
        toml.dump(toml_old, f)
