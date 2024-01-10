import toml
from collections import defaultdict
import pandas as pd
import re


# CONSTANTS
# 1. Define the shares
# -----------------------------------------------------------------------------------------------------------
STAKE_TOTAL = 1_000_000_000.00
PILOT_SHARE = float(1/3) # 33%
FAUCET_2_SHARE = float(1/3) # 33%
VAL_SHARE = 0.15 # 15%
CREW_SHARE = 0.15 # 15%
HELIAX_SHARE = 0.00001 # 0.001% i.e 10K NAAN for heliax
FAUCET_SHARE =  1 - sum([PILOT_SHARE, FAUCET_2_SHARE, VAL_SHARE, CREW_SHARE, HELIAX_SHARE]) # The rest
# -----------------------------------------------------------------------------------------------------------
# 2. Define the heliax public keys
FAUCET_PK = "tpknam1qz52su4kfr294egn3t6pc9dt0lp5khap3f69y4xzy3cl84js8ckg639u6nr"
FAUCET_2_PK = "tpknam1qzvszv50azclqa05reqveehkwknpl4kh6tn3vajpt0vusa8mjpluk89ac03"
HELIAX_PK = "tpknam1qrjdcswdy2p3m00lk26jdxzt7d7lmlkhheeaw6qngxla47ampar67qn47nt"


# -----------------------------------------------------------------------------------------------------------
"""This file takes the 3 raw csvs and processes them. The columns in the original csv are:"""
"""
PILOTS = ['#',
'DiscordName',
'Allocation (NAAN)',
'Add a link to your GitHub user profile',
'Organization Name',
'Organization Website',
'What is your email address?',
'Pick a moniker',
'Enter your Namada Public Key (tpknam1...) for the SHIELDED EXPEDITION',
'Enter your Namada Transparent Account (tnam1...) for the SHIELDED EXPEDITION',
'OPTIONAL: Enter a different Namada Public Key for MAINNET',
'OPTIONAL: Enter a different Namada Transparent Account for MAINNET']
"""
"""CREW =
['Submission Timestamp',
'Twitter Username',
'Twitter Account Created At',
'Twitter Follower Count',
'Twitter Following Count',
'Twitter Tweet Count',
'Discord Display Name',
'Add a link to your github user profile',
'Organization Name',
'Organization Website',
'What is your email address?',
'Pick a moniker',
'OPTIONAL: Link to a profile picture image',
'Enter your Namada Public Key (tpknam1...) for the SHIELDED EXPEDITION',
'Enter your Namada Transparent Account (tnam1...) for the SHIELDED EXPEDITION',
'OPTIONAL: Enter a different Namada Public Key for MAINNET',
'OPTIONAL: Enter a different Namada Transparent Account for MAINNET',
'Terms and Conditions'] 
"""
"""VALS =
['Submission Timestamp',
'Twitter Username',
'Twitter Account Created At',
'Twitter Follower Count',
'Twitter Following Count',
'Twitter Tweet Count',
'Discord Display Name',
'Add a link to your GitHub user profile',
'Organization Name',
'Organization Website',
'What is your email address?',
'Pick a moniker',
'Enter your Namada Public Key (tpknam1...) for the SHIELDED EXPEDITION',
'Enter your Namada Transparent Account (tnam1...) for the SHIELDED EXPEDITION',
'OPTIONAL: Enter a different Namada Public Key for MAINNET',
'OPTIONAL: Enter a different Namada Transparent Account for MAINNET',
'Have you been involved with Namada?',
'Public Testnet',
'Public Testnet TOML file',
'How many Namada public testnets did you participate in?',
'Have you made a contribution to Namada?',
'Namada contribution URL',
'Community, protocol, or governance contribution',
'Reputation',
'Operational capacity',
'Experience',
'Shielded Expedition responsiveness',
'Infrastructure',
'Geography',
'Monitoring and Alerting',
'Mainnet Security Measures',
'OPTIONAL: References and Testimonials',
'OPTIONAL: Audit and Compliance',
'OPTIONAL: Mainnet Technical Documentation',
'Terms and Conditions']
"""
# -----------------------------------------------------------------------------------------------------------


def rename_column(column_name):
    """Renames a column based on predefined criteria for readability."""
    column_name_lower = column_name.lower()
    if "tpknam1" in column_name_lower and "expedition" in column_name_lower:
        return "public_key"
    elif "email" in column_name_lower:
        return "email"
    elif "tnam1" in column_name_lower and "expedition" in column_name_lower:
        return "address"
    elif column_name_lower in ["discordname", "discord_name", "discord display name"]:
        return "discord_handle"
    return None

def drop_unimportant_columns(df, important_columns):
    """Drops columns from the dataframe that are not in the list of important columns."""
    return df[important_columns].copy()

def drop_duplicate_public_keys(df):
    """Drops duplicate public keys from the dataframe."""
    return df.drop_duplicates(subset=["public_key"])

def check_alphanumeric(public_key):
    """Checks if the public key is alphanumeric and starts with a specific prefix."""
    if not str(public_key).startswith("tpknam1q"):
        print(f"This pk does not have a q: {public_key}")
    is_alnum = str(public_key).isalnum()
    if not is_alnum:
        print(f"This pk is not alphanumeric: {public_key}")
    return is_alnum

# These are hardcoded addresses that are not bech32 and checked using a rust script. Jacob ran a script to determine this blacklist.
def is_blacklisted(pk):
    if re.sub(r'\W+', '', pk.strip()).lower() not in ["tpknam1qp0qs42asyw6mm3a5krd5c6ehukmx0rfsq6kthq0642tt3xeygsvy9v6s35",
                                                        "tpknam1qzhf46xkfwngxzxvjgluz5jveqg29rltfpvkrn6xjzge717xf2pzwf7kj48",
                                                        "tpknam1qzxrcx172qrup9h8puf1766mu3ns5qts779np6xsvlknq7sy2f45kta6kud",
                                                        "tpknam1qzmg8usrmc6r25ma4h8emfkzj4w7jvms4qcv73gerfhw6egfee78zqsq3dy"]:
        return True
    else:
        print(f"pruning {pk} because it was blacklisted")
        return False
    

def check_public_key(df, df_name="pilot"):
    """Checks the validity of public keys in the dataframe."""
    starts_with_prefix = df["public_key"].str.startswith("tpknam1")
    if not starts_with_prefix.all():
        problematic_pks = len(df[~starts_with_prefix]['public_key'].tolist())
        print(f"WARNING: not all public keys start with tpknam for df {df_name}")
        print(f"The number of public keys with this problem is {problematic_pks}")
    
    df = df[starts_with_prefix & df['public_key'].apply(check_alphanumeric) & df['public_key'].apply(is_blacklisted)].copy()
    return df

# This cleans the csvs since the initial columns are a bit wonky.
def clean(df, df_name = "pilot"):
    columns = df.columns.tolist()
    # These are the columns that are important
    important_columns = [c for c in columns if any(x in c.lower() for x in ["tpknam1", "email", "tnam1", "discord"])]
    # Some dfs have 2 discord columns, so we drop one of them
    important_columns = [c for c in important_columns if c != "DiscordName.1"]
    # These are the new column names that we want
    new_columns = [rename_column(c) for c in columns if rename_column(c) is not None]
    # Drop the unimportant columns
    df = drop_unimportant_columns(df, important_columns)
    # Rename the columns
    df = df.rename(columns= {k:v for k,v in zip(important_columns, new_columns)})
    # Drop all duplicate public keys
    df = drop_duplicate_public_keys(df)
    # Check if the public keys are valid
    df = check_public_key(df, df_name)
    return df

# This drops all public keys that are in both dataframes from the second dataframe, and keeps leaves the first dataframe unchanged
def drop_intersect(df1, df2):
    # Find the common keys between the two dataframes
    common_keys = set(df1["public_key"].tolist()) & set(df2["public_key"].tolist())
    # Drop the common keys from the second dataframe
    new_df = df2[~df2["public_key"].isin(common_keys)].copy()
    # Return the new df2
    return new_df


def read_csv_files():
    """Reads CSV files and returns DataFrames."""
    pilots_csv = pd.read_csv("pilot.csv")
    vals_csv = pd.read_csv("validators.csv")
    crew_csv = pd.read_csv("crew.csv")
    return pilots_csv, vals_csv, crew_csv

def validate_dataframes(pilots_csv, vals_csv, crew_csv):
    """Validates the columns and uniqueness of public keys in the dataframes."""
    expected_columns = ["discord_handle", "email", "public_key", "address"]

    assert pilots_csv.columns.tolist() == expected_columns, f"Columns mismatch in pilots CSV: {pilots_csv.columns.tolist()}"
    assert vals_csv.columns.tolist() == expected_columns, f"Columns mismatch in validators CSV: {vals_csv.columns.tolist()}"
    assert crew_csv.columns.tolist() == expected_columns, f"Columns mismatch in crew CSV: {crew_csv.columns.tolist()}"

    for df, role in zip([pilots_csv, vals_csv, crew_csv], ["pilots", "validators", "crew"]):
        assert df["public_key"].nunique() == len(df), f"Public keys of {role} are not unique."
        assert df["public_key"].isna().sum() == 0, f"Public keys of {role} are missing entries."

def calculate_stake(df, total_stake, share):
    """Calculates the stake for each public key in the dataframe."""
    return {re.sub(r'\W+', '', str(row["public_key"])).lower(): (total_stake * share / len(df)) for _, row in df.iterrows()}

def combine_stakes(*dicts):
    """Combines multiple dictionaries into one."""
    combined = {}
    for dictionary in dicts:
        combined.update(dictionary)
    return combined

def update_balances(balances, stake_pk_dict):
    """Updates the balances dictionary with the stake for each public key."""
    for pk, stake in stake_pk_dict.items():
        balances["token"]["NAAN"][pk] = "{:.6f}".format(stake)

    # Adjust additional stake
    additional_stake = STAKE_TOTAL - sum([float(v) for v in balances["token"]["NAAN"].values()])
    balances["token"]["NAAN"][FAUCET_PK] = "{:.6f}".format(float(balances["token"]["NAAN"][FAUCET_PK]) + additional_stake)

    # Validate total sum
    assert "{:.6f}".format(sum([float(v) for v in balances['token']['NAAN'].values()])) == "{:.6f}".format(STAKE_TOTAL), "Sum of stake is incorrect"

if __name__ == "__main__":
    pilots_csv, vals_csv, crew_csv = read_csv_files()
    print(f"Raw numbers for each csv are {len(pilots_csv)}, {len(vals_csv)}, {len(crew_csv)}")

    pilots_csv, vals_csv, crew_csv = [clean(df, role) for df, role in zip([pilots_csv, vals_csv, crew_csv], ["pilot", "vals", "crew"])]
    validate_dataframes(pilots_csv, vals_csv, crew_csv)
    print("------------------------------------------------------------------------------------")

    # Drop intersecting public keys
    vals_csv = drop_intersect(pilots_csv, vals_csv)
    crew_csv = drop_intersect(pilots_csv, crew_csv)
    crew_csv = drop_intersect(vals_csv, crew_csv)
    print(f"Cleaned numbers for each csv are {len(pilots_csv)}, {len(vals_csv)}, {len(crew_csv)}")

    # Calculate stakes
    pilot_stake_dict = calculate_stake(pilots_csv, STAKE_TOTAL, PILOT_SHARE)
    vals_stake_dict = calculate_stake(vals_csv, STAKE_TOTAL, VAL_SHARE)
    crew_stake_dict = calculate_stake(crew_csv, STAKE_TOTAL, CREW_SHARE)
    faucet_pk_dict = {FAUCET_PK: (STAKE_TOTAL * FAUCET_SHARE)}
    faucet_2_pk_dict = {FAUCET_2_PK: (STAKE_TOTAL * FAUCET_2_SHARE)}
    heliax_pk_dict = {HELIAX_PK: (STAKE_TOTAL * HELIAX_SHARE)}

    # Combine stakes
    stake_pk_dict = combine_stakes(pilot_stake_dict, vals_stake_dict, crew_stake_dict, faucet_pk_dict, faucet_2_pk_dict, heliax_pk_dict)

    print("------------------------------------------------------------------------------------")
    balances = {"token": {"NAAN": {}}}
    update_balances(balances, stake_pk_dict)
    print("Total sum of stake is " + "{:.6f}".format(sum([float(v) for v in balances['token']['NAAN'].values()])))

    print("------------------------------------------------------------------------------------")
    toml.dump(balances, open("balances.toml", "w"))
