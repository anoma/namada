import toml
import os
from collections import defaultdict
import pandas as pd
import re
import bech32


def rename_column(c):
    if "tpknam1" in c.lower() and "expedition" in c.lower():
        return "public_key"
    elif "email" in c.lower():
        return "email"
    elif "tnam1" in c.lower() and "expedition" in c.lower():
        return "address"
    elif "discordname" == c.lower() or "discord_name" == c.lower() or "discord display name" == c.lower():
        return "discord_handle"
    else:
        return None

def drop_unimportant_columns(df, important_columns):
    return df[important_columns].copy()

def drop_duplicate_public_keys(df):
    return df.drop_duplicates(subset=["public_key"])

def reveal_stupidity(pk):
    if str(pk).isalnum():
        if not str(pk).startswith("tpknam1q"):
            print("This guy is also a dumbass", pk)
            return False
        return True
    else:
        print("This guy is a dumbass", pk)
        return False

def is_bech32(pk):
    if re.sub(r'\W+', '', pk.strip()).lower() not in ["tpknam1qp0qs42asyw6mm3a5krd5c6ehukmx0rfsq6kthq0642tt3xeygsvy9v6s35",
"tpknam1qzhf46xkfwngxzxvjgluz5jveqg29rltfpvkrn6xjzge717xf2pzwf7kj48",
"tpknam1qzxrcx172qrup9h8puf1766mu3ns5qts779np6xsvlknq7sy2f45kta6kud",
"tpknam1qzmg8usrmc6r25ma4h8emfkzj4w7jvms4qcv73gerfhw6egfee78zqsq3dy"]:
        return True
    else:
        print(pk)
        return False
    

def check_public_key(df, df_name = "pilot"):
    starts_with_tpknam = df["public_key"].str.startswith("tpknam")
    if not starts_with_tpknam.all():
        # print(f"WARNING: not all public keys start with tpknam for df {df_name}")
        # print(len(df[~starts_with_tpknam]["public_key"].tolist()))

        # print(f"The following discord names have public keys that do not start with tpknam for df {df_name}")
        # print(df[~starts_with_tpknam]["discord_handle"].tolist())
        pass
    
    df = df[df["public_key"].str.startswith("tpknam1")].copy()
    df = df[df['public_key'].apply(reveal_stupidity)].copy()
    df = df[df['public_key'].apply(is_bech32)].copy()
    return df

balances = {"token": {"NAAN": {}}} # NAAN is the token symbol for the shielded expedition

pilots_csv = pd.read_csv("pilot.csv")
vals_csv = pd.read_csv("validators.csv")
crew_csv = pd.read_csv("crew.csv")

def clean(df, df_name = "pilot"):
    columns = df.columns.tolist()
    important_columns = [c for c in columns if any(x in c.lower() for x in ["tpknam1", "email", "tnam1", "discord"])]
    important_columns = [c for c in important_columns if c != "DiscordName.1"]
    new_columns = [rename_column(c) for c in columns if rename_column(c) is not None]
    df = drop_unimportant_columns(df, important_columns)
    df = df.rename(columns= {k:v for k,v in zip(important_columns, new_columns)})
    df = drop_duplicate_public_keys(df)
    df = check_public_key(df, df_name)
    return df


pilots_csv = clean(pilots_csv, "pilot")
vals_csv = clean(vals_csv, "vals")
crew_csv = clean(crew_csv, "crew")


assert pilots_csv.columns.tolist() == ["discord_handle", "email", "public_key", "address"], pilots_csv.columns.tolist()
assert vals_csv.columns.tolist() == ["discord_handle", "email", "public_key", "address"], vals_csv.columns.tolist()
assert crew_csv.columns.tolist() == ["discord_handle", "email", "public_key", "address"], crew_csv.columns.tolist()

assert pilots_csv["public_key"].nunique() == len(pilots_csv), "public keys of pilots are not unique. These are the duplicates: \n" + str(pilots_csv[pilots_csv["public_key"].duplicated()]["public_key"].tolist())
assert vals_csv["public_key"].nunique() == len(vals_csv), "public keys of validators are not unique. These are the duplicates: \n" + str(vals_csv[vals_csv["public_key"].duplicated()]["public_key"].tolist()) + f". There are {vals_csv['public_key'].duplicated().sum()} duplicates."
assert crew_csv["public_key"].nunique() == len(crew_csv), "public keys of crew are not unique. These are the duplicates: \n" + str(crew_csv[crew_csv["public_key"].duplicated()]["public_key"].tolist())

assert pilots_csv["public_key"].isna().sum() == 0, f"public keys of pilots are missing entries. {pilots_csv['public_key'].isna().sum()} missing entries"
assert vals_csv["public_key"].isna().sum() == 0, f"public keys of validators are missing entries. {vals_csv['public_key'].isna().sum()} missing entries"
assert crew_csv["public_key"].isna().sum() == 0, f"public keys of crew are missing entries. {crew_csv['public_key'].isna().sum()} missing entries"

STAKE_TOTAL = 1_000_000_000.00
PILOT_SHARE = float(1/3)
EMERGENCIES_SHARE = float(1/3)
VAL_SHARE = 0.15
CREW_SHARE = 0.15
HELIAX_SHARE = 0.00001
FAUCET_SHARE =  1 - sum([PILOT_SHARE, EMERGENCIES_SHARE, VAL_SHARE, CREW_SHARE, HELIAX_SHARE])

FULL_SHARE = sum([PILOT_SHARE, EMERGENCIES_SHARE, VAL_SHARE, CREW_SHARE, HELIAX_SHARE, FAUCET_SHARE])
assert FULL_SHARE == 1, f"Shares do not add up to 1. They add up to {FULL_SHARE}"

faucet_pk = "tpknam1qz52su4kfr294egn3t6pc9dt0lp5khap3f69y4xzy3cl84js8ckg639u6nr"
recovery_pk = "tpknam1qzvszv50azclqa05reqveehkwknpl4kh6tn3vajpt0vusa8mjpluk89ac03"
heliax_pk = "tpknam1qrjdcswdy2p3m00lk26jdxzt7d7lmlkhheeaw6qngxla47ampar67qn47nt"

def drop_intersect(df1, df2):
    common_keys = set(df1["public_key"].tolist()) & set(df2["public_key"].tolist())
    new_df = df2[~df2["public_key"].isin(common_keys)].copy()
    return new_df

vals_csv = drop_intersect(pilots_csv, vals_csv)
crew_csv= drop_intersect(pilots_csv, crew_csv)

if VAL_SHARE / len(vals_csv) > CREW_SHARE / len(crew_csv):
    crew_csv = drop_intersect(vals_csv, crew_csv)
else:
    vals_csv = drop_intersect(crew_csv, vals_csv)



pilot_stake_dict = {re.sub(r'\W+', '', str(row["public_key"])).lower(): (STAKE_TOTAL * PILOT_SHARE / len(pilots_csv)) for _, row in pilots_csv.iterrows()}
vals_stake_dict = {re.sub(r'\W+', '', str(row["public_key"])).lower(): (STAKE_TOTAL * VAL_SHARE / len(vals_csv)) for _, row in vals_csv.iterrows()}
crew_stake_dict = {re.sub(r'\W+', '', str(row["public_key"])).lower(): (STAKE_TOTAL * CREW_SHARE / len(crew_csv)) for _, row in crew_csv.iterrows()}
faucet_pk_dict = {faucet_pk: (STAKE_TOTAL * FAUCET_SHARE )}
recovery_pk_dict = {recovery_pk: (STAKE_TOTAL * EMERGENCIES_SHARE )}
heliax_pk_dict = {heliax_pk: (STAKE_TOTAL * HELIAX_SHARE )}
stake_pk_dict = {**pilot_stake_dict, **vals_stake_dict, **crew_stake_dict, **faucet_pk_dict, **recovery_pk_dict, **heliax_pk_dict}

print("------------------------------------------------------------------------------------")
for pk, stake in stake_pk_dict.items():
    if pk == "tpknamıqqxly2aqtgphrkkg5pqaryzrwneqq22gt5oozu73lgkzqvdexqnqsjksj4k" in pk:
        pk_new = pk.replace("ı", "1")
        balances["token"]["NAAN"][pk_new] = "{:.6f}".format(stake)
    else:
        balances["token"]["NAAN"][pk] = "{:.6f}".format(stake)

additional_stake = STAKE_TOTAL - sum([float(v) for v in balances["token"]["NAAN"].values()])
balances["token"]["NAAN"][faucet_pk] = "{:.6f}".format(float(balances["token"]["NAAN"][faucet_pk]) + additional_stake)

print("Total sum of stake is", sum([float(v) for v in balances["token"]["NAAN"].values()]))

print("------------------------------------------------------------------------------------")
toml.dump(balances, open("balances.toml", "w"))
import json
json.dump(list(balances["token"]["NAAN"].keys()), open("balances.json", "w"))