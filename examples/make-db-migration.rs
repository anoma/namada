use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::{HEXLOWER, HEXUPPER};
use namada_apps_lib::wasm_loader::read_wasm;
use namada_macros::BorshDeserializer;
use namada_parameters::storage;
use namada_sdk::address::Address;
use namada_sdk::hash::Hash as CodeHash;
use namada_sdk::masp_primitives::asset_type::AssetType;
use namada_sdk::masp_primitives::convert::AllowedConversion;
use namada_sdk::masp_primitives::merkle_tree::FrozenCommitmentTree;
use namada_sdk::masp_primitives::sapling;
use namada_sdk::migrations;
use namada_sdk::proof_of_stake::Epoch;
use namada_sdk::storage::{DbColFam, Key};
use namada_sdk::token::{Denomination, MaspDigitPos};
use namada_shielded_token::storage_key::masp_token_map_key;
use namada_shielded_token::ConversionState;
use namada_trans_token::storage_key::{balance_key, minted_balance_key};
use namada_trans_token::Amount;

pub const OLD_CONVERSION_STATE_TYPE_HASH: &str =
    "05E2FD0BEBD54A05AAE349BBDE61F90893F09A72850EFD4F69060821EC5DE65F";

#[derive(
    Debug, Default, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
pub struct NewConversionState {
    /// The last amount of the native token distributed
    pub normed_inflation: Option<u128>,
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<sapling::Node>,
    /// Map assets to their latest conversion and position in Merkle tree
    #[allow(clippy::type_complexity)]
    pub assets: BTreeMap<
        AssetType,
        (
            (Address, Denomination, MaspDigitPos),
            Epoch,
            AllowedConversion,
            usize,
        ),
    >,
}

impl From<ConversionState> for NewConversionState {
    fn from(value: ConversionState) -> Self {
        Self {
            normed_inflation: value.normed_inflation,
            tree: value.tree,
            assets: value.assets,
        }
    }
}

#[allow(dead_code)]
fn example() {
    let person =
        Address::decode("tnam1q9rhgyv3ydq0zu3whnftvllqnvhvhm270qxay5tn")
            .unwrap();
    let nam = Address::decode("tnam1qxgfw7myv4dh0qna4hq0xdg6lx77fzl7dcem8h7e")
        .unwrap();
    let apfel = "tnam1qyvfwdkz8zgs9n3qn9xhp8scyf8crrxwuq26r6gy".to_string();
    let amount = Amount::native_whole(3200000036910u64);
    let minted_key = minted_balance_key(&nam);
    let minted_value = Amount::from(117600000504441u64);

    let updates = [
        migrations::DbUpdateType::Add {
            key: balance_key(&nam, &person),
            cf: DbColFam::SUBSPACE,
            value: amount.into(),
            force: false,
        },
        migrations::DbUpdateType::Add {
            key: minted_key,
            cf: DbColFam::SUBSPACE,
            value: minted_value.into(),
            force: false,
        },
        migrations::DbUpdateType::RepeatDelete(apfel, DbColFam::SUBSPACE),
    ];
    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    std::fs::write("migrations.json", serde_json::to_string(&changes).unwrap())
        .unwrap();
}

fn main() {
    se_migration()
}

// The current vp_user hash to be replaced on the SE
const REMOVED_HASH: &str =
    "129EE7BEE68B02BFAE638DA2A634B8ECBFFA2CB3F46CFA8E172BAF009627EC78";
fn se_migration() {
    // Get VP
    let wasm_path = "wasm";
    let bytes = read_wasm(wasm_path, "vp_user.wasm").expect("bingbong");
    let vp_hash = CodeHash::sha256(&bytes);

    // account VPs
    let account_vp_str = "#tnam[a-z,0-9]*\\/\\?".to_string();
    let accounts_update = migrations::DbUpdateType::RepeatAdd {
        pattern: account_vp_str,
        cf: DbColFam::SUBSPACE,
        value: migrations::UpdateValue::raw(vp_hash),
        force: false,
    };

    // wasm/hash and wasm/name
    let wasm_name_key = Key::wasm_code_name("vp_user.wasm".to_string());
    let wasm_hash_key = Key::wasm_hash("vp_user.wasm");
    let wasm_name_update = migrations::DbUpdateType::Add {
        key: wasm_name_key,
        cf: DbColFam::SUBSPACE,
        value: migrations::UpdateValue::raw(vp_hash),
        force: false,
    };
    let wasm_hash_update = migrations::DbUpdateType::Add {
        key: wasm_hash_key,
        cf: DbColFam::SUBSPACE,
        value: migrations::UpdateValue::raw(vp_hash),
        force: false,
    };

    // wasm/code/<uc hash>
    let code_key = Key::wasm_code(&vp_hash);
    let code_update = migrations::DbUpdateType::Add {
        key: code_key,
        cf: DbColFam::SUBSPACE,
        value: migrations::UpdateValue::raw(bytes.clone()),
        force: false,
    };

    // wasm/len/<code len>
    let len_key = Key::wasm_code_len(&vp_hash);
    let code_len_update = migrations::DbUpdateType::Add {
        key: len_key,
        cf: DbColFam::SUBSPACE,
        value: (bytes.len() as u64).into(),
        force: false,
    };

    // VP allowlist
    let vp_allowlist_key = storage::get_vp_allowlist_storage_key();
    let new_hash_str = HEXLOWER.encode(vp_hash.as_ref());
    let new_vp_allowlist = vec![
        "8781c170ad1e3d2bbddc308b77b7a2edda3fff3bc5d746232feec968ee4fe3cd"
            .to_string(),
        new_hash_str,
    ];
    let allowlist_update = migrations::DbUpdateType::Add {
        key: vp_allowlist_key,
        cf: DbColFam::SUBSPACE,
        value: new_vp_allowlist.into(),
        force: false,
    };

    // remove keys associated with old wasm
    let remove_old_wasm = migrations::DbUpdateType::RepeatDelete(
        format!("/wasm/[a-z]+/{}", REMOVED_HASH),
        DbColFam::SUBSPACE,
    );

    // Conversion state token map
    let conversion_token_map: BTreeMap<String, Address> = BTreeMap::new();
    let conversion_token_map_key = masp_token_map_key();
    let conversion_state_token_map_update = migrations::DbUpdateType::Add {
        key: conversion_token_map_key,
        cf: DbColFam::SUBSPACE,
        value: migrations::UpdateValue::wrapped(conversion_token_map),
        force: false,
    };

    // Conversion state
    let query_result = std::fs::read_to_string("conversion_state.txt").unwrap();
    let hex_bytes = query_result.split('\n').nth(2).unwrap();
    let bytes = HEXUPPER
        .decode(
            hex_bytes
                .strip_prefix("The value in bytes is ")
                .unwrap()
                .trim()
                .as_bytes(),
        )
        .unwrap();
    let old_conversion_state = ConversionState::try_from_slice(&bytes).unwrap();
    let new_conversion_state: NewConversionState = old_conversion_state.into();
    let conversion_state_update = migrations::DbUpdateType::Add {
        key: Key::parse("conversion_state").unwrap(),
        cf: DbColFam::STATE,
        value: migrations::UpdateValue::force_borsh(new_conversion_state),
        force: true,
    };

    let updates = [
        accounts_update,
        wasm_name_update,
        wasm_hash_update,
        code_update,
        allowlist_update,
        code_len_update,
        remove_old_wasm,
        conversion_state_token_map_update,
        conversion_state_update,
    ];

    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    std::fs::write("migrations.json", serde_json::to_string(&changes).unwrap())
        .unwrap();
}
