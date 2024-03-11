use data_encoding::HEXLOWER;
use namada_apps::wasm_loader::read_wasm;
use namada_parameters::storage;
use namada_sdk::address::Address;
use namada_sdk::hash::Hash as CodeHash;
use namada_sdk::migrations;
use namada_sdk::storage::Key;
use namada_trans_token::storage_key::{balance_key, minted_balance_key};
use namada_trans_token::Amount;

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
            value: amount.into(),
            force: false,
        },
        migrations::DbUpdateType::Add {
            key: minted_key,
            value: minted_value.into(),
            force: false,
        },
        migrations::DbUpdateType::RepeatDelete(apfel),
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

// TODO: put in the correct hash
const REMOVED_HASH: &str = "000000000000000000000000000000000000000";
fn se_migration() {
    // Get VP
    let wasm_path = "wasm";
    let bytes = read_wasm(wasm_path, "vp_user.wasm").expect("bingbong");
    let vp_hash = CodeHash::sha256(&bytes);

    // account VPs
    let account_vp_str = "#tnam[a-z,0-9]*\\/\\?".to_string();
    let accounts_update = migrations::DbUpdateType::RepeatAdd {
        pattern: account_vp_str,
        value: migrations::UpdateValue::raw(vp_hash.0.to_vec()),
        force: true,
    };

    // wasm/hash and wasm/name
    let wasm_name_key = Key::wasm_code_name("vp_user.wasm".to_string());
    let wasm_hash_key = Key::wasm_hash("vp_user.wasm");
    let wasm_name_update = migrations::DbUpdateType::Add {
        key: wasm_name_key,
        value: migrations::UpdateValue::raw(vp_hash.0.to_vec()),
        force: true,
    };
    let wasm_hash_update = migrations::DbUpdateType::Add {
        key: wasm_hash_key,
        value: migrations::UpdateValue::raw(vp_hash.0.to_vec()),
        force: true,
    };

    // wasm/code/<uc hash>
    let code_key = Key::wasm_code(&vp_hash);
    let code_update = migrations::DbUpdateType::Add {
        key: code_key,
        value: migrations::UpdateValue::raw(bytes.clone()),
        force: true,
    };

    // wasm/len/<code len>
    let len_key = Key::wasm_code_len(&vp_hash);
    let code_len_update = migrations::DbUpdateType::Add {
        key: len_key,
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
        value: new_vp_allowlist.into(),
        force: false,
    };

    // remove keys associated with old wasm
    let remove_old_wasm = migrations::DbUpdateType::RepeatDelete(format!(
        "/wasm/[a-z]+/{}",
        REMOVED_HASH
    ));

    let updates = [
        accounts_update,
        wasm_name_update,
        wasm_hash_update,
        code_update,
        allowlist_update,
        code_len_update,
        remove_old_wasm,
    ];

    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    std::fs::write("migrations.json", serde_json::to_string(&changes).unwrap())
        .unwrap();
}
