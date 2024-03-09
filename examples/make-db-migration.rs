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

fn se_migration() {
    // TODO: may want to remove some keys corresponding to the old VP and it hash

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
        force: true,
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
        force: true,
    };

    let updates = [
        accounts_update,
        wasm_name_update,
        wasm_hash_update,
        code_update,
        allowlist_update,
        code_len_update,
    ];

    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    std::fs::write("migrations.json", serde_json::to_string(&changes).unwrap())
        .unwrap();
}

#[test]
fn bingbong() {
    let key = storage::get_vp_allowlist_storage_key();
    let type_hash = namada_migrations::foreign_types::HASHVECSTR;
    let hex = HEXUPPER.encode(&type_hash);
    println!("{}", hex);
    println!("{}", key);

    let token_amount_hash = HEXUPPER.encode(&Amount::HASH);
    println!("{}", token_amount_hash);

    let serialized = "0200000040000000383738316331373061643165336432626264646333303862373762376132656464613366666633626335643734363233326665656339363865653466653363644000000031323965653762656536386230326266616536333864613261363334623865636266666132636233663436636661386531373262616630303936323765633738";
    // let serialized = serialized.chars().map(|bing|
    // u8::try_from(bing).unwrap()).collect::<Vec<_>>();
    let serialized = HEXUPPER.decode(serialized.as_bytes()).unwrap();
    let allowlist =
        Vec::<String>::try_from_slice(serialized.as_slice()).unwrap();
    println!("{:?}", allowlist);
}
