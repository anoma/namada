use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_macros::BorshDeserializer;
use namada_parameters::storage::{
    get_implicit_vp_key, get_vp_allowlist_storage_key,
};
use namada_sdk::address::Address;
use namada_sdk::hash::Hash;
use namada_sdk::masp_primitives::asset_type::AssetType;
use namada_sdk::masp_primitives::merkle_tree::FrozenCommitmentTree;
use namada_sdk::masp_primitives::sapling;
use namada_sdk::migrations;
use namada_sdk::storage::DbColFam;
use namada_shielded_token::{ConversionLeaf, ConversionState};
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
    pub assets: BTreeMap<AssetType, ConversionLeaf>,
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

struct Vp {
    hash: Hash,
    name: &'static str,
    length: u64,
    code: Vec<u8>,
}

fn testnet() {
    const IMPLICIT_VP_HASH: &str =
        "1e3bab5297842be1a3155ae3fe60ccff269f3574726351275efcfca521ac5234";
    const USER_VP_HASH: &str =
        "041e44c075317e00ae4de8535f2ea49496cef91290939b8625dd75a9c8884620";

    let implicit_vp_code = std::fs::read(
        "./vp_implicit.\
         1e3bab5297842be1a3155ae3fe60ccff269f3574726351275efcfca521ac5234.wasm",
    )
    .unwrap();
    let user_vp_code = std::fs::read("./vp_user.041e44c075317e00ae4de8535f2ea49496cef91290939b8625dd75a9c8884620.wasm").unwrap();

    let implicit_vp = Vp {
        hash: IMPLICIT_VP_HASH.try_into().unwrap(),
        name: "vp_implicit.wasm",
        length: 374583,
        code: implicit_vp_code,
    };
    let user_vp = Vp {
        hash: USER_VP_HASH.try_into().unwrap(),
        name: "vp_user.wasm",
        length: 372605,
        code: user_vp_code,
    };

    // Add keys for the two new vps
    let mut updates = vec![];
    for vp in [implicit_vp, user_vp] {
        // 	Wasm code
        updates.push(migrations::DbUpdateType::Add {
            key: namada_sdk::storage::Key::wasm_code(&vp.hash),
            cf: DbColFam::SUBSPACE,
            value: vp.code.into(),
            force: false,
        });
        // 	Wasm code name
        updates.push(migrations::DbUpdateType::Add {
            key: namada_sdk::storage::Key::wasm_code_name(vp.name.to_string()),
            cf: DbColFam::SUBSPACE,
            value: vp.hash.into(),
            force: false,
        });
        // 	Wasm code length
        updates.push(migrations::DbUpdateType::Add {
            key: namada_sdk::storage::Key::wasm_code_len(&vp.hash),
            cf: DbColFam::SUBSPACE,
            value: vp.length.into(),
            force: false,
        });
        // 	Wasm hash
        updates.push(migrations::DbUpdateType::Add {
            key: namada_sdk::storage::Key::wasm_hash(vp.name),
            cf: DbColFam::SUBSPACE,
            value: vp.hash.into(),
            force: false,
        });
    }

    // For implicit vp change the parameter
    updates.push(migrations::DbUpdateType::Add {
        key: get_implicit_vp_key(),
        cf: DbColFam::SUBSPACE,
        value: Hash::try_from(IMPLICIT_VP_HASH).unwrap().into(),
        force: false,
    });

    // Update the vp allowlist (overwrite old hashes with the new ones)
    let vp_allowlist =
        vec![IMPLICIT_VP_HASH.to_string(), USER_VP_HASH.to_string()];
    updates.push(migrations::DbUpdateType::Add {
        key: get_vp_allowlist_storage_key(),
        cf: DbColFam::SUBSPACE,
        value: vp_allowlist.into(),
        force: false,
    });

    // For the user vp, regex on ? subkeys of established addresses
    let pattern = r"#[a-z0-9]{45}\/\?".to_string();
    updates.push(migrations::DbUpdateType::RepeatAdd {
        pattern,
        cf: DbColFam::SUBSPACE,
        value: Hash::try_from(USER_VP_HASH).unwrap().into(),
        force: false,
    });

    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    std::fs::write(
        "testnet_migrations.json",
        serde_json::to_string(&changes).unwrap(),
    )
    .unwrap();
}

fn main() {
    // example()
    testnet()
}
