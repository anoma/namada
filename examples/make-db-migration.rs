use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_macros::BorshDeserializer;
use namada_sdk::address::Address;
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

fn main() {
    example()
}
