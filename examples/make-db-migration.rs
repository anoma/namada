use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use namada_macros::BorshDeserializer;
use namada_sdk::address::Address;
use namada_sdk::ibc::trace::ibc_token;
use namada_sdk::masp_primitives::asset_type::AssetType;
use namada_sdk::masp_primitives::merkle_tree::FrozenCommitmentTree;
use namada_sdk::masp_primitives::sapling;
use namada_sdk::migrations;
use namada_sdk::storage::DbColFam;
use namada_shielded_token::storage_key::masp_reward_precision_key;
use namada_shielded_token::{ConversionLeaf, ConversionState};
use namada_trans_token::storage_key::{balance_key, minted_balance_key};
use namada_trans_token::{Amount, Store};

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

// Demonstrate how to set the minted balance using a migration
fn minted_balance_migration() {
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
    std::fs::write(
        "minted_balance_migration.json",
        serde_json::to_string(&changes).unwrap(),
    )
    .unwrap();
}

// Demonstrate how to set the shielded reward precision of IBC tokens using a
// migration
fn shielded_reward_precision_migration() {
    pub type ChannelId = &'static str;
    pub type BaseToken = &'static str;
    pub type Precision = u128;

    const IBC_TOKENS: [(ChannelId, BaseToken, Precision); 6] = [
        ("channel-1", "uosmo", 1000u128),
        ("channel-2", "uatom", 1000u128),
        ("channel-3", "utia", 1000u128),
        ("channel-0", "stuosmo", 1000u128),
        ("channel-0", "stuatom", 1000u128),
        ("channel-0", "stutia", 1000u128),
    ];

    let mut updates = Vec::new();
    // Set IBC token shielded reward precisions
    for (channel_id, base_token, precision) in IBC_TOKENS {
        let ibc_denom = format!("transfer/{channel_id}/{base_token}");
        let token_address = ibc_token(&ibc_denom).clone();

        // The key holding the shielded reward precision of current token
        let shielded_token_reward_precision_key =
            masp_reward_precision_key::<Store<()>>(&token_address);

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_reward_precision_key,
            cf: DbColFam::SUBSPACE,
            value: precision.into(),
            force: false,
        });
    }

    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    std::fs::write(
        "shielded_reward_precision_migration.json",
        serde_json::to_string(&changes).unwrap(),
    )
    .unwrap();
}

// Generate various migrations
fn main() {
    minted_balance_migration();
    shielded_reward_precision_migration();
}
