use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::convert::AllowedConversion;
use masp_primitives::transaction::components::I128Sum;
use namada_core::masp::encode_asset_type;
use namada_macros::BorshDeserializer;
use namada_migrations::REGISTER_DESERIALIZERS;
use namada_sdk::address::Address;
use namada_sdk::ibc::trace::ibc_token;
use namada_sdk::masp_primitives::asset_type::AssetType;
use namada_sdk::masp_primitives::merkle_tree::FrozenCommitmentTree;
use namada_sdk::masp_primitives::sapling;
use namada_sdk::migrations;
use namada_sdk::storage::DbColFam;
use namada_shielded_token::storage_key::{
    masp_conversion_key, masp_reward_precision_key,
};
use namada_shielded_token::{ConversionLeaf, ConversionState, MaspEpoch};
use namada_trans_token::storage_key::{balance_key, minted_balance_key};
use namada_trans_token::{Amount, Denomination, MaspDigitPos, Store};

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

// Demonstrate clearing MASP rewards for the given IBC tokens by overwriting
// their allowed conversions with conversions that do not contain rewards.
fn shielded_reward_reset_migration() {
    pub type ChannelId = &'static str;
    pub type BaseToken = &'static str;
    // Valid precisions must be in the intersection of i128 and u128
    pub type Precision = i128;

    // The MASP epoch in which this migration will be applied. This number
    // controls the number of epochs of conversions created.
    const TARGET_MASP_EPOCH: MaspEpoch = MaspEpoch::new(2000);
    // The denomination of the targetted token. Since all tokens here are IBC
    // tokens, this is 0.
    const DENOMINATION: Denomination = Denomination(0u8);
    // The tokens whose rewarrds will be reset.
    const IBC_TOKENS: [(ChannelId, BaseToken, Precision); 6] = [
        ("channel-1", "uosmo", 1000i128),
        ("channel-2", "uatom", 1000i128),
        ("channel-3", "utia", 1000i128),
        ("channel-0", "stuosmo", 1000i128),
        ("channel-0", "stuatom", 1000i128),
        ("channel-0", "stutia", 1000i128),
    ];

    let mut updates = Vec::new();
    // Reset the allowed conversions for the above tokens
    for (channel_id, base_token, precision) in IBC_TOKENS {
        let ibc_denom = format!("transfer/{channel_id}/{base_token}");
        let token_address = ibc_token(&ibc_denom).clone();

        // Erase the TOK rewards that have been distributed so far
        let mut asset_types = BTreeMap::new();
        let mut precision_toks = BTreeMap::new();
        let mut reward_deltas = BTreeMap::new();
        // TOK[ep, digit]
        let mut asset_type = |epoch, digit| {
            *asset_types.entry((epoch, digit)).or_insert_with(|| {
                encode_asset_type(
                    token_address.clone(),
                    DENOMINATION,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type")
            })
        };
        // PRECISION TOK[ep, digit]
        let mut precision_tok = |epoch, digit| {
            precision_toks
                .entry((epoch, digit))
                .or_insert_with(|| {
                    AllowedConversion::from(I128Sum::from_pair(
                        asset_type(epoch, digit),
                        precision,
                    ))
                })
                .clone()
        };
        // -PRECISION TOK[ep, digit] + PRECISION TOK[ep+1, digit]
        let mut reward_delta = |epoch, digit| {
            reward_deltas
                .entry((epoch, digit))
                .or_insert_with(|| {
                    -precision_tok(epoch, digit)
                        + precision_tok(epoch.next().unwrap(), digit)
                })
                .clone()
        };
        // The key holding the shielded reward precision of current token
        let shielded_token_reward_precision_key =
            masp_reward_precision_key::<Store<()>>(&token_address);

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_reward_precision_key,
            cf: DbColFam::SUBSPACE,
            value: (precision as u128).into(),
            force: false,
        });
        // Write the new TOK conversions to memory
        for digit in MaspDigitPos::iter() {
            // -PRECISION TOK[ep, digit] + PRECISION TOK[current_ep, digit]
            let mut reward: AllowedConversion = I128Sum::zero().into();
            for epoch in MaspEpoch::iter_bounds_inclusive(
                MaspEpoch::zero(),
                TARGET_MASP_EPOCH.prev().unwrap(),
            )
            .rev()
            {
                // TOK[ep, digit]
                let asset_type = encode_asset_type(
                    token_address.clone(),
                    DENOMINATION,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type");
                reward += reward_delta(epoch, digit);
                // Write the conversion update to memory
                updates.push(migrations::DbUpdateType::Add {
                    key: masp_conversion_key(&asset_type),
                    cf: DbColFam::SUBSPACE,
                    value: reward.clone().into(),
                    force: false,
                });
            }
        }
    }

    let changes = migrations::DbChanges {
        changes: updates.into_iter().collect(),
    };
    std::fs::write(
        "shielded_reward_reset_migration.json",
        serde_json::to_string(&changes).unwrap(),
    )
    .unwrap();
}

// Generate various migrations
fn main() {
    minted_balance_migration();
    shielded_reward_precision_migration();
    shielded_reward_reset_migration();
}
