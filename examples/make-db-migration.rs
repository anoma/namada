use std::collections::BTreeMap;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::I128Sum;
use namada_core::borsh::BorshSerializeExt;
use namada_core::chain::BlockHeight;
use namada_core::dec::Dec;
use namada_core::hash::Hash;
use namada_core::masp::{Precision, encode_asset_type};
use namada_core::storage::Key;
use namada_core::time::MIN_UTC;
use namada_macros::BorshDeserializer;
use namada_migrations::REGISTER_DESERIALIZERS;
use namada_parameters::EpochDuration;
use namada_parameters::storage::{
    get_epoch_duration_storage_key, get_epochs_per_year_key,
    get_masp_epoch_multiplier_key, get_tx_allowlist_storage_key,
};
use namada_sdk::address::Address;
use namada_sdk::ibc::trace::ibc_token;
use namada_sdk::masp_primitives::asset_type::AssetType;
use namada_sdk::masp_primitives::merkle_tree::FrozenCommitmentTree;
use namada_sdk::masp_primitives::sapling;
use namada_sdk::migrations;
use namada_sdk::storage::DbColFam;
use namada_shielded_token::storage_key::{
    masp_assets_hash_key, masp_conversion_key, masp_kd_gain_key,
    masp_kp_gain_key, masp_locked_amount_target_key, masp_max_reward_rate_key,
    masp_reward_precision_key, masp_scheduled_base_native_precision_key,
    masp_scheduled_reward_precision_key,
};
use namada_shielded_token::{ConversionLeaf, ConversionState, MaspEpoch};
use namada_trans_token::storage_key::{balance_key, minted_balance_key};
use namada_trans_token::{Amount, Denomination, MaspDigitPos, Store};
use sha2::{Digest, Sha256};

/// Represents the channel ID of an IBC token
pub type ChannelId = &'static str;
/// Represents the base token of an IBC token
pub type BaseToken = &'static str;
/// Represents a Namada address in Bech32m encoding
pub type AddressBech32m = &'static str;
/// Represents the hash of a WASM binary
pub type WasmHash = &'static str;
/// Represents the bytes of a WASM binary
pub type WasmBytes = &'static [u8];
/// Represents a maximum reward rate
pub type MaxRewardRate = &'static str;
/// Represents a target locked amount
pub type TargetLockedAmount = u64;
/// Represents a nominal proportional gain
pub type KpGain = &'static str;
/// Represents a nominal derivative gain
pub type KdGain = &'static str;
/// The type hash of the conversion state structure in v0.31.9
pub const OLD_CONVERSION_STATE_TYPE_HASH: &str =
    "05E2FD0BEBD54A05AAE349BBDE61F90893F09A72850EFD4F69060821EC5DE65F";

/// The new conversion state structure after the v0.32.0 upgrade
#[derive(
    Debug, Default, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
pub struct NewConversionState {
    /// The last amount of the native token distributed
    pub current_precision: Option<u128>,
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<sapling::Node>,
    /// Map assets to their latest conversion and position in Merkle tree
    #[allow(clippy::type_complexity)]
    pub assets: BTreeMap<AssetType, ConversionLeaf>,
}

impl From<ConversionState> for NewConversionState {
    fn from(value: ConversionState) -> Self {
        Self {
            #[allow(deprecated)]
            current_precision: value.current_precision,
            tree: value.tree,
            assets: value.assets,
        }
    }
}

/// Demonstrate how to set the minted balance using a migration
pub fn minted_balance_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    let person =
        Address::decode("tnam1q9rhgyv3ydq0zu3whnftvllqnvhvhm270qxay5tn")
            .unwrap();
    let nam = Address::decode("tnam1qxgfw7myv4dh0qna4hq0xdg6lx77fzl7dcem8h7e")
        .unwrap();
    let apfel = "tnam1qyvfwdkz8zgs9n3qn9xhp8scyf8crrxwuq26r6gy".to_string();
    let amount = Amount::native_whole(3200000036910u64);
    let minted_key = minted_balance_key(&nam);
    let minted_value = Amount::from(117600000504441u64);

    updates.push(migrations::DbUpdateType::Add {
        key: balance_key(&nam, &person),
        cf: DbColFam::SUBSPACE,
        value: amount.into(),
        force: false,
    });
    updates.push(migrations::DbUpdateType::Add {
        key: minted_key,
        cf: DbColFam::SUBSPACE,
        value: minted_value.into(),
        force: false,
    });
    updates.push(migrations::DbUpdateType::RepeatDelete(
        apfel,
        DbColFam::SUBSPACE,
    ));
}

/// A convenience data structure to allow token addresses to be more readably
/// expressed as a channel ID and base token instead of a raw Namada address.
pub enum TokenAddress {
    // Specify an IBC address. This can also be done more directly using the
    // Self::Address variant.
    Ibc(ChannelId, BaseToken),
    // Directly specify a Namada address
    Address(AddressBech32m),
}

/// Demonstrate how to set the shielded reward precision of IBC tokens using a
/// migration
pub fn shielded_reward_precision_migration(
    updates: &mut Vec<migrations::DbUpdateType>,
) {
    const TOKENS: [(TokenAddress, Precision); 6] = [
        (TokenAddress::Ibc("channel-1", "uosmo"), 1000u128),
        (TokenAddress::Ibc("channel-2", "uatom"), 1000u128),
        (TokenAddress::Ibc("channel-3", "utia"), 1000u128),
        (TokenAddress::Ibc("channel-0", "stuosmo"), 1000u128),
        (TokenAddress::Ibc("channel-0", "stuatom"), 1000u128),
        (TokenAddress::Ibc("channel-0", "stutia"), 1000u128),
    ];

    // Set IBC token shielded reward precisions
    for (token_address, precision) in TOKENS {
        // Compute the Namada address
        let token_address = match token_address {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };

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
}

/// Demonstrate clearing MASP rewards for the given IBC tokens by overwriting
/// their allowed conversions with conversions that do not contain rewards.
pub fn shielded_reward_reset_migration(
    updates: &mut Vec<migrations::DbUpdateType>,
) {
    // The address of the native token. This is what rewards are denominated in.
    const NATIVE_TOKEN_BECH32M: AddressBech32m =
        "tnam1q9gr66cvu4hrzm0sd5kmlnjje82gs3xlfg3v6nu7";
    let native_token = Address::from_str(NATIVE_TOKEN_BECH32M)
        .expect("unable to construct native token address");
    
    // The MASP epoch in which this migration will be applied. This number
    // controls the number of epochs of conversions created.
    const TARGET_MASP_EPOCH: MaspEpoch = MaspEpoch::new(175); // est. 20:00 CEST May 27

    // The tokens whose rewards will be reset.
    const TOKENS: [(TokenAddress, Denomination, Precision); 10] = [
        (
            TokenAddress::Ibc("channel-1", "uosmo"), // OSMO
            Denomination(0u8),
            10_000,
        ),
        (
            TokenAddress::Ibc("channel-2", "uatom"), // ATOM
            Denomination(0u8),
            5_000,
        ),
        (
            TokenAddress::Ibc("channel-3", "utia"), // TIA
            Denomination(0u8),
            5_000,
        ),
        (
            TokenAddress::Ibc("channel-0", "stuosmo"), // stOSMO
            Denomination(0u8),
            5_000,
        ),
        (
            TokenAddress::Ibc("channel-0", "stuatom"), // stATOM
            Denomination(0u8),
            5_000,
        ),
        (
            TokenAddress::Ibc("channel-0", "stutia"), // stTIA
            Denomination(0u8),
            5_000,
        ),
        (
            TokenAddress::Ibc("channel-4", "upenumbra"), // UM
            Denomination(0u8),
            1_000,
        ),
        (
            TokenAddress::Ibc("channel-5", "uusdc"), // USDC
            Denomination(0u8),
            1_000,
        ),
        (
            TokenAddress::Ibc("channel-6", "unym"), // NYM
            Denomination(0u8),
            1_000,
        ),
        (
            TokenAddress::Ibc("channel-7", "untrn"), // NTRN
            Denomination(0u8),
            1_000,
        ),
    ];

    // Reset the allowed conversions for the above tokens
    for (token_address, denomination, precision) in TOKENS {
        // Compute the Namada address
        let token_address = match token_address {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };
        // Erase the TOK rewards that have been distributed so far
        let mut asset_types = BTreeMap::new();
        let mut precision_toks = BTreeMap::new();
        let mut reward_deltas = BTreeMap::new();
        // TOK[ep, digit]
        let mut asset_type = |epoch, digit| {
            *asset_types.entry((epoch, digit)).or_insert_with(|| {
                encode_asset_type(
                    token_address.clone(),
                    denomination,
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
                        i128::try_from(precision).expect("precision too large"),
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
            masp_scheduled_reward_precision_key(
                &TARGET_MASP_EPOCH,
                &token_address,
            );

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_reward_precision_key,
            cf: DbColFam::SUBSPACE,
            value: precision.into(),
            force: false,
        });
        // If the current token is the native token, then also update the base
        // native precision
        if token_address == native_token {
            let shielded_token_base_native_precision_key =
                masp_scheduled_base_native_precision_key(&TARGET_MASP_EPOCH);

            updates.push(migrations::DbUpdateType::Add {
                key: shielded_token_base_native_precision_key,
                cf: DbColFam::SUBSPACE,
                value: precision.into(),
                force: false,
            });
        }
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
                    denomination,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type");
                reward += reward_delta(epoch, digit);
                // Write the conversion update to memory
                updates.push(migrations::DbUpdateType::Add {
                    key: masp_conversion_key(&TARGET_MASP_EPOCH, &asset_type),
                    cf: DbColFam::SUBSPACE,
                    value: reward.clone().into(),
                    force: false,
                });
            }
        }
    }
}

/// Demonstrate replacing the entire conversion state with a new state that does
/// not contain rewards.
pub fn conversion_state_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    // The MASP epoch in which this migration will be applied. This number
    // controls the number of epochs of conversions created.
    const TARGET_MASP_EPOCH: MaspEpoch = MaspEpoch::new(4);
    // Precision to use for the native token
    const NATIVE_PRECISION: Precision = 1000;
    // The tokens whose rewarrds will be reset.
    const TOKENS: [(TokenAddress, Denomination, Precision); 7] = [
        (
            TokenAddress::Address(
                "tnam1qyvfwdkz8zgs9n3qn9xhp8scyf8crrxwuq26r6gy",
            ),
            Denomination(6),
            1000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qy8qgxlcteehlk70sn8wx2pdlavtayp38vvrnkhq",
            ),
            Denomination(8),
            10000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qyfl072lhaazfj05m7ydz8cr57zdygk375jxjfwx",
            ),
            Denomination(10),
            10000000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qxvnvm2t9xpceu8rup0n6espxyj2ke36yv4dw6q5",
            ),
            Denomination(18),
            10000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qyx93z5ma43jjmvl0xhwz4rzn05t697f3vfv8yuj",
            ),
            Denomination(6),
            1000u128,
        ),
        (
            TokenAddress::Address(
                "tnam1qxgfw7myv4dh0qna4hq0xdg6lx77fzl7dcem8h7e",
            ),
            Denomination(6),
            NATIVE_PRECISION,
        ),
        (
            TokenAddress::Address(
                "tnam1q9f5yynt5qfxe28ae78xxp7wcgj50fn4syetyrj6",
            ),
            Denomination(6),
            1000u128,
        ),
    ];

    let mut assets = BTreeMap::new();
    let mut conv_notes = Vec::new();
    // Reset the allowed conversions for the above tokens
    for (token_address, denomination, precision) in TOKENS {
        // Compute the Namada address
        let token_address = match token_address {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };
        // Erase the TOK rewards that have been distributed so far
        let mut asset_types = BTreeMap::new();
        let mut precision_toks = BTreeMap::new();
        let mut reward_deltas = BTreeMap::new();
        // TOK[ep, digit]
        let mut asset_type = |epoch, digit| {
            *asset_types.entry((epoch, digit)).or_insert_with(|| {
                encode_asset_type(
                    token_address.clone(),
                    denomination,
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
                        precision.try_into().expect("precision too large"),
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
            value: precision.into(),
            force: false,
        });
        // Build up the new TOK conversions into an object
        for digit in MaspDigitPos::iter() {
            // -PRECISION TOK[ep, digit] + PRECISION TOK[current_ep, digit]
            let mut reward: AllowedConversion = I128Sum::zero().into();
            for epoch in MaspEpoch::iter_bounds_inclusive(
                MaspEpoch::zero(),
                TARGET_MASP_EPOCH,
            )
            .rev()
            {
                // TOK[ep, digit]
                let asset_type = encode_asset_type(
                    token_address.clone(),
                    denomination,
                    digit,
                    Some(epoch),
                )
                .expect("unable to encode asset type");
                // Add an allowed conversion to the Merkle tree if we are on an
                // asset from a preceding epoch.
                let leaf_pos = if epoch < TARGET_MASP_EPOCH {
                    reward += reward_delta(epoch, digit);
                    conv_notes.push(Node::new(reward.cmu().to_repr()));
                    conv_notes.len() - 1
                } else {
                    // Otherwise use a sentinel value for the note position
                    usize::MAX
                };
                // Construct the conversion leaf that can help decode and
                // convert the current asset type
                let leaf = ConversionLeaf {
                    token: token_address.clone(),
                    denom: denomination,
                    digit_pos: digit,
                    epoch,
                    conversion: reward.clone(),
                    leaf_pos,
                };
                assets.insert(asset_type, leaf);
            }
        }
    }

    // Finally construct the entire conversion state
    let conversion_state = ConversionState {
        #[allow(deprecated)]
        current_precision: Some(NATIVE_PRECISION),
        tree: FrozenCommitmentTree::new(&conv_notes),
        assets,
    };
    let assets_hash = Hash::sha256(conversion_state.assets.serialize_to_vec());
    // Write the conversion state to the database and memory
    updates.push(migrations::DbUpdateType::Add {
        key: migrations::CONVERSION_STATE_KEY
            .parse()
            .expect("unable to construct conversion state key"),
        cf: DbColFam::STATE,
        value: conversion_state.into(),
        force: false,
    });

    // Put in storage only the assets hash because the size is quite large
    updates.push(migrations::DbUpdateType::Add {
        key: masp_assets_hash_key(),
        cf: DbColFam::SUBSPACE,
        value: assets_hash.into(),
        force: false,
    });
}

/// Demonstrate upgrading the transaction WASM code and hashes in storage
pub fn wasm_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    // wasm_updates[x].0) The WASM hash that is being replaced
    // wasm_updates[x].1) The name of WASM being updated
    // wasm_updates[x].2) The bytes of the new WASM code
    const WASM_UPDATES: [(WasmHash, &str, WasmBytes); 2] = [
      (
            "6d753db0390e7cec16729fc405bfe41384c93bd79f42b8b8be41b22edbbf1b7c",
            "tx_transfer.wasm",
            include_bytes!("tx_transfer.ef687f96ec919f5da2e90f125a2800f198a06bcd609a37e5a9ec90d442e32239.wasm"),
            // &[0xDE, 0xAD, 0xBE, 0xEF],
        ),
        (
            "cecb1f1b75cd649915423c5e68be20c5232f94ab57a11a908dc66751bbdc4f72",
            "tx_ibc.wasm",
            include_bytes!("tx_ibc.7b0d43f4a277aadd02562d811c755e09d7f191c601ca3bffb89a7f8b599dab1e.wasm"),
            // &[0xDE, 0xAD, 0xBE, 0xEF],
        ),
    ];

    // Update the tx allowlist parameter
    let tx_allowlist_key = get_tx_allowlist_storage_key();
    const TX_ALLOWLIST: [WasmHash; 22] = [
        "c6629064a1c3bde8503212cfa5e9b954169a7f162ad411b63a71db782fe909d7",
        "490cf419bdbffe616c6aa6c72d38064e350ee65fb04d92472ccf285aec6844b6",
        "473ee80e6e714f6097ec713c88f527b38da6479354075c879b66b9f53e813cb0",
        "0295796e5ff47aeecb95b68c2fe308693e5f84b251126f26d03309e5f4f5da55",
        "b745bc2b87bf8acd07e2f3409c77eee06c9b5206d2a77a2f23bb8e593c70cbfe",
        "1b5a323c140b54700f280cde8b9aac1c12555f9c119e936432ddfa8f194d23ac",
        "b74104949ac0c35ee922fdc3f3db454627742e2483d79550c12fcf31755c6d01",
        "5120581194f1e6a122d2eec3f886e9cf5f079f56540d96193d3c1f9804c4d936",
        "cecb1f1b75cd649915423c5e68be20c5232f94ab57a11a908dc66751bbdc4f72", // tx_ibc
        "26f90ec6676444cd6191d7555fd48861372f901c46e5178c59a897b411616918",
        "33ee28597cf0f6a11dfe6e23e9aedf2eb04dabb44069cbe317768f4d982d80be",
        "fbe97ce1136225bdbf8e388bab833a8c51e80bc1b8d94f7d3f8e49b3fad08543",
        "7d5ad1877643f7d9b32a511ef93a11e8503426baee0f5986d29e3f63a2355d58",
        "b63738a98927be05fd27f00d208e8703031e45b579d42f776d27234c48a48523",
        "f1fc74460bd9bbd17140c88dfc0543440f066ffb84849c35c2bb0e331e51cf1c",
        "6d753db0390e7cec16729fc405bfe41384c93bd79f42b8b8be41b22edbbf1b7c", // tx_transfer
        "36e774350b865752c9d309d518223abf0a60374bae15a1f73dfe4721b5887048",
        "2e17680cec3e97ff5a6d4db2ba4a376a15f6da143abce690affd800645c6db80",
        "12faf164aef7b6f91ed918db39f00e19fd3fc527a63f3b2589f43bf30bbaf24b",
        "d7e34efc128d6a1c84691200f72f83ad9f696e1766f8ce083894f26343fc395f",
        "faad78023b9391596981ac9a536070a3d7d469d5c6e20c2855b2cfca63c38f59",
        "8a9df03a1a8f5e9e606e14a97fdfb2097dba062da1b3b2158bbfa7deabeeadfb",
    ];
    let mut tx_allowlist: Vec<String> = TX_ALLOWLIST
        .into_iter()
        .map(|hash_str| {
            Hash::from_str(hash_str).unwrap().to_string().to_lowercase()
        })
        .collect();
    // Replace the targetted old hashes
    for (old_code_hash, name, code) in WASM_UPDATES {
        let old_code_hash = Hash::from_str(old_code_hash).unwrap();
        let new_code_hash = Hash(*Sha256::digest(code).as_ref());
        let new_code_len = u64::try_from(code.len()).unwrap();
        let pos = tx_allowlist
            .iter()
            .position(|x| Hash::from_str(x).unwrap() == old_code_hash)
            .expect("old tx code hash not found");
        tx_allowlist[pos] = new_code_hash.to_string().to_lowercase();

        // Delete the old tx code
        let old_code_key = Key::wasm_code(&old_code_hash);
        let old_code_len_key = Key::wasm_code_len(&old_code_hash);
        updates.push(migrations::DbUpdateType::Delete(
            old_code_key,
            DbColFam::SUBSPACE,
        ));
        updates.push(migrations::DbUpdateType::Delete(
            old_code_len_key,
            DbColFam::SUBSPACE,
        ));

        // Write the new tx code into storage
        let code_key = Key::wasm_code(&new_code_hash);
        let code_len_key = Key::wasm_code_len(&new_code_hash);
        let hash_key = Key::wasm_hash(name);
        let code_name_key = Key::wasm_code_name(name.to_owned());

        updates.push(migrations::DbUpdateType::Add {
            key: code_key,
            cf: DbColFam::SUBSPACE,
            value: code.to_vec().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: code_len_key,
            cf: DbColFam::SUBSPACE,
            value: new_code_len.into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: hash_key,
            cf: DbColFam::SUBSPACE,
            value: new_code_hash.into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: code_name_key,
            cf: DbColFam::SUBSPACE,
            value: new_code_hash.into(),
            force: false,
        });
    }
    // Put the allow list in storage
    updates.push(migrations::DbUpdateType::Add {
        key: tx_allowlist_key,
        cf: DbColFam::SUBSPACE,
        value: tx_allowlist.into(),
        force: false,
    });
}

/// Demonstrate how to set the shielded reward parameters of IBC tokens using a
/// migration
pub fn shielded_reward_parameters_migration(
    updates: &mut Vec<migrations::DbUpdateType>,
) {
    const TOKENS: [(
        Denomination,
        TokenAddress,
        MaxRewardRate,
        TargetLockedAmount,
        KpGain,
        KdGain,
    ); 6] = [
        (
            Denomination(0),
            TokenAddress::Ibc("channel-1", "uosmo"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-2", "uatom"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-3", "utia"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-0", "stuosmo"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-0", "stuatom"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
        (
            Denomination(0),
            TokenAddress::Ibc("channel-0", "stutia"),
            "0.01",
            1_000_000,
            "120000",
            "120000",
        ),
    ];

    // Set IBC token shielded reward parameters
    for (denomination, token_addr, max_reward, lock_target, kp, kd) in TOKENS {
        // Compute the Namada address
        let token_address = match token_addr {
            TokenAddress::Ibc(channel_id, base_token) => {
                let ibc_denom = format!("transfer/{channel_id}/{base_token}");
                ibc_token(&ibc_denom).clone()
            }
            TokenAddress::Address(addr) => Address::from_str(addr)
                .expect("unable to construct token address"),
        };

        // The keys holding the shielded reward parameters of current token
        let shielded_token_max_rewards_key =
            masp_max_reward_rate_key::<Store<()>>(&token_address);
        let shielded_token_target_locked_amount_key =
            masp_locked_amount_target_key::<Store<()>>(&token_address);
        let shielded_token_kp_gain_key =
            masp_kp_gain_key::<Store<()>>(&token_address);
        let shielded_token_kd_gain_key =
            masp_kd_gain_key::<Store<()>>(&token_address);

        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_max_rewards_key,
            cf: DbColFam::SUBSPACE,
            value: Dec::from_str(max_reward).unwrap().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_target_locked_amount_key,
            cf: DbColFam::SUBSPACE,
            value: Amount::from_uint(lock_target, denomination).unwrap().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_kp_gain_key,
            cf: DbColFam::SUBSPACE,
            value: Dec::from_str(kp).unwrap().into(),
            force: false,
        });
        updates.push(migrations::DbUpdateType::Add {
            key: shielded_token_kd_gain_key,
            cf: DbColFam::SUBSPACE,
            value: Dec::from_str(kd).unwrap().into(),
            force: false,
        });
    }
}

/// Demonstrate accelerating epochs
pub fn accelerate_epoch_migration(updates: &mut Vec<migrations::DbUpdateType>) {
    // Set the number of epochs per year to the specified constant
    const EPOCHS_PER_YEAR: u64 = 175200;
    let epochs_per_year_key = get_epochs_per_year_key();
    updates.push(migrations::DbUpdateType::Add {
        key: epochs_per_year_key,
        cf: DbColFam::SUBSPACE,
        value: EPOCHS_PER_YEAR.into(),
        force: false,
    });
    // Set the MASP epoch multiplier to the specified constant
    const MASP_EPOCH_MULTIPLIER: u64 = 2;
    let masp_epoch_multiplier_key = get_masp_epoch_multiplier_key();
    updates.push(migrations::DbUpdateType::Add {
        key: masp_epoch_multiplier_key,
        cf: DbColFam::SUBSPACE,
        value: MASP_EPOCH_MULTIPLIER.into(),
        force: false,
    });
    // Set the epoch duration to the specified constant
    const MIN_NUM_OF_BLOCKS: u64 = 4;
    let epy_i64 = i64::try_from(EPOCHS_PER_YEAR)
        .expect("`epochs_per_year` must not exceed `i64::MAX`");
    #[allow(clippy::arithmetic_side_effects)]
    let min_duration: i64 = 60 * 60 * 24 * 365 / epy_i64;
    let epoch_duration = EpochDuration {
        min_num_of_blocks: MIN_NUM_OF_BLOCKS,
        min_duration: namada_sdk::time::Duration::seconds(min_duration).into(),
    };
    let epoch_duration_key = get_epoch_duration_storage_key();
    updates.push(migrations::DbUpdateType::Add {
        key: epoch_duration_key,
        cf: DbColFam::SUBSPACE,
        value: epoch_duration.into(),
        force: false,
    });
    // Set the next epoch's block height to zero in order to force transition
    updates.push(migrations::DbUpdateType::Add {
        key: migrations::NEXT_EPOCH_MIN_START_HEIGHT_KEY
            .parse()
            .expect("unable to construct conversion state key"),
        cf: DbColFam::STATE,
        value: BlockHeight(0).into(),
        force: false,
    });
    // Set the next epoch's start time to a minimum in order to force transition
    updates.push(migrations::DbUpdateType::Add {
        key: migrations::NEXT_EPOCH_MIN_START_TIME_KEY
            .parse()
            .expect("unable to construct conversion state key"),
        cf: DbColFam::STATE,
        value: MIN_UTC.into(),
        force: false,
    });
}

/// Generate various migrations
pub fn main() {
    // Write an example migration that updates minted balances
    let mut minted_balance_changes = migrations::DbChanges { changes: vec![] };
    minted_balance_migration(&mut minted_balance_changes.changes);
    std::fs::write(
        "minted_balance_migration.json",
        serde_json::to_string(&minted_balance_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that updates token precision
    let mut reward_precision_changes =
        migrations::DbChanges { changes: vec![] };
    shielded_reward_precision_migration(&mut reward_precision_changes.changes);
    std::fs::write(
        "reward_precision_migration.json",
        serde_json::to_string(&reward_precision_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that resets shielded rewards
    let mut reward_reset_changes = migrations::DbChanges { changes: vec![] };
    shielded_reward_reset_migration(&mut reward_reset_changes.changes);
    std::fs::write(
        "reward_reset_migration.json",
        serde_json::to_string(&reward_reset_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that directly updates conversion state
    let mut conversion_state_changes =
        migrations::DbChanges { changes: vec![] };
    conversion_state_migration(&mut conversion_state_changes.changes);
    std::fs::write(
        "conversion_state_migration.json",
        serde_json::to_string(&conversion_state_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that just updates WASMs
    let mut wasm_changes = migrations::DbChanges { changes: vec![] };
    wasm_migration(&mut wasm_changes.changes);
    std::fs::write(
        "wasm_migration.json",
        serde_json::to_string(&wasm_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that updates WASMs and resets shielded rewards
    let mut pre_phase4_changes = migrations::DbChanges { changes: vec![] };
    shielded_reward_reset_migration(&mut pre_phase4_changes.changes);
    wasm_migration(&mut pre_phase4_changes.changes);
    std::fs::write(
        "pre_phase4_migration.json",
        serde_json::to_string(&pre_phase4_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that sets shielded reward parameters
    let mut reward_parameter_changes =
        migrations::DbChanges { changes: vec![] };
    shielded_reward_parameters_migration(&mut reward_parameter_changes.changes);
    std::fs::write(
        "reward_parameters_migration.json",
        serde_json::to_string(&reward_parameter_changes).unwrap(),
    )
    .unwrap();
    // Write an example migration that accelerates epochs
    let mut accelerate_epochs_changes =
        migrations::DbChanges { changes: vec![] };
    accelerate_epoch_migration(&mut accelerate_epochs_changes.changes);
    std::fs::write(
        "accelerate_epochs_migration.json",
        serde_json::to_string(&accelerate_epochs_changes).unwrap(),
    )
    .unwrap();
}
