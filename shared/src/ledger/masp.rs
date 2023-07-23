//! MASP verification wrappers.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fmt::Debug;
#[cfg(feature = "masp-tx-gen")]
use std::ops::Deref;
use std::path::PathBuf;

use async_trait::async_trait;
// use async_std::io::prelude::WriteExt;
// use async_std::io::{self};
use borsh::{BorshDeserialize, BorshSerialize};
use itertools::Either;
use masp_primitives::asset_type::AssetType;
#[cfg(feature = "mainnet")]
use masp_primitives::consensus::MainNetwork;
#[cfg(not(feature = "mainnet"))]
use masp_primitives::consensus::TestNetwork;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::group::GroupEncoding;
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{
    CommitmentTree, IncrementalWitness, MerklePath,
};
use masp_primitives::sapling::keys::FullViewingKey;
use masp_primitives::sapling::note_encryption::*;
use masp_primitives::sapling::redjubjub::PublicKey;
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
#[cfg(feature = "masp-tx-gen")]
use masp_primitives::transaction::builder::{self, *};
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::components::{
    Amount, ConvertDescription, OutputDescription, SpendDescription, TxOut,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::sighash::{signature_hash, SignableInput};
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData,
    TransparentAddress, Unauthorized,
};
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use masp_proofs::bellman::groth16::{
    prepare_verifying_key, PreparedVerifyingKey, VerifyingKey,
};
use masp_proofs::bls12_381::Bls12;
use masp_proofs::prover::LocalTxProver;
use masp_proofs::sapling::SaplingVerificationContext;
use namada_core::types::token::{Change, MaspDenom};
use namada_core::types::transaction::AffineCurve;
#[cfg(feature = "masp-tx-gen")]
use rand_core::{CryptoRng, OsRng, RngCore};
use ripemd::Digest as RipemdDigest;
#[cfg(feature = "masp-tx-gen")]
use sha2::Digest;

use crate::ledger::args::InputAmount;
use crate::ledger::queries::Client;
use crate::ledger::rpc::{query_conversion, query_storage_value};
use crate::ledger::tx::decode_component;
use crate::ledger::{args, rpc};
use crate::proto::Tx;
use crate::tendermint_rpc::query::Query;
use crate::tendermint_rpc::Order;
use crate::types::address::{masp, Address};
use crate::types::masp::{BalanceOwner, ExtendedViewingKey, PaymentAddress};
use crate::types::storage::{BlockHeight, Epoch, Key, KeySeg, TxIndex};
use crate::types::token;
use crate::types::token::{
    Transfer, HEAD_TX_KEY, PIN_KEY_PREFIX, TX_KEY_PREFIX,
};
use crate::types::transaction::{EllipticCurve, PairingEngine, WrapperTx};

/// TODO: properly tested crate
/// Spend verifying key
pub const NAMADA_MASP_SPEND_VK_BYTES: &'static [u8] = &[
    13u8, 184u8, 130u8, 207u8, 93u8, 179u8, 232u8, 86u8, 127u8, 22u8, 180u8,
    219u8, 23u8, 114u8, 212u8, 209u8, 245u8, 163u8, 254u8, 141u8, 98u8, 240u8,
    223u8, 46u8, 184u8, 165u8, 207u8, 165u8, 8u8, 6u8, 112u8, 42u8, 253u8,
    232u8, 252u8, 37u8, 51u8, 94u8, 181u8, 236u8, 133u8, 156u8, 40u8, 24u8,
    178u8, 97u8, 11u8, 46u8, 25u8, 171u8, 68u8, 93u8, 172u8, 114u8, 11u8,
    177u8, 242u8, 176u8, 205u8, 51u8, 54u8, 247u8, 161u8, 172u8, 198u8, 43u8,
    241u8, 179u8, 163u8, 33u8, 130u8, 98u8, 100u8, 220u8, 126u8, 70u8, 146u8,
    129u8, 226u8, 59u8, 33u8, 131u8, 148u8, 213u8, 152u8, 104u8, 157u8, 160u8,
    78u8, 19u8, 104u8, 120u8, 255u8, 154u8, 120u8, 151u8, 1u8, 74u8, 120u8,
    168u8, 209u8, 113u8, 128u8, 163u8, 124u8, 76u8, 168u8, 251u8, 35u8, 31u8,
    38u8, 74u8, 184u8, 155u8, 209u8, 72u8, 99u8, 119u8, 127u8, 193u8, 255u8,
    233u8, 1u8, 253u8, 146u8, 68u8, 67u8, 101u8, 209u8, 143u8, 120u8, 35u8,
    118u8, 18u8, 172u8, 56u8, 227u8, 159u8, 65u8, 156u8, 50u8, 240u8, 130u8,
    69u8, 21u8, 33u8, 158u8, 196u8, 92u8, 38u8, 193u8, 250u8, 213u8, 48u8,
    81u8, 78u8, 216u8, 145u8, 160u8, 208u8, 4u8, 58u8, 206u8, 223u8, 52u8,
    137u8, 34u8, 16u8, 46u8, 149u8, 179u8, 230u8, 208u8, 126u8, 10u8, 250u8,
    148u8, 197u8, 138u8, 164u8, 20u8, 128u8, 99u8, 31u8, 193u8, 202u8, 54u8,
    229u8, 90u8, 174u8, 81u8, 253u8, 10u8, 65u8, 107u8, 129u8, 135u8, 69u8,
    11u8, 40u8, 240u8, 37u8, 196u8, 33u8, 227u8, 255u8, 20u8, 211u8, 143u8,
    154u8, 189u8, 154u8, 242u8, 241u8, 4u8, 107u8, 145u8, 75u8, 83u8, 171u8,
    55u8, 233u8, 174u8, 187u8, 166u8, 131u8, 203u8, 37u8, 40u8, 78u8, 92u8,
    34u8, 250u8, 52u8, 17u8, 41u8, 152u8, 82u8, 80u8, 161u8, 3u8, 84u8, 125u8,
    229u8, 208u8, 5u8, 223u8, 72u8, 38u8, 95u8, 124u8, 178u8, 88u8, 22u8, 34u8,
    83u8, 213u8, 111u8, 188u8, 104u8, 45u8, 16u8, 106u8, 30u8, 203u8, 7u8,
    102u8, 110u8, 191u8, 117u8, 36u8, 163u8, 100u8, 229u8, 18u8, 195u8, 122u8,
    166u8, 47u8, 130u8, 214u8, 231u8, 221u8, 78u8, 216u8, 131u8, 132u8, 120u8,
    16u8, 67u8, 118u8, 169u8, 128u8, 114u8, 118u8, 108u8, 41u8, 149u8, 147u8,
    88u8, 233u8, 205u8, 230u8, 164u8, 152u8, 86u8, 24u8, 246u8, 94u8, 162u8,
    87u8, 232u8, 242u8, 136u8, 151u8, 79u8, 74u8, 237u8, 222u8, 82u8, 229u8,
    218u8, 194u8, 251u8, 122u8, 229u8, 211u8, 14u8, 171u8, 124u8, 216u8, 40u8,
    162u8, 200u8, 177u8, 95u8, 21u8, 177u8, 111u8, 19u8, 159u8, 44u8, 51u8,
    239u8, 51u8, 214u8, 59u8, 239u8, 228u8, 4u8, 230u8, 150u8, 201u8, 112u8,
    119u8, 209u8, 126u8, 164u8, 47u8, 79u8, 249u8, 216u8, 46u8, 196u8, 86u8,
    170u8, 244u8, 57u8, 20u8, 163u8, 208u8, 121u8, 104u8, 17u8, 26u8, 58u8,
    52u8, 143u8, 21u8, 126u8, 100u8, 192u8, 39u8, 138u8, 19u8, 224u8, 43u8,
    96u8, 82u8, 113u8, 159u8, 96u8, 125u8, 172u8, 211u8, 160u8, 136u8, 39u8,
    79u8, 101u8, 89u8, 107u8, 208u8, 208u8, 153u8, 32u8, 182u8, 26u8, 181u8,
    218u8, 97u8, 187u8, 220u8, 127u8, 80u8, 73u8, 51u8, 76u8, 241u8, 18u8,
    19u8, 148u8, 93u8, 87u8, 229u8, 172u8, 125u8, 5u8, 93u8, 4u8, 43u8, 126u8,
    2u8, 74u8, 162u8, 178u8, 240u8, 143u8, 10u8, 145u8, 38u8, 8u8, 5u8, 39u8,
    45u8, 197u8, 16u8, 81u8, 198u8, 228u8, 122u8, 212u8, 250u8, 64u8, 59u8,
    2u8, 180u8, 81u8, 11u8, 100u8, 122u8, 227u8, 209u8, 119u8, 11u8, 172u8,
    3u8, 38u8, 168u8, 5u8, 187u8, 239u8, 212u8, 128u8, 86u8, 200u8, 193u8,
    33u8, 189u8, 184u8, 6u8, 6u8, 196u8, 160u8, 46u8, 167u8, 52u8, 204u8, 50u8,
    172u8, 210u8, 176u8, 43u8, 194u8, 139u8, 153u8, 203u8, 62u8, 40u8, 126u8,
    133u8, 167u8, 99u8, 175u8, 38u8, 116u8, 146u8, 171u8, 87u8, 46u8, 153u8,
    171u8, 63u8, 55u8, 13u8, 39u8, 92u8, 236u8, 29u8, 161u8, 170u8, 169u8, 7u8,
    95u8, 240u8, 95u8, 121u8, 190u8, 12u8, 229u8, 213u8, 39u8, 114u8, 125u8,
    110u8, 17u8, 140u8, 201u8, 205u8, 198u8, 218u8, 46u8, 53u8, 26u8, 173u8,
    253u8, 155u8, 170u8, 140u8, 189u8, 211u8, 167u8, 109u8, 66u8, 154u8, 105u8,
    81u8, 96u8, 209u8, 44u8, 146u8, 58u8, 201u8, 204u8, 59u8, 172u8, 162u8,
    137u8, 225u8, 147u8, 84u8, 134u8, 8u8, 184u8, 40u8, 1u8, 1u8, 6u8, 16u8,
    188u8, 11u8, 56u8, 80u8, 38u8, 104u8, 12u8, 114u8, 189u8, 138u8, 135u8,
    6u8, 9u8, 87u8, 90u8, 235u8, 132u8, 108u8, 5u8, 207u8, 59u8, 159u8, 198u8,
    231u8, 119u8, 30u8, 181u8, 180u8, 18u8, 204u8, 74u8, 28u8, 37u8, 150u8,
    139u8, 253u8, 122u8, 2u8, 204u8, 10u8, 11u8, 89u8, 39u8, 55u8, 84u8, 14u8,
    232u8, 95u8, 187u8, 38u8, 187u8, 116u8, 29u8, 111u8, 2u8, 203u8, 16u8,
    143u8, 142u8, 147u8, 47u8, 69u8, 157u8, 217u8, 249u8, 31u8, 42u8, 162u8,
    196u8, 12u8, 9u8, 70u8, 88u8, 251u8, 85u8, 109u8, 196u8, 173u8, 128u8,
    229u8, 229u8, 1u8, 249u8, 38u8, 209u8, 22u8, 153u8, 52u8, 164u8, 205u8,
    5u8, 201u8, 113u8, 5u8, 156u8, 79u8, 250u8, 32u8, 78u8, 207u8, 40u8, 139u8,
    71u8, 52u8, 165u8, 51u8, 128u8, 119u8, 112u8, 212u8, 7u8, 209u8, 0u8,
    119u8, 109u8, 105u8, 51u8, 182u8, 192u8, 173u8, 0u8, 105u8, 76u8, 64u8,
    246u8, 93u8, 225u8, 236u8, 142u8, 53u8, 44u8, 91u8, 169u8, 16u8, 209u8,
    73u8, 238u8, 36u8, 48u8, 137u8, 25u8, 12u8, 172u8, 35u8, 134u8, 140u8,
    103u8, 9u8, 252u8, 154u8, 49u8, 56u8, 130u8, 92u8, 228u8, 175u8, 21u8,
    42u8, 63u8, 246u8, 184u8, 222u8, 143u8, 181u8, 218u8, 78u8, 200u8, 238u8,
    113u8, 180u8, 91u8, 133u8, 46u8, 202u8, 152u8, 166u8, 9u8, 111u8, 47u8,
    165u8, 38u8, 179u8, 48u8, 128u8, 56u8, 237u8, 13u8, 30u8, 197u8, 17u8,
    216u8, 129u8, 98u8, 110u8, 255u8, 230u8, 129u8, 11u8, 185u8, 116u8, 63u8,
    61u8, 168u8, 135u8, 199u8, 114u8, 27u8, 34u8, 109u8, 112u8, 22u8, 228u8,
    101u8, 229u8, 117u8, 203u8, 231u8, 131u8, 229u8, 27u8, 235u8, 254u8, 243u8,
    237u8, 116u8, 115u8, 182u8, 39u8, 74u8, 9u8, 148u8, 18u8, 226u8, 84u8, 9u8,
    235u8, 160u8, 22u8, 10u8, 55u8, 56u8, 202u8, 206u8, 16u8, 199u8, 52u8,
    247u8, 175u8, 33u8, 150u8, 111u8, 54u8, 186u8, 212u8, 132u8, 60u8, 164u8,
    214u8, 247u8, 114u8, 53u8, 147u8, 50u8, 100u8, 37u8, 87u8, 121u8, 103u8,
    200u8, 206u8, 218u8, 103u8, 2u8, 174u8, 85u8, 28u8, 139u8, 218u8, 207u8,
    42u8, 215u8, 99u8, 189u8, 171u8, 208u8, 0u8, 0u8, 0u8, 8u8, 18u8, 249u8,
    114u8, 166u8, 226u8, 128u8, 171u8, 241u8, 248u8, 174u8, 75u8, 252u8, 184u8,
    47u8, 163u8, 51u8, 203u8, 41u8, 127u8, 180u8, 188u8, 66u8, 249u8, 199u8,
    154u8, 136u8, 36u8, 183u8, 241u8, 91u8, 137u8, 96u8, 171u8, 21u8, 24u8,
    89u8, 93u8, 177u8, 20u8, 2u8, 213u8, 58u8, 171u8, 184u8, 51u8, 109u8,
    249u8, 186u8, 12u8, 228u8, 111u8, 216u8, 54u8, 144u8, 20u8, 219u8, 115u8,
    59u8, 178u8, 240u8, 105u8, 217u8, 252u8, 81u8, 29u8, 196u8, 98u8, 53u8,
    117u8, 1u8, 48u8, 136u8, 30u8, 219u8, 141u8, 58u8, 47u8, 68u8, 187u8,
    251u8, 62u8, 146u8, 95u8, 75u8, 59u8, 7u8, 200u8, 146u8, 48u8, 219u8, 67u8,
    92u8, 42u8, 76u8, 212u8, 68u8, 15u8, 219u8, 108u8, 191u8, 98u8, 133u8,
    192u8, 78u8, 58u8, 36u8, 150u8, 14u8, 235u8, 26u8, 44u8, 202u8, 44u8,
    176u8, 25u8, 193u8, 76u8, 189u8, 112u8, 56u8, 169u8, 48u8, 181u8, 1u8,
    197u8, 149u8, 219u8, 125u8, 197u8, 57u8, 223u8, 115u8, 233u8, 57u8, 132u8,
    17u8, 71u8, 226u8, 129u8, 241u8, 225u8, 224u8, 218u8, 37u8, 17u8, 175u8,
    158u8, 231u8, 251u8, 114u8, 1u8, 193u8, 1u8, 120u8, 143u8, 85u8, 38u8,
    213u8, 77u8, 137u8, 139u8, 118u8, 60u8, 219u8, 235u8, 243u8, 117u8, 116u8,
    28u8, 27u8, 154u8, 230u8, 235u8, 239u8, 64u8, 23u8, 89u8, 254u8, 243u8,
    84u8, 198u8, 103u8, 125u8, 243u8, 102u8, 144u8, 223u8, 162u8, 2u8, 59u8,
    253u8, 37u8, 12u8, 122u8, 183u8, 152u8, 85u8, 25u8, 32u8, 166u8, 31u8,
    218u8, 114u8, 177u8, 158u8, 18u8, 182u8, 53u8, 84u8, 71u8, 26u8, 48u8,
    63u8, 160u8, 120u8, 135u8, 31u8, 92u8, 190u8, 243u8, 97u8, 20u8, 30u8,
    220u8, 35u8, 126u8, 3u8, 251u8, 226u8, 173u8, 78u8, 20u8, 194u8, 40u8,
    12u8, 242u8, 245u8, 118u8, 32u8, 107u8, 15u8, 33u8, 243u8, 18u8, 199u8,
    192u8, 211u8, 58u8, 46u8, 40u8, 44u8, 60u8, 33u8, 197u8, 21u8, 173u8,
    176u8, 4u8, 79u8, 191u8, 79u8, 246u8, 72u8, 36u8, 79u8, 185u8, 60u8, 230u8,
    210u8, 8u8, 13u8, 203u8, 31u8, 206u8, 179u8, 117u8, 70u8, 7u8, 182u8,
    196u8, 89u8, 46u8, 69u8, 95u8, 218u8, 95u8, 102u8, 171u8, 9u8, 159u8,
    165u8, 68u8, 129u8, 191u8, 12u8, 233u8, 121u8, 89u8, 215u8, 117u8, 76u8,
    36u8, 118u8, 23u8, 72u8, 195u8, 27u8, 47u8, 104u8, 92u8, 15u8, 197u8, 93u8,
    24u8, 72u8, 240u8, 140u8, 63u8, 34u8, 168u8, 89u8, 203u8, 127u8, 176u8,
    83u8, 170u8, 226u8, 130u8, 85u8, 167u8, 19u8, 126u8, 63u8, 186u8, 63u8,
    187u8, 22u8, 142u8, 188u8, 144u8, 140u8, 222u8, 112u8, 165u8, 64u8, 185u8,
    18u8, 228u8, 0u8, 17u8, 129u8, 16u8, 8u8, 232u8, 124u8, 44u8, 13u8, 168u8,
    103u8, 220u8, 255u8, 131u8, 81u8, 129u8, 57u8, 154u8, 147u8, 145u8, 254u8,
    152u8, 158u8, 79u8, 101u8, 247u8, 115u8, 85u8, 205u8, 68u8, 119u8, 143u8,
    218u8, 171u8, 198u8, 128u8, 14u8, 154u8, 130u8, 51u8, 30u8, 60u8, 197u8,
    123u8, 118u8, 213u8, 143u8, 67u8, 25u8, 66u8, 44u8, 152u8, 193u8, 211u8,
    210u8, 234u8, 37u8, 170u8, 213u8, 184u8, 199u8, 1u8, 189u8, 86u8, 40u8,
    196u8, 233u8, 111u8, 128u8, 64u8, 176u8, 149u8, 138u8, 57u8, 161u8, 49u8,
    87u8, 204u8, 121u8, 6u8, 100u8, 221u8, 95u8, 79u8, 6u8, 101u8, 169u8, 28u8,
    158u8, 233u8, 118u8, 60u8, 70u8, 172u8, 56u8, 247u8, 125u8, 53u8, 238u8,
    31u8, 81u8, 11u8, 144u8, 76u8, 80u8, 118u8, 83u8, 145u8, 162u8, 204u8,
    105u8, 58u8, 74u8, 92u8, 205u8, 197u8, 142u8, 61u8, 15u8, 49u8, 219u8,
    14u8, 228u8, 186u8, 50u8, 96u8, 166u8, 159u8, 37u8, 160u8, 201u8, 137u8,
    10u8, 255u8, 107u8, 130u8, 162u8, 12u8, 131u8, 227u8, 196u8, 30u8, 141u8,
    67u8, 66u8, 127u8, 249u8, 27u8, 155u8, 255u8, 130u8, 148u8, 179u8, 29u8,
    3u8, 55u8, 153u8, 82u8, 178u8, 114u8, 246u8, 233u8, 72u8, 171u8, 118u8,
    206u8, 19u8, 102u8, 253u8, 249u8, 132u8, 210u8, 106u8, 87u8, 110u8, 33u8,
    215u8, 224u8, 40u8, 88u8, 12u8, 84u8, 17u8, 233u8, 246u8, 60u8, 26u8, 62u8,
    90u8, 173u8, 85u8, 50u8, 215u8, 147u8, 6u8, 70u8, 13u8, 209u8, 137u8, 38u8,
    26u8, 102u8, 159u8, 188u8, 63u8, 225u8, 64u8, 12u8, 77u8, 123u8, 66u8,
    50u8, 82u8, 193u8, 116u8, 27u8, 198u8, 60u8, 161u8, 222u8, 212u8, 216u8,
    27u8, 170u8, 77u8, 3u8, 27u8, 28u8, 25u8, 219u8, 18u8, 141u8, 110u8, 21u8,
    2u8, 1u8, 220u8, 248u8, 10u8, 184u8, 206u8, 249u8, 38u8, 45u8, 187u8, 29u8,
    167u8, 228u8, 123u8, 92u8, 14u8, 138u8, 94u8, 95u8, 51u8, 76u8, 155u8,
    248u8, 242u8, 171u8, 120u8, 122u8, 165u8, 154u8, 147u8, 2u8, 17u8, 246u8,
    17u8, 133u8, 124u8, 211u8, 211u8, 198u8, 192u8, 191u8, 24u8, 240u8, 173u8,
    124u8, 107u8, 182u8, 34u8, 24u8, 121u8, 255u8, 63u8, 15u8, 86u8, 194u8,
    208u8, 226u8, 68u8, 152u8, 138u8, 87u8, 5u8, 206u8, 37u8, 111u8, 46u8,
    241u8, 142u8, 98u8, 186u8, 39u8, 73u8, 88u8, 130u8, 6u8, 84u8, 96u8, 240u8,
    46u8, 194u8, 108u8, 94u8, 187u8, 242u8, 211u8, 139u8, 228u8, 122u8, 52u8,
    20u8, 34u8, 133u8, 230u8, 219u8, 156u8, 16u8, 81u8, 95u8, 184u8, 228u8,
    62u8, 54u8, 1u8, 177u8, 128u8, 195u8, 128u8, 148u8, 7u8, 62u8, 31u8, 255u8,
    236u8, 213u8, 247u8, 34u8, 248u8, 3u8, 204u8, 29u8, 221u8, 128u8, 139u8,
    22u8, 54u8, 37u8, 34u8, 179u8, 150u8, 17u8, 51u8, 37u8, 94u8, 228u8, 205u8,
    42u8, 253u8, 4u8, 11u8, 138u8, 211u8, 185u8, 117u8, 160u8, 243u8, 94u8,
    178u8, 45u8, 230u8, 186u8, 124u8, 244u8, 169u8, 95u8, 130u8, 179u8, 158u8,
    49u8, 154u8, 219u8, 95u8, 157u8, 102u8, 229u8, 88u8, 113u8, 116u8, 250u8,
    219u8, 116u8, 154u8, 152u8, 225u8, 44u8, 160u8, 251u8, 101u8, 198u8, 191u8,
    91u8, 93u8, 220u8, 78u8, 104u8, 121u8,
];
/// Convert verifying key
pub const NAMADA_MASP_CONVERT_VK_BYTES: &'static [u8] = &[
    13u8, 184u8, 130u8, 207u8, 93u8, 179u8, 232u8, 86u8, 127u8, 22u8, 180u8,
    219u8, 23u8, 114u8, 212u8, 209u8, 245u8, 163u8, 254u8, 141u8, 98u8, 240u8,
    223u8, 46u8, 184u8, 165u8, 207u8, 165u8, 8u8, 6u8, 112u8, 42u8, 253u8,
    232u8, 252u8, 37u8, 51u8, 94u8, 181u8, 236u8, 133u8, 156u8, 40u8, 24u8,
    178u8, 97u8, 11u8, 46u8, 25u8, 171u8, 68u8, 93u8, 172u8, 114u8, 11u8,
    177u8, 242u8, 176u8, 205u8, 51u8, 54u8, 247u8, 161u8, 172u8, 198u8, 43u8,
    241u8, 179u8, 163u8, 33u8, 130u8, 98u8, 100u8, 220u8, 126u8, 70u8, 146u8,
    129u8, 226u8, 59u8, 33u8, 131u8, 148u8, 213u8, 152u8, 104u8, 157u8, 160u8,
    78u8, 19u8, 104u8, 120u8, 255u8, 154u8, 120u8, 151u8, 1u8, 74u8, 120u8,
    168u8, 209u8, 113u8, 128u8, 163u8, 124u8, 76u8, 168u8, 251u8, 35u8, 31u8,
    38u8, 74u8, 184u8, 155u8, 209u8, 72u8, 99u8, 119u8, 127u8, 193u8, 255u8,
    233u8, 1u8, 253u8, 146u8, 68u8, 67u8, 101u8, 209u8, 143u8, 120u8, 35u8,
    118u8, 18u8, 172u8, 56u8, 227u8, 159u8, 65u8, 156u8, 50u8, 240u8, 130u8,
    69u8, 21u8, 33u8, 158u8, 196u8, 92u8, 38u8, 193u8, 250u8, 213u8, 48u8,
    81u8, 78u8, 216u8, 145u8, 160u8, 208u8, 4u8, 58u8, 206u8, 223u8, 52u8,
    137u8, 34u8, 16u8, 46u8, 149u8, 179u8, 230u8, 208u8, 126u8, 10u8, 250u8,
    148u8, 197u8, 138u8, 164u8, 20u8, 128u8, 99u8, 31u8, 193u8, 202u8, 54u8,
    229u8, 90u8, 174u8, 81u8, 253u8, 10u8, 65u8, 107u8, 129u8, 135u8, 69u8,
    11u8, 40u8, 240u8, 37u8, 196u8, 33u8, 227u8, 255u8, 20u8, 211u8, 143u8,
    154u8, 189u8, 154u8, 242u8, 241u8, 4u8, 107u8, 145u8, 75u8, 83u8, 171u8,
    55u8, 233u8, 174u8, 187u8, 166u8, 131u8, 203u8, 37u8, 40u8, 78u8, 92u8,
    34u8, 250u8, 52u8, 17u8, 41u8, 152u8, 82u8, 80u8, 161u8, 3u8, 84u8, 125u8,
    229u8, 208u8, 5u8, 223u8, 72u8, 38u8, 95u8, 124u8, 178u8, 88u8, 22u8, 34u8,
    83u8, 213u8, 111u8, 188u8, 104u8, 45u8, 16u8, 106u8, 30u8, 203u8, 7u8,
    102u8, 110u8, 191u8, 117u8, 36u8, 163u8, 100u8, 229u8, 18u8, 195u8, 122u8,
    166u8, 47u8, 130u8, 214u8, 231u8, 221u8, 78u8, 216u8, 131u8, 132u8, 120u8,
    16u8, 67u8, 118u8, 169u8, 128u8, 114u8, 118u8, 108u8, 41u8, 149u8, 147u8,
    88u8, 233u8, 205u8, 230u8, 164u8, 152u8, 86u8, 24u8, 246u8, 94u8, 162u8,
    87u8, 232u8, 242u8, 136u8, 151u8, 79u8, 74u8, 237u8, 222u8, 82u8, 229u8,
    218u8, 194u8, 251u8, 122u8, 229u8, 211u8, 14u8, 171u8, 124u8, 216u8, 40u8,
    162u8, 200u8, 177u8, 95u8, 21u8, 177u8, 111u8, 19u8, 159u8, 44u8, 51u8,
    239u8, 51u8, 214u8, 59u8, 239u8, 228u8, 4u8, 230u8, 150u8, 201u8, 112u8,
    119u8, 209u8, 126u8, 164u8, 47u8, 79u8, 249u8, 216u8, 46u8, 196u8, 86u8,
    170u8, 244u8, 57u8, 20u8, 163u8, 208u8, 121u8, 104u8, 17u8, 26u8, 58u8,
    52u8, 143u8, 21u8, 126u8, 100u8, 192u8, 39u8, 138u8, 19u8, 224u8, 43u8,
    96u8, 82u8, 113u8, 159u8, 96u8, 125u8, 172u8, 211u8, 160u8, 136u8, 39u8,
    79u8, 101u8, 89u8, 107u8, 208u8, 208u8, 153u8, 32u8, 182u8, 26u8, 181u8,
    218u8, 97u8, 187u8, 220u8, 127u8, 80u8, 73u8, 51u8, 76u8, 241u8, 18u8,
    19u8, 148u8, 93u8, 87u8, 229u8, 172u8, 125u8, 5u8, 93u8, 4u8, 43u8, 126u8,
    2u8, 74u8, 162u8, 178u8, 240u8, 143u8, 10u8, 145u8, 38u8, 8u8, 5u8, 39u8,
    45u8, 197u8, 16u8, 81u8, 198u8, 228u8, 122u8, 212u8, 250u8, 64u8, 59u8,
    2u8, 180u8, 81u8, 11u8, 100u8, 122u8, 227u8, 209u8, 119u8, 11u8, 172u8,
    3u8, 38u8, 168u8, 5u8, 187u8, 239u8, 212u8, 128u8, 86u8, 200u8, 193u8,
    33u8, 189u8, 184u8, 6u8, 6u8, 196u8, 160u8, 46u8, 167u8, 52u8, 204u8, 50u8,
    172u8, 210u8, 176u8, 43u8, 194u8, 139u8, 153u8, 203u8, 62u8, 40u8, 126u8,
    133u8, 167u8, 99u8, 175u8, 38u8, 116u8, 146u8, 171u8, 87u8, 46u8, 153u8,
    171u8, 63u8, 55u8, 13u8, 39u8, 92u8, 236u8, 29u8, 161u8, 170u8, 169u8, 7u8,
    95u8, 240u8, 95u8, 121u8, 190u8, 12u8, 229u8, 213u8, 39u8, 114u8, 125u8,
    110u8, 17u8, 140u8, 201u8, 205u8, 198u8, 218u8, 46u8, 53u8, 26u8, 173u8,
    253u8, 155u8, 170u8, 140u8, 189u8, 211u8, 167u8, 109u8, 66u8, 154u8, 105u8,
    81u8, 96u8, 209u8, 44u8, 146u8, 58u8, 201u8, 204u8, 59u8, 172u8, 162u8,
    137u8, 225u8, 147u8, 84u8, 134u8, 8u8, 184u8, 40u8, 1u8, 18u8, 167u8, 22u8,
    41u8, 157u8, 2u8, 67u8, 181u8, 110u8, 102u8, 58u8, 173u8, 53u8, 87u8, 86u8,
    136u8, 42u8, 84u8, 139u8, 205u8, 183u8, 182u8, 50u8, 175u8, 56u8, 114u8,
    174u8, 254u8, 33u8, 252u8, 70u8, 59u8, 140u8, 118u8, 203u8, 24u8, 78u8,
    54u8, 55u8, 106u8, 219u8, 22u8, 104u8, 110u8, 52u8, 102u8, 179u8, 233u8,
    12u8, 231u8, 38u8, 39u8, 87u8, 7u8, 213u8, 164u8, 232u8, 146u8, 71u8, 94u8,
    188u8, 83u8, 133u8, 50u8, 47u8, 196u8, 97u8, 22u8, 78u8, 164u8, 247u8,
    95u8, 16u8, 210u8, 66u8, 78u8, 125u8, 90u8, 108u8, 183u8, 80u8, 206u8,
    133u8, 229u8, 34u8, 5u8, 141u8, 47u8, 90u8, 128u8, 90u8, 172u8, 65u8,
    126u8, 127u8, 74u8, 22u8, 244u8, 102u8, 41u8, 198u8, 245u8, 226u8, 133u8,
    248u8, 186u8, 183u8, 47u8, 230u8, 212u8, 19u8, 110u8, 217u8, 218u8, 41u8,
    74u8, 155u8, 178u8, 21u8, 243u8, 215u8, 77u8, 6u8, 131u8, 219u8, 138u8,
    99u8, 151u8, 220u8, 114u8, 10u8, 113u8, 137u8, 91u8, 249u8, 217u8, 97u8,
    196u8, 59u8, 95u8, 38u8, 63u8, 181u8, 194u8, 15u8, 178u8, 175u8, 98u8,
    81u8, 245u8, 47u8, 255u8, 166u8, 87u8, 142u8, 237u8, 134u8, 195u8, 163u8,
    12u8, 131u8, 1u8, 223u8, 114u8, 204u8, 221u8, 60u8, 157u8, 57u8, 178u8,
    123u8, 158u8, 117u8, 225u8, 25u8, 178u8, 124u8, 244u8, 216u8, 171u8, 186u8,
    190u8, 194u8, 25u8, 13u8, 203u8, 104u8, 45u8, 226u8, 241u8, 88u8, 206u8,
    5u8, 213u8, 12u8, 168u8, 53u8, 115u8, 166u8, 8u8, 63u8, 28u8, 76u8, 182u8,
    48u8, 105u8, 250u8, 206u8, 132u8, 113u8, 127u8, 206u8, 225u8, 46u8, 245u8,
    14u8, 122u8, 157u8, 250u8, 201u8, 233u8, 44u8, 169u8, 125u8, 209u8, 113u8,
    118u8, 103u8, 148u8, 209u8, 255u8, 17u8, 72u8, 107u8, 111u8, 239u8, 80u8,
    179u8, 161u8, 206u8, 9u8, 249u8, 195u8, 173u8, 223u8, 153u8, 20u8, 6u8,
    129u8, 200u8, 238u8, 68u8, 162u8, 100u8, 146u8, 139u8, 212u8, 122u8, 180u8,
    56u8, 185u8, 29u8, 232u8, 111u8, 63u8, 32u8, 146u8, 192u8, 228u8, 154u8,
    192u8, 109u8, 184u8, 236u8, 226u8, 232u8, 149u8, 130u8, 81u8, 22u8, 188u8,
    51u8, 191u8, 186u8, 13u8, 50u8, 79u8, 98u8, 0u8, 0u8, 0u8, 4u8, 18u8, 17u8,
    98u8, 220u8, 255u8, 144u8, 161u8, 174u8, 110u8, 119u8, 47u8, 57u8, 58u8,
    190u8, 176u8, 108u8, 217u8, 176u8, 116u8, 90u8, 33u8, 95u8, 148u8, 52u8,
    219u8, 142u8, 64u8, 120u8, 252u8, 51u8, 243u8, 91u8, 26u8, 2u8, 115u8,
    155u8, 250u8, 70u8, 23u8, 61u8, 186u8, 18u8, 71u8, 34u8, 93u8, 78u8, 162u8,
    52u8, 19u8, 189u8, 134u8, 134u8, 230u8, 225u8, 153u8, 159u8, 188u8, 103u8,
    244u8, 70u8, 44u8, 76u8, 28u8, 248u8, 181u8, 212u8, 99u8, 4u8, 231u8,
    114u8, 62u8, 250u8, 121u8, 30u8, 154u8, 27u8, 140u8, 222u8, 89u8, 205u8,
    235u8, 191u8, 72u8, 27u8, 238u8, 172u8, 78u8, 170u8, 84u8, 131u8, 254u8,
    209u8, 55u8, 48u8, 133u8, 89u8, 23u8, 84u8, 76u8, 70u8, 20u8, 33u8, 174u8,
    196u8, 240u8, 184u8, 63u8, 120u8, 189u8, 228u8, 71u8, 157u8, 3u8, 198u8,
    126u8, 122u8, 5u8, 248u8, 16u8, 155u8, 67u8, 52u8, 8u8, 206u8, 171u8,
    236u8, 11u8, 196u8, 13u8, 237u8, 108u8, 230u8, 154u8, 245u8, 210u8, 105u8,
    243u8, 61u8, 247u8, 82u8, 18u8, 102u8, 125u8, 34u8, 25u8, 38u8, 254u8,
    36u8, 210u8, 214u8, 81u8, 67u8, 188u8, 20u8, 137u8, 34u8, 135u8, 29u8,
    115u8, 168u8, 88u8, 121u8, 62u8, 15u8, 121u8, 189u8, 205u8, 5u8, 129u8,
    245u8, 228u8, 87u8, 116u8, 170u8, 94u8, 35u8, 134u8, 199u8, 25u8, 198u8,
    103u8, 35u8, 68u8, 157u8, 238u8, 21u8, 23u8, 143u8, 236u8, 228u8, 35u8,
    37u8, 9u8, 154u8, 144u8, 49u8, 132u8, 79u8, 139u8, 98u8, 24u8, 122u8,
    232u8, 91u8, 221u8, 40u8, 84u8, 77u8, 212u8, 205u8, 124u8, 71u8, 26u8,
    205u8, 32u8, 79u8, 163u8, 214u8, 29u8, 122u8, 76u8, 27u8, 13u8, 8u8, 206u8,
    128u8, 123u8, 147u8, 24u8, 231u8, 172u8, 32u8, 39u8, 72u8, 24u8, 223u8,
    140u8, 178u8, 53u8, 132u8, 3u8, 40u8, 91u8, 150u8, 146u8, 131u8, 56u8,
    43u8, 215u8, 163u8, 15u8, 82u8, 157u8, 69u8, 207u8, 67u8, 173u8, 185u8,
    73u8, 245u8, 170u8, 253u8, 140u8, 125u8, 203u8, 26u8, 54u8, 70u8, 77u8,
    159u8, 88u8, 178u8, 165u8, 147u8, 90u8, 100u8, 103u8, 195u8, 147u8, 251u8,
    52u8, 136u8, 118u8, 48u8, 242u8, 211u8, 43u8, 69u8, 19u8, 112u8, 209u8,
    11u8, 43u8, 115u8, 11u8, 228u8, 94u8, 72u8, 7u8, 45u8, 127u8, 223u8, 147u8,
    123u8, 95u8, 98u8, 166u8, 51u8, 8u8, 96u8, 180u8, 63u8, 63u8, 63u8, 36u8,
    194u8, 154u8, 210u8, 103u8, 208u8, 176u8, 74u8, 175u8, 38u8, 86u8, 5u8,
    113u8, 64u8, 87u8, 74u8, 30u8, 155u8, 236u8, 250u8, 230u8, 203u8, 20u8,
    3u8, 203u8, 250u8, 5u8, 111u8, 148u8, 129u8, 28u8, 70u8, 89u8, 235u8,
    198u8, 163u8, 168u8, 43u8, 109u8, 222u8, 147u8, 228u8, 253u8, 84u8, 215u8,
    12u8, 201u8, 225u8, 47u8, 183u8, 138u8, 236u8, 62u8, 189u8, 223u8, 232u8,
    201u8, 68u8, 122u8, 133u8, 137u8, 143u8, 238u8, 195u8, 62u8, 238u8, 65u8,
    136u8, 242u8, 194u8,
];
/// Output verifying key
pub const NAMADA_MASP_OUTPUT_VK_BYTES: &'static [u8] = &[
    13u8, 184u8, 130u8, 207u8, 93u8, 179u8, 232u8, 86u8, 127u8, 22u8, 180u8,
    219u8, 23u8, 114u8, 212u8, 209u8, 245u8, 163u8, 254u8, 141u8, 98u8, 240u8,
    223u8, 46u8, 184u8, 165u8, 207u8, 165u8, 8u8, 6u8, 112u8, 42u8, 253u8,
    232u8, 252u8, 37u8, 51u8, 94u8, 181u8, 236u8, 133u8, 156u8, 40u8, 24u8,
    178u8, 97u8, 11u8, 46u8, 25u8, 171u8, 68u8, 93u8, 172u8, 114u8, 11u8,
    177u8, 242u8, 176u8, 205u8, 51u8, 54u8, 247u8, 161u8, 172u8, 198u8, 43u8,
    241u8, 179u8, 163u8, 33u8, 130u8, 98u8, 100u8, 220u8, 126u8, 70u8, 146u8,
    129u8, 226u8, 59u8, 33u8, 131u8, 148u8, 213u8, 152u8, 104u8, 157u8, 160u8,
    78u8, 19u8, 104u8, 120u8, 255u8, 154u8, 120u8, 151u8, 1u8, 74u8, 120u8,
    168u8, 209u8, 113u8, 128u8, 163u8, 124u8, 76u8, 168u8, 251u8, 35u8, 31u8,
    38u8, 74u8, 184u8, 155u8, 209u8, 72u8, 99u8, 119u8, 127u8, 193u8, 255u8,
    233u8, 1u8, 253u8, 146u8, 68u8, 67u8, 101u8, 209u8, 143u8, 120u8, 35u8,
    118u8, 18u8, 172u8, 56u8, 227u8, 159u8, 65u8, 156u8, 50u8, 240u8, 130u8,
    69u8, 21u8, 33u8, 158u8, 196u8, 92u8, 38u8, 193u8, 250u8, 213u8, 48u8,
    81u8, 78u8, 216u8, 145u8, 160u8, 208u8, 4u8, 58u8, 206u8, 223u8, 52u8,
    137u8, 34u8, 16u8, 46u8, 149u8, 179u8, 230u8, 208u8, 126u8, 10u8, 250u8,
    148u8, 197u8, 138u8, 164u8, 20u8, 128u8, 99u8, 31u8, 193u8, 202u8, 54u8,
    229u8, 90u8, 174u8, 81u8, 253u8, 10u8, 65u8, 107u8, 129u8, 135u8, 69u8,
    11u8, 40u8, 240u8, 37u8, 196u8, 33u8, 227u8, 255u8, 20u8, 211u8, 143u8,
    154u8, 189u8, 154u8, 242u8, 241u8, 4u8, 107u8, 145u8, 75u8, 83u8, 171u8,
    55u8, 233u8, 174u8, 187u8, 166u8, 131u8, 203u8, 37u8, 40u8, 78u8, 92u8,
    34u8, 250u8, 52u8, 17u8, 41u8, 152u8, 82u8, 80u8, 161u8, 3u8, 84u8, 125u8,
    229u8, 208u8, 5u8, 223u8, 72u8, 38u8, 95u8, 124u8, 178u8, 88u8, 22u8, 34u8,
    83u8, 213u8, 111u8, 188u8, 104u8, 45u8, 16u8, 106u8, 30u8, 203u8, 7u8,
    102u8, 110u8, 191u8, 117u8, 36u8, 163u8, 100u8, 229u8, 18u8, 195u8, 122u8,
    166u8, 47u8, 130u8, 214u8, 231u8, 221u8, 78u8, 216u8, 131u8, 132u8, 120u8,
    16u8, 67u8, 118u8, 169u8, 128u8, 114u8, 118u8, 108u8, 41u8, 149u8, 147u8,
    88u8, 233u8, 205u8, 230u8, 164u8, 152u8, 86u8, 24u8, 246u8, 94u8, 162u8,
    87u8, 232u8, 242u8, 136u8, 151u8, 79u8, 74u8, 237u8, 222u8, 82u8, 229u8,
    218u8, 194u8, 251u8, 122u8, 229u8, 211u8, 14u8, 171u8, 124u8, 216u8, 40u8,
    162u8, 200u8, 177u8, 95u8, 21u8, 177u8, 111u8, 19u8, 159u8, 44u8, 51u8,
    239u8, 51u8, 214u8, 59u8, 239u8, 228u8, 4u8, 230u8, 150u8, 201u8, 112u8,
    119u8, 209u8, 126u8, 164u8, 47u8, 79u8, 249u8, 216u8, 46u8, 196u8, 86u8,
    170u8, 244u8, 57u8, 20u8, 163u8, 208u8, 121u8, 104u8, 17u8, 26u8, 58u8,
    52u8, 143u8, 21u8, 126u8, 100u8, 192u8, 39u8, 138u8, 19u8, 224u8, 43u8,
    96u8, 82u8, 113u8, 159u8, 96u8, 125u8, 172u8, 211u8, 160u8, 136u8, 39u8,
    79u8, 101u8, 89u8, 107u8, 208u8, 208u8, 153u8, 32u8, 182u8, 26u8, 181u8,
    218u8, 97u8, 187u8, 220u8, 127u8, 80u8, 73u8, 51u8, 76u8, 241u8, 18u8,
    19u8, 148u8, 93u8, 87u8, 229u8, 172u8, 125u8, 5u8, 93u8, 4u8, 43u8, 126u8,
    2u8, 74u8, 162u8, 178u8, 240u8, 143u8, 10u8, 145u8, 38u8, 8u8, 5u8, 39u8,
    45u8, 197u8, 16u8, 81u8, 198u8, 228u8, 122u8, 212u8, 250u8, 64u8, 59u8,
    2u8, 180u8, 81u8, 11u8, 100u8, 122u8, 227u8, 209u8, 119u8, 11u8, 172u8,
    3u8, 38u8, 168u8, 5u8, 187u8, 239u8, 212u8, 128u8, 86u8, 200u8, 193u8,
    33u8, 189u8, 184u8, 6u8, 6u8, 196u8, 160u8, 46u8, 167u8, 52u8, 204u8, 50u8,
    172u8, 210u8, 176u8, 43u8, 194u8, 139u8, 153u8, 203u8, 62u8, 40u8, 126u8,
    133u8, 167u8, 99u8, 175u8, 38u8, 116u8, 146u8, 171u8, 87u8, 46u8, 153u8,
    171u8, 63u8, 55u8, 13u8, 39u8, 92u8, 236u8, 29u8, 161u8, 170u8, 169u8, 7u8,
    95u8, 240u8, 95u8, 121u8, 190u8, 12u8, 229u8, 213u8, 39u8, 114u8, 125u8,
    110u8, 17u8, 140u8, 201u8, 205u8, 198u8, 218u8, 46u8, 53u8, 26u8, 173u8,
    253u8, 155u8, 170u8, 140u8, 189u8, 211u8, 167u8, 109u8, 66u8, 154u8, 105u8,
    81u8, 96u8, 209u8, 44u8, 146u8, 58u8, 201u8, 204u8, 59u8, 172u8, 162u8,
    137u8, 225u8, 147u8, 84u8, 134u8, 8u8, 184u8, 40u8, 1u8, 3u8, 128u8, 183u8,
    200u8, 160u8, 201u8, 184u8, 33u8, 242u8, 26u8, 165u8, 239u8, 193u8, 20u8,
    134u8, 244u8, 115u8, 19u8, 78u8, 177u8, 137u8, 30u8, 193u8, 102u8, 65u8,
    89u8, 126u8, 251u8, 255u8, 184u8, 129u8, 37u8, 147u8, 135u8, 193u8, 92u8,
    187u8, 79u8, 75u8, 47u8, 90u8, 215u8, 6u8, 232u8, 131u8, 186u8, 246u8,
    73u8, 7u8, 127u8, 15u8, 65u8, 41u8, 9u8, 246u8, 80u8, 27u8, 206u8, 170u8,
    133u8, 154u8, 253u8, 205u8, 7u8, 126u8, 206u8, 234u8, 93u8, 254u8, 96u8,
    35u8, 138u8, 25u8, 150u8, 222u8, 194u8, 195u8, 186u8, 15u8, 201u8, 197u8,
    62u8, 26u8, 227u8, 11u8, 85u8, 224u8, 195u8, 62u8, 184u8, 1u8, 1u8, 73u8,
    5u8, 50u8, 233u8, 1u8, 147u8, 247u8, 60u8, 172u8, 198u8, 242u8, 154u8,
    76u8, 58u8, 152u8, 138u8, 130u8, 96u8, 175u8, 182u8, 168u8, 29u8, 107u8,
    16u8, 107u8, 24u8, 62u8, 71u8, 223u8, 99u8, 88u8, 160u8, 66u8, 11u8, 163u8,
    197u8, 126u8, 113u8, 74u8, 198u8, 224u8, 98u8, 245u8, 198u8, 40u8, 19u8,
    27u8, 100u8, 164u8, 34u8, 93u8, 71u8, 17u8, 117u8, 247u8, 99u8, 15u8,
    247u8, 214u8, 231u8, 123u8, 238u8, 154u8, 118u8, 133u8, 97u8, 203u8, 1u8,
    7u8, 253u8, 44u8, 59u8, 67u8, 145u8, 174u8, 191u8, 115u8, 29u8, 243u8,
    195u8, 159u8, 74u8, 151u8, 155u8, 247u8, 117u8, 204u8, 184u8, 238u8, 234u8,
    54u8, 74u8, 160u8, 177u8, 184u8, 182u8, 187u8, 116u8, 19u8, 17u8, 6u8,
    188u8, 73u8, 120u8, 28u8, 145u8, 63u8, 77u8, 124u8, 222u8, 33u8, 97u8,
    214u8, 109u8, 130u8, 215u8, 217u8, 188u8, 165u8, 218u8, 219u8, 220u8,
    216u8, 126u8, 127u8, 170u8, 179u8, 220u8, 113u8, 239u8, 171u8, 204u8,
    119u8, 153u8, 7u8, 87u8, 42u8, 224u8, 76u8, 111u8, 233u8, 196u8, 254u8,
    249u8, 58u8, 158u8, 157u8, 62u8, 12u8, 243u8, 122u8, 93u8, 46u8, 212u8,
    69u8, 135u8, 30u8, 45u8, 196u8, 120u8, 154u8, 85u8, 212u8, 9u8, 34u8,
    195u8, 44u8, 86u8, 7u8, 122u8, 100u8, 166u8, 89u8, 178u8, 60u8, 42u8,
    225u8, 151u8, 28u8, 108u8, 241u8, 60u8, 195u8, 247u8, 198u8, 18u8, 248u8,
    8u8, 1u8, 139u8, 15u8, 161u8, 133u8, 235u8, 86u8, 201u8, 0u8, 0u8, 0u8,
    6u8, 13u8, 220u8, 204u8, 208u8, 166u8, 167u8, 131u8, 236u8, 102u8, 198u8,
    44u8, 151u8, 212u8, 172u8, 7u8, 123u8, 66u8, 204u8, 199u8, 57u8, 15u8,
    164u8, 66u8, 194u8, 129u8, 18u8, 53u8, 65u8, 29u8, 187u8, 185u8, 59u8,
    141u8, 62u8, 217u8, 119u8, 138u8, 55u8, 62u8, 32u8, 229u8, 18u8, 76u8,
    150u8, 110u8, 179u8, 48u8, 59u8, 3u8, 133u8, 184u8, 137u8, 198u8, 58u8,
    249u8, 36u8, 116u8, 224u8, 17u8, 43u8, 203u8, 121u8, 193u8, 56u8, 20u8,
    146u8, 204u8, 125u8, 100u8, 46u8, 49u8, 99u8, 228u8, 243u8, 187u8, 128u8,
    102u8, 10u8, 127u8, 30u8, 242u8, 134u8, 220u8, 89u8, 160u8, 238u8, 46u8,
    201u8, 230u8, 160u8, 126u8, 197u8, 177u8, 202u8, 198u8, 39u8, 0u8, 97u8,
    3u8, 57u8, 121u8, 231u8, 147u8, 190u8, 77u8, 28u8, 216u8, 109u8, 190u8,
    0u8, 11u8, 238u8, 129u8, 160u8, 222u8, 117u8, 158u8, 244u8, 32u8, 40u8,
    112u8, 162u8, 35u8, 67u8, 134u8, 179u8, 122u8, 245u8, 59u8, 247u8, 115u8,
    112u8, 254u8, 178u8, 152u8, 158u8, 243u8, 32u8, 85u8, 91u8, 188u8, 164u8,
    132u8, 51u8, 13u8, 149u8, 6u8, 8u8, 139u8, 69u8, 90u8, 8u8, 22u8, 170u8,
    7u8, 177u8, 81u8, 25u8, 200u8, 250u8, 184u8, 47u8, 172u8, 151u8, 0u8, 87u8,
    67u8, 71u8, 238u8, 96u8, 238u8, 52u8, 128u8, 27u8, 246u8, 216u8, 149u8,
    34u8, 119u8, 132u8, 105u8, 168u8, 130u8, 250u8, 97u8, 159u8, 62u8, 134u8,
    183u8, 24u8, 221u8, 178u8, 21u8, 170u8, 247u8, 184u8, 153u8, 163u8, 139u8,
    102u8, 37u8, 233u8, 243u8, 192u8, 46u8, 12u8, 93u8, 48u8, 135u8, 119u8,
    175u8, 21u8, 244u8, 120u8, 193u8, 252u8, 219u8, 124u8, 232u8, 66u8, 172u8,
    74u8, 251u8, 224u8, 215u8, 100u8, 241u8, 180u8, 175u8, 97u8, 59u8, 105u8,
    132u8, 29u8, 230u8, 31u8, 177u8, 143u8, 144u8, 2u8, 16u8, 77u8, 73u8,
    236u8, 234u8, 24u8, 191u8, 160u8, 76u8, 88u8, 72u8, 38u8, 223u8, 176u8,
    250u8, 19u8, 19u8, 235u8, 209u8, 19u8, 192u8, 191u8, 223u8, 134u8, 162u8,
    95u8, 101u8, 61u8, 225u8, 193u8, 23u8, 24u8, 149u8, 36u8, 54u8, 237u8,
    134u8, 17u8, 64u8, 164u8, 141u8, 152u8, 64u8, 5u8, 130u8, 165u8, 1u8,
    209u8, 8u8, 57u8, 172u8, 168u8, 63u8, 186u8, 50u8, 235u8, 187u8, 161u8,
    30u8, 121u8, 123u8, 162u8, 141u8, 238u8, 243u8, 237u8, 236u8, 221u8, 242u8,
    173u8, 247u8, 68u8, 94u8, 28u8, 51u8, 60u8, 143u8, 165u8, 136u8, 217u8,
    87u8, 169u8, 63u8, 174u8, 197u8, 199u8, 7u8, 249u8, 150u8, 107u8, 23u8,
    107u8, 125u8, 186u8, 193u8, 110u8, 5u8, 148u8, 200u8, 178u8, 30u8, 10u8,
    91u8, 158u8, 45u8, 68u8, 72u8, 33u8, 159u8, 46u8, 184u8, 76u8, 187u8, 29u8,
    9u8, 249u8, 109u8, 135u8, 142u8, 22u8, 60u8, 100u8, 218u8, 184u8, 22u8,
    1u8, 111u8, 5u8, 219u8, 66u8, 183u8, 108u8, 250u8, 70u8, 44u8, 193u8,
    200u8, 187u8, 22u8, 175u8, 19u8, 46u8, 67u8, 70u8, 17u8, 236u8, 154u8,
    201u8, 156u8, 185u8, 4u8, 185u8, 201u8, 138u8, 167u8, 84u8, 172u8, 190u8,
    107u8, 160u8, 44u8, 102u8, 66u8, 253u8, 213u8, 196u8, 82u8, 198u8, 233u8,
    237u8, 211u8, 7u8, 122u8, 75u8, 33u8, 89u8, 55u8, 213u8, 150u8, 63u8, 31u8,
    26u8, 155u8, 13u8, 104u8, 103u8, 255u8, 208u8, 7u8, 219u8, 6u8, 42u8, 18u8,
    48u8, 186u8, 97u8, 219u8, 219u8, 8u8, 94u8, 77u8, 8u8, 33u8, 51u8, 112u8,
    132u8, 40u8, 9u8, 62u8, 28u8, 35u8, 83u8, 199u8, 83u8, 92u8, 144u8, 233u8,
    224u8, 136u8, 211u8, 210u8, 245u8, 11u8, 206u8, 130u8, 229u8, 132u8, 236u8,
    102u8, 90u8, 244u8, 134u8, 145u8, 73u8, 143u8, 141u8, 234u8, 140u8, 71u8,
    65u8, 16u8, 18u8, 100u8, 103u8, 209u8, 186u8, 92u8, 48u8, 31u8, 118u8,
    43u8, 131u8, 19u8, 87u8, 173u8, 108u8, 102u8, 111u8, 175u8, 169u8, 198u8,
    133u8, 120u8, 138u8, 88u8, 48u8, 251u8, 86u8, 26u8, 135u8, 91u8, 2u8, 72u8,
    43u8, 15u8, 177u8, 158u8, 130u8, 86u8, 108u8, 227u8, 30u8, 128u8, 16u8,
    5u8, 16u8, 172u8, 79u8, 9u8, 101u8, 108u8, 198u8, 91u8, 160u8, 90u8, 59u8,
    78u8, 86u8, 184u8, 65u8, 116u8, 15u8, 147u8, 83u8, 73u8, 2u8, 0u8, 116u8,
    84u8, 6u8, 209u8, 114u8, 231u8, 173u8, 129u8, 138u8, 193u8, 92u8, 109u8,
    231u8, 147u8, 3u8, 119u8, 91u8, 232u8, 239u8, 115u8, 111u8, 29u8, 213u8,
    146u8, 9u8, 138u8, 55u8, 48u8, 250u8,
];

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

/// The network to use for MASP
#[cfg(feature = "mainnet")]
const NETWORK: MainNetwork = MainNetwork;
#[cfg(not(feature = "mainnet"))]
const NETWORK: TestNetwork = TestNetwork;

// TODO these could be exported from masp_proof crate
/// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
/// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
/// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

fn prepare_verifying_keys() -> [PreparedVerifyingKey<Bls12>; 3] {
    [
        NAMADA_MASP_SPEND_VK_BYTES,
        NAMADA_MASP_CONVERT_VK_BYTES,
        NAMADA_MASP_OUTPUT_VK_BYTES,
    ]
    .map(|vk_bytes| {
        let vk = VerifyingKey::<Bls12>::read(vk_bytes)
            .expect("expected to deserialize verifying keys");
        prepare_verifying_key(&vk)
    })
}

#[cfg(test)]
fn load_pvks() -> (
    PreparedVerifyingKey<Bls12>,
    PreparedVerifyingKey<Bls12>,
    PreparedVerifyingKey<Bls12>,
) {
    let params_dir = get_params_dir();
    let [spend_path, convert_path, output_path] =
        [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| params_dir.join(p));

    if !spend_path.exists() || !convert_path.exists() || !output_path.exists() {
        let paths = masp_proofs::download_masp_parameters(None).expect(
            "MASP parameters were not present, expected the download to \
             succeed",
        );
        if paths.spend != spend_path
            || paths.convert != convert_path
            || paths.output != output_path
        {
            panic!(
                "unrecoverable: downloaded missing masp params, but to an \
                 unfamiliar path"
            )
        }
    }
    // size and blake2b checked here
    let params = masp_proofs::load_parameters(
        spend_path.as_path(),
        output_path.as_path(),
        convert_path.as_path(),
    );
    (params.spend_vk, params.convert_vk, params.output_vk)
}

/// check_spend wrapper
pub fn check_spend(
    spend: &SpendDescription<<Authorized as Authorization>::SaplingAuth>,
    sighash: &[u8; 32],
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(spend.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    ctx.check_spend(
        spend.cv,
        spend.anchor,
        &spend.nullifier.0,
        PublicKey(spend.rk.0),
        sighash,
        spend.spend_auth_sig,
        zkproof,
        parameters,
    )
}

/// check_output wrapper
pub fn check_output(
    output: &OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(output.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    let epk =
        masp_proofs::jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key.0);
    let epk = match epk.into() {
        Some(p) => p,
        None => return false,
    };
    ctx.check_output(output.cv, output.cmu, epk, zkproof, parameters)
}

/// check convert wrapper
pub fn check_convert(
    convert: &ConvertDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(convert.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    ctx.check_convert(convert.cv, convert.anchor, zkproof, parameters)
}

/// Represents an authorization where the Sapling bundle is authorized and the
/// transparent bundle is unauthorized.
pub struct PartialAuthorized;

impl Authorization for PartialAuthorized {
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type TransparentAuth = <Unauthorized as Authorization>::TransparentAuth;
}

/// Partially deauthorize the transparent bundle
fn partial_deauthorize(
    tx_data: &TransactionData<Authorized>,
) -> Option<TransactionData<PartialAuthorized>> {
    let transp = tx_data.transparent_bundle().and_then(|x| {
        let mut tb = TransparentBuilder::empty();
        for vin in &x.vin {
            tb.add_input(TxOut {
                asset_type: vin.asset_type,
                value: vin.value,
                address: vin.address,
            })
            .ok()?;
        }
        for vout in &x.vout {
            tb.add_output(&vout.address, vout.asset_type, vout.value)
                .ok()?;
        }
        tb.build()
    });
    if tx_data.transparent_bundle().is_some() != transp.is_some() {
        return None;
    }
    Some(TransactionData::from_parts(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        transp,
        tx_data.sapling_bundle().cloned(),
    ))
}

/// Verify a shielded transaction.
pub fn verify_shielded_tx(transaction: &Transaction) -> bool {
    tracing::info!("entered verify_shielded_tx()");

    let sapling_bundle = if let Some(bundle) = transaction.sapling_bundle() {
        bundle
    } else {
        return false;
    };
    let tx_data = transaction.deref();

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = match partial_deauthorize(tx_data) {
        Some(tx_data) => tx_data,
        None => return false,
    };

    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    // the commitment being signed is shared across all Sapling inputs; once
    // V4 transactions are deprecated this should just be the txid, but
    // for now we need to continue to compute it here.
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);

    tracing::info!("sighash computed");

    let [spend_pvk, convert_pvk, output_pvk] = prepare_verifying_keys();

    let mut ctx = SaplingVerificationContext::new(true);
    let spends_valid = sapling_bundle.shielded_spends.iter().all(|spend| {
        check_spend(spend, sighash.as_ref(), &mut ctx, &spend_pvk)
    });
    let converts_valid = sapling_bundle
        .shielded_converts
        .iter()
        .all(|convert| check_convert(convert, &mut ctx, &convert_pvk));
    let outputs_valid = sapling_bundle
        .shielded_outputs
        .iter()
        .all(|output| check_output(output, &mut ctx, &output_pvk));

    if !(spends_valid && outputs_valid && converts_valid) {
        return false;
    }

    tracing::info!("passed spend/output verification");

    let assets_and_values: Amount = sapling_bundle.value_balance.clone();

    tracing::info!(
        "accumulated {} assets/values",
        assets_and_values.components().len()
    );

    let result = ctx.final_check(
        assets_and_values,
        sighash.as_ref(),
        sapling_bundle.authorization.binding_sig,
    );
    tracing::info!("final check result {result}");
    result
}

/// Get the path to MASP parameters from [`ENV_VAR_MASP_PARAMS_DIR`] env var or
/// use the default.
pub fn get_params_dir() -> PathBuf {
    if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
        println!("Using {} as masp parameter folder.", params_dir);
        PathBuf::from(params_dir)
    } else {
        masp_proofs::default_params_folder().unwrap()
    }
}

/// Freeze a Builder into the format necessary for inclusion in a Tx. This is
/// the format used by hardware wallets to validate a MASP Transaction.
struct WalletMap;

impl<P1>
    masp_primitives::transaction::components::sapling::builder::MapBuilder<
        P1,
        ExtendedSpendingKey,
        (),
        ExtendedFullViewingKey,
    > for WalletMap
{
    fn map_params(&self, _s: P1) {}

    fn map_key(&self, s: ExtendedSpendingKey) -> ExtendedFullViewingKey {
        (&s).into()
    }
}

impl<P1, R1, N1>
    MapBuilder<
        P1,
        R1,
        ExtendedSpendingKey,
        N1,
        (),
        (),
        ExtendedFullViewingKey,
        (),
    > for WalletMap
{
    fn map_rng(&self, _s: R1) {}

    fn map_notifier(&self, _s: N1) {}
}

/// Abstracts platform specific details away from the logic of shielded pool
/// operations.
#[async_trait(? Send)]
pub trait ShieldedUtils:
    Sized + BorshDeserialize + BorshSerialize + Default + Clone
{
    /// Get a MASP transaction prover
    fn local_tx_prover(&self) -> LocalTxProver;

    /// Load up the currently saved ShieldedContext
    async fn load(self) -> std::io::Result<ShieldedContext<Self>>;

    /// Sace the given ShieldedContext for future loads
    async fn save(&self, ctx: &ShieldedContext<Self>) -> std::io::Result<()>;
}

/// Make a ViewingKey that can view notes encrypted by given ExtendedSpendingKey
pub fn to_viewing_key(esk: &ExtendedSpendingKey) -> FullViewingKey {
    ExtendedFullViewingKey::from(esk).fvk
}

/// Generate a valid diversifier, i.e. one that has a diversified base. Return
/// also this diversified base.
#[cfg(feature = "masp-tx-gen")]
pub fn find_valid_diversifier<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Diversifier, masp_primitives::jubjub::SubgroupPoint) {
    let mut diversifier;
    let g_d;
    // Keep generating random diversifiers until one has a diversified base
    loop {
        let mut d = [0; 11];
        rng.fill_bytes(&mut d);
        diversifier = Diversifier(d);
        if let Some(val) = diversifier.g_d() {
            g_d = val;
            break;
        }
    }
    (diversifier, g_d)
}

/// Determine if using the current note would actually bring us closer to our
/// target
pub fn is_amount_required(src: Amount, dest: Amount, delta: Amount) -> bool {
    let gap = dest - src;
    for (asset_type, value) in gap.components() {
        if *value >= 0 && delta[asset_type] >= 0 {
            return true;
        }
    }
    false
}

/// Errors that can occur when trying to retrieve pinned transaction
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum PinnedBalanceError {
    /// No transaction has yet been pinned to the given payment address
    NoTransactionPinned,
    /// The supplied viewing key does not recognize payments to given address
    InvalidViewingKey,
}

// #[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
// pub struct MaspAmount {
//     pub asset: Address,
//     pub amount: token::Amount,
// }

/// a masp change
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct MaspChange {
    /// the token address
    pub asset: Address,
    /// the change in the token
    pub change: token::Change,
}

/// a masp amount
#[derive(
    BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct MaspAmount(HashMap<(Epoch, Address), token::Change>);

impl std::ops::Deref for MaspAmount {
    type Target = HashMap<(Epoch, Address), token::Change>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for MaspAmount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Add for MaspAmount {
    type Output = MaspAmount;

    fn add(mut self, mut rhs: MaspAmount) -> Self::Output {
        for (key, value) in rhs.drain() {
            self.entry(key)
                .and_modify(|val| *val += value)
                .or_insert(value);
        }
        self.retain(|_, v| !v.is_zero());
        self
    }
}

impl std::ops::AddAssign for MaspAmount {
    fn add_assign(&mut self, amount: MaspAmount) {
        *self = self.clone() + amount
    }
}

// please stop copying and pasting make a function
impl std::ops::Sub for MaspAmount {
    type Output = MaspAmount;

    fn sub(mut self, mut rhs: MaspAmount) -> Self::Output {
        for (key, value) in rhs.drain() {
            self.entry(key)
                .and_modify(|val| *val -= value)
                .or_insert(-value);
        }
        self.0.retain(|_, v| !v.is_zero());
        self
    }
}

impl std::ops::SubAssign for MaspAmount {
    fn sub_assign(&mut self, amount: MaspAmount) {
        *self = self.clone() - amount
    }
}

impl std::ops::Mul<Change> for MaspAmount {
    type Output = Self;

    fn mul(mut self, rhs: Change) -> Self::Output {
        for (_, value) in self.iter_mut() {
            *value = *value * rhs
        }
        self
    }
}

impl<'a> From<&'a MaspAmount> for Amount {
    fn from(masp_amount: &'a MaspAmount) -> Amount {
        let mut res = Amount::zero();
        for ((epoch, token), val) in masp_amount.iter() {
            for denom in MaspDenom::iter() {
                let asset = make_asset_type(Some(*epoch), token, denom);
                res += Amount::from_pair(asset, denom.denominate_i128(val))
                    .unwrap();
            }
        }
        res
    }
}

impl From<MaspAmount> for Amount {
    fn from(amt: MaspAmount) -> Self {
        Self::from(&amt)
    }
}

/// Represents the amount used of different conversions
pub type Conversions =
    HashMap<AssetType, (AllowedConversion, MerklePath<Node>, i128)>;

/// Represents the changes that were made to a list of transparent accounts
pub type TransferDelta = HashMap<Address, MaspChange>;

/// Represents the changes that were made to a list of shielded accounts
pub type TransactionDelta = HashMap<ViewingKey, MaspAmount>;

/// Represents the current state of the shielded pool from the perspective of
/// the chosen viewing keys.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ShieldedContext<U: ShieldedUtils> {
    /// Location where this shielded context is saved
    #[borsh_skip]
    pub utils: U,
    /// The last transaction index to be processed in this context
    pub last_txidx: u64,
    /// The commitment tree produced by scanning all transactions up to tx_pos
    pub tree: CommitmentTree<Node>,
    /// Maps viewing keys to applicable note positions
    pub pos_map: HashMap<ViewingKey, HashSet<usize>>,
    /// Maps a nullifier to the note position to which it applies
    pub nf_map: HashMap<Nullifier, usize>,
    /// Maps note positions to their corresponding notes
    pub note_map: HashMap<usize, Note>,
    /// Maps note positions to their corresponding memos
    pub memo_map: HashMap<usize, MemoBytes>,
    /// Maps note positions to the diversifier of their payment address
    pub div_map: HashMap<usize, Diversifier>,
    /// Maps note positions to their witness (used to make merkle paths)
    pub witness_map: HashMap<usize, IncrementalWitness<Node>>,
    /// Tracks what each transaction does to various account balances
    pub delta_map: BTreeMap<
        (BlockHeight, TxIndex),
        (Epoch, TransferDelta, TransactionDelta),
    >,
    /// The set of note positions that have been spent
    pub spents: HashSet<usize>,
    /// Maps asset types to their decodings
    pub asset_types: HashMap<AssetType, (Address, MaspDenom, Epoch)>,
    /// Maps note positions to their corresponding viewing keys
    pub vk_map: HashMap<usize, ViewingKey>,
}

/// Default implementation to ease construction of TxContexts. Derive cannot be
/// used here due to CommitmentTree not implementing Default.
impl<U: ShieldedUtils + Default> Default for ShieldedContext<U> {
    fn default() -> ShieldedContext<U> {
        ShieldedContext::<U> {
            utils: U::default(),
            last_txidx: u64::default(),
            tree: CommitmentTree::empty(),
            pos_map: HashMap::default(),
            nf_map: HashMap::default(),
            note_map: HashMap::default(),
            memo_map: HashMap::default(),
            div_map: HashMap::default(),
            witness_map: HashMap::default(),
            spents: HashSet::default(),
            delta_map: BTreeMap::default(),
            asset_types: HashMap::default(),
            vk_map: HashMap::default(),
        }
    }
}

impl<U: ShieldedUtils> ShieldedContext<U> {
    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    pub async fn load(&mut self) -> std::io::Result<()> {
        let new_ctx = self.utils.clone().load().await?;
        *self = new_ctx;
        Ok(())
    }

    /// Save this shielded context into its associated context directory
    pub async fn save(&self) -> std::io::Result<()> {
        self.utils.save(self).await
    }

    /// Merge data from the given shielded context into the current shielded
    /// context. It must be the case that the two shielded contexts share the
    /// same last transaction ID and share identical commitment trees.
    pub fn merge(&mut self, new_ctx: ShieldedContext<U>) {
        debug_assert_eq!(self.last_txidx, new_ctx.last_txidx);
        // Merge by simply extending maps. Identical keys should contain
        // identical values, so overwriting should not be problematic.
        self.pos_map.extend(new_ctx.pos_map);
        self.nf_map.extend(new_ctx.nf_map);
        self.note_map.extend(new_ctx.note_map);
        self.memo_map.extend(new_ctx.memo_map);
        self.div_map.extend(new_ctx.div_map);
        self.witness_map.extend(new_ctx.witness_map);
        self.spents.extend(new_ctx.spents);
        self.asset_types.extend(new_ctx.asset_types);
        self.vk_map.extend(new_ctx.vk_map);
        // The deltas are the exception because different keys can reveal
        // different parts of the same transaction. Hence each delta needs to be
        // merged separately.
        for ((height, idx), (ep, ntfer_delta, ntx_delta)) in new_ctx.delta_map {
            let (_ep, tfer_delta, tx_delta) = self
                .delta_map
                .entry((height, idx))
                .or_insert((ep, TransferDelta::new(), TransactionDelta::new()));
            tfer_delta.extend(ntfer_delta);
            tx_delta.extend(ntx_delta);
        }
    }

    /// Fetch the current state of the multi-asset shielded pool into a
    /// ShieldedContext
    pub async fn fetch<C: Client + Sync>(
        &mut self,
        client: &C,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) {
        // First determine which of the keys requested to be fetched are new.
        // Necessary because old transactions will need to be scanned for new
        // keys.
        let mut unknown_keys = Vec::new();
        for esk in sks {
            let vk = to_viewing_key(esk).vk;
            if !self.pos_map.contains_key(&vk) {
                unknown_keys.push(vk);
            }
        }
        for vk in fvks {
            if !self.pos_map.contains_key(vk) {
                unknown_keys.push(*vk);
            }
        }

        // If unknown keys are being used, we need to scan older transactions
        // for any unspent notes
        let (txs, mut tx_iter);
        if !unknown_keys.is_empty() {
            // Load all transactions accepted until this point
            txs = Self::fetch_shielded_transfers(client, 0).await;
            tx_iter = txs.iter();
            // Do this by constructing a shielding context only for unknown keys
            let mut tx_ctx = Self {
                utils: self.utils.clone(),
                ..Default::default()
            };
            for vk in unknown_keys {
                tx_ctx.pos_map.entry(vk).or_insert_with(HashSet::new);
            }
            // Update this unknown shielded context until it is level with self
            while tx_ctx.last_txidx != self.last_txidx {
                if let Some(((height, idx), (epoch, tx, stx))) = tx_iter.next()
                {
                    tx_ctx
                        .scan_tx(client, *height, *idx, *epoch, tx, stx)
                        .await;
                } else {
                    break;
                }
            }
            // Merge the context data originating from the unknown keys into the
            // current context
            self.merge(tx_ctx);
        } else {
            // Load only transactions accepted from last_txid until this point
            txs = Self::fetch_shielded_transfers(client, self.last_txidx).await;
            tx_iter = txs.iter();
        }
        // Now that we possess the unspent notes corresponding to both old and
        // new keys up until tx_pos, proceed to scan the new transactions.
        for ((height, idx), (epoch, tx, stx)) in &mut tx_iter {
            self.scan_tx(client, *height, *idx, *epoch, tx, stx).await;
        }
    }

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from the ledger. The ledger conceptually stores
    /// transactions as a vector. More concretely, the HEAD_TX_KEY location
    /// stores the index of the last accepted transaction and each transaction
    /// is stored at a key derived from its index.
    pub async fn fetch_shielded_transfers<C: Client + Sync>(
        client: &C,
        last_txidx: u64,
    ) -> BTreeMap<(BlockHeight, TxIndex), (Epoch, Transfer, Transaction)> {
        // The address of the MASP account
        let masp_addr = masp();
        // Construct the key where last transaction pointer is stored
        let head_tx_key = Key::from(masp_addr.to_db_key())
            .push(&HEAD_TX_KEY.to_owned())
            .expect("Cannot obtain a storage key");
        // Query for the index of the last accepted transaction
        let head_txidx = query_storage_value::<C, u64>(client, &head_tx_key)
            .await
            .unwrap_or(0);
        let mut shielded_txs = BTreeMap::new();
        // Fetch all the transactions we do not have yet
        for i in last_txidx..head_txidx {
            // Construct the key for where the current transaction is stored
            let current_tx_key = Key::from(masp_addr.to_db_key())
                .push(&(TX_KEY_PREFIX.to_owned() + &i.to_string()))
                .expect("Cannot obtain a storage key");
            // Obtain the current transaction
            let (tx_epoch, tx_height, tx_index, current_tx, current_stx) =
                query_storage_value::<
                    C,
                    (Epoch, BlockHeight, TxIndex, Transfer, Transaction),
                >(client, &current_tx_key)
                .await
                .unwrap();
            // Collect the current transaction
            shielded_txs.insert(
                (tx_height, tx_index),
                (tx_epoch, current_tx, current_stx),
            );
        }
        shielded_txs
    }

    /// Applies the given transaction to the supplied context. More precisely,
    /// the shielded transaction's outputs are added to the commitment tree.
    /// Newly discovered notes are associated to the supplied viewing keys. Note
    /// nullifiers are mapped to their originating notes. Note positions are
    /// associated to notes, memos, and diversifiers. And the set of notes that
    /// we have spent are updated. The witness map is maintained to make it
    /// easier to construct note merkle paths in other code. See
    /// <https://zips.z.cash/protocol/protocol.pdf#scan>
    pub async fn scan_tx<C: Client + Sync>(
        &mut self,
        client: &C,
        height: BlockHeight,
        index: TxIndex,
        epoch: Epoch,
        tx: &Transfer,
        shielded: &Transaction,
    ) {
        // For tracking the account changes caused by this Transaction
        let mut transaction_delta = TransactionDelta::new();
        // Listen for notes sent to our viewing keys
        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
            // Create merkle tree leaf node from note commitment
            let node = Node::new(so.cmu.to_repr());
            // Update each merkle tree in the witness map with the latest
            // addition
            for (_, witness) in self.witness_map.iter_mut() {
                witness.append(node).expect("note commitment tree is full");
            }
            let note_pos = self.tree.size();
            self.tree
                .append(node)
                .expect("note commitment tree is full");
            // Finally, make it easier to construct merkle paths to this new
            // note
            let witness = IncrementalWitness::<Node>::from_tree(&self.tree);
            self.witness_map.insert(note_pos, witness);
            // Let's try to see if any of our viewing keys can decrypt latest
            // note
            let mut pos_map = HashMap::new();
            std::mem::swap(&mut pos_map, &mut self.pos_map);
            for (vk, notes) in pos_map.iter_mut() {
                let decres = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                    &NETWORK,
                    1.into(),
                    &PreparedIncomingViewingKey::new(&vk.ivk()),
                    so,
                );
                // So this current viewing key does decrypt this current note...
                if let Some((note, pa, memo)) = decres {
                    // Add this note to list of notes decrypted by this viewing
                    // key
                    notes.insert(note_pos);
                    // Compute the nullifier now to quickly recognize when spent
                    let nf = note.nf(&vk.nk, note_pos.try_into().unwrap());
                    self.note_map.insert(note_pos, note);
                    self.memo_map.insert(note_pos, memo);
                    // The payment address' diversifier is required to spend
                    // note
                    self.div_map.insert(note_pos, *pa.diversifier());
                    self.nf_map.insert(nf, note_pos);
                    // Note the account changes
                    let balance = transaction_delta
                        .entry(*vk)
                        .or_insert_with(MaspAmount::default);
                    *balance += self
                        .decode_all_amounts(
                            client,
                            Amount::from_nonnegative(
                                note.asset_type,
                                note.value,
                            )
                            .expect(
                                "found note with invalid value or asset type",
                            ),
                        )
                        .await;

                    self.vk_map.insert(note_pos, *vk);
                    break;
                }
            }
            std::mem::swap(&mut pos_map, &mut self.pos_map);
        }
        // Cancel out those of our notes that have been spent
        for ss in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_spends)
        {
            // If the shielded spend's nullifier is in our map, then target note
            // is rendered unusable
            if let Some(note_pos) = self.nf_map.get(&ss.nullifier) {
                self.spents.insert(*note_pos);
                // Note the account changes
                let balance = transaction_delta
                    .entry(self.vk_map[note_pos])
                    .or_insert_with(MaspAmount::default);
                let note = self.note_map[note_pos];
                *balance -= self
                    .decode_all_amounts(
                        client,
                        Amount::from_nonnegative(note.asset_type, note.value)
                            .expect(
                                "found note with invalid value or asset type",
                            ),
                    )
                    .await;
            }
        }
        // Record the changes to the transparent accounts
        let mut transfer_delta = TransferDelta::new();
        let token_addr = tx.token.clone();
        transfer_delta.insert(
            tx.source.clone(),
            MaspChange {
                asset: token_addr,
                change: -tx.amount.amount.change(),
            },
        );
        self.last_txidx += 1;

        self.delta_map.insert(
            (height, index),
            (epoch, transfer_delta, transaction_delta),
        );
    }

    /// Summarize the effects on shielded and transparent accounts of each
    /// Transfer in this context
    pub fn get_tx_deltas(
        &self,
    ) -> &BTreeMap<
        (BlockHeight, TxIndex),
        (Epoch, TransferDelta, TransactionDelta),
    > {
        &self.delta_map
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_shielded_balance<C: Client + Sync>(
        &mut self,
        client: &C,
        vk: &ViewingKey,
    ) -> Option<MaspAmount> {
        // Cannot query the balance of a key that's not in the map
        if !self.pos_map.contains_key(vk) {
            return None;
        }
        let mut val_acc = Amount::zero();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk) {
            for note_idx in avail_notes {
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note associated with this ID
                let note = self.note_map.get(note_idx).unwrap();
                // Finally add value to multi-asset accumulator
                val_acc +=
                    Amount::from_nonnegative(note.asset_type, note.value)
                        .expect("found note with invalid value or asset type");
            }
        }
        Some(self.decode_all_amounts(client, val_acc).await)
    }

    /// Query the ledger for the decoding of the given asset type and cache it
    /// if it is found.
    pub async fn decode_asset_type<C: Client + Sync>(
        &mut self,
        client: &C,
        asset_type: AssetType,
    ) -> Option<(Address, MaspDenom, Epoch)> {
        // Try to find the decoding in the cache
        if let decoded @ Some(_) = self.asset_types.get(&asset_type) {
            return decoded.cloned();
        }
        // Query for the ID of the last accepted transaction
        let (addr, denom, ep, _conv, _path): (
            Address,
            MaspDenom,
            _,
            Amount,
            MerklePath<Node>,
        ) = rpc::query_conversion(client, asset_type).await?;
        self.asset_types
            .insert(asset_type, (addr.clone(), denom, ep));
        Some((addr, denom, ep))
    }

    /// Query the ledger for the conversion that is allowed for the given asset
    /// type and cache it.
    async fn query_allowed_conversion<'a, C: Client + Sync>(
        &'a mut self,
        client: &C,
        asset_type: AssetType,
        conversions: &'a mut Conversions,
    ) {
        if let Entry::Vacant(conv_entry) = conversions.entry(asset_type) {
            // Query for the ID of the last accepted transaction
            if let Some((addr, denom, ep, conv, path)) =
                query_conversion(client, asset_type).await
            {
                self.asset_types.insert(asset_type, (addr, denom, ep));
                // If the conversion is 0, then we just have a pure decoding
                if conv != Amount::zero() {
                    conv_entry.insert((conv.into(), path, 0));
                }
            }
        }
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context and express that value in terms of the currently timestamped
    /// asset types. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_exchanged_balance<C: Client + Sync>(
        &mut self,
        client: &C,
        vk: &ViewingKey,
        target_epoch: Epoch,
    ) -> Option<MaspAmount> {
        // First get the unexchanged balance
        if let Some(balance) = self.compute_shielded_balance(client, vk).await {
            let exchanged_amount = self
                .compute_exchanged_amount(
                    client,
                    balance,
                    target_epoch,
                    HashMap::new(),
                )
                .await
                .0;
            // And then exchange balance into current asset types
            Some(self.decode_all_amounts(client, exchanged_amount).await)
        } else {
            None
        }
    }

    /// Try to convert as much of the given asset type-value pair using the
    /// given allowed conversion. usage is incremented by the amount of the
    /// conversion used, the conversions are applied to the given input, and
    /// the trace amount that could not be converted is moved from input to
    /// output.
    #[allow(clippy::too_many_arguments)]
    async fn apply_conversion<C: Client + Sync>(
        &mut self,
        client: &C,
        conv: AllowedConversion,
        asset_type: (Epoch, Address, MaspDenom),
        value: i128,
        usage: &mut i128,
        input: &mut MaspAmount,
        output: &mut MaspAmount,
    ) {
        // we do not need to convert negative values
        if value <= 0 {
            return;
        }
        // If conversion if possible, accumulate the exchanged amount
        let conv: Amount = conv.into();
        // The amount required of current asset to qualify for conversion
        let masp_asset =
            make_asset_type(Some(asset_type.0), &asset_type.1, asset_type.2);
        let threshold = -conv[&masp_asset];
        if threshold == 0 {
            eprintln!(
                "Asset threshold of selected conversion for asset type {} is \
                 0, this is a bug, please report it.",
                masp_asset
            );
        }
        // We should use an amount of the AllowedConversion that almost
        // cancels the original amount
        let required = value / threshold;
        // Forget about the trace amount left over because we cannot
        // realize its value
        let trace = MaspAmount(HashMap::from([(
            (asset_type.0, asset_type.1),
            Change::from(value % threshold),
        )]));
        // Record how much more of the given conversion has been used
        *usage += required;
        // Apply the conversions to input and move the trace amount to output
        *input += self
            .decode_all_amounts(client, conv.clone() * required)
            .await
            - trace.clone();
        *output += trace;
    }

    /// Convert the given amount into the latest asset types whilst making a
    /// note of the conversions that were used. Note that this function does
    /// not assume that allowed conversions from the ledger are expressed in
    /// terms of the latest asset types.
    pub async fn compute_exchanged_amount<C: Client + Sync>(
        &mut self,
        client: &C,
        mut input: MaspAmount,
        target_epoch: Epoch,
        mut conversions: Conversions,
    ) -> (Amount, Conversions) {
        // Where we will store our exchanged value
        let mut output = MaspAmount::default();
        // Repeatedly exchange assets until it is no longer possible
        while let Some(((asset_epoch, token_addr), value)) = input.iter().next()
        {
            let value = *value;
            let asset_epoch = *asset_epoch;
            let token_addr = token_addr.clone();
            for denom in MaspDenom::iter() {
                let target_asset_type =
                    make_asset_type(Some(target_epoch), &token_addr, denom);
                let asset_type =
                    make_asset_type(Some(asset_epoch), &token_addr, denom);
                let at_target_asset_type = target_epoch == asset_epoch;

                let denom_value = denom.denominate_i128(&value);
                self.query_allowed_conversion(
                    client,
                    target_asset_type,
                    &mut conversions,
                )
                .await;
                self.query_allowed_conversion(
                    client,
                    asset_type,
                    &mut conversions,
                )
                .await;
                if let (Some((conv, _wit, usage)), false) =
                    (conversions.get_mut(&asset_type), at_target_asset_type)
                {
                    println!(
                        "converting current asset type to latest asset type..."
                    );
                    // Not at the target asset type, not at the latest asset
                    // type. Apply conversion to get from
                    // current asset type to the latest
                    // asset type.
                    self.apply_conversion(
                        client,
                        conv.clone(),
                        (asset_epoch, token_addr.clone(), denom),
                        denom_value,
                        usage,
                        &mut input,
                        &mut output,
                    )
                    .await;
                } else if let (Some((conv, _wit, usage)), false) = (
                    conversions.get_mut(&target_asset_type),
                    at_target_asset_type,
                ) {
                    println!(
                        "converting latest asset type to target asset type..."
                    );
                    // Not at the target asset type, yet at the latest asset
                    // type. Apply inverse conversion to get
                    // from latest asset type to the target
                    // asset type.
                    self.apply_conversion(
                        client,
                        conv.clone(),
                        (asset_epoch, token_addr.clone(), denom),
                        denom_value,
                        usage,
                        &mut input,
                        &mut output,
                    )
                    .await;
                } else {
                    // At the target asset type. Then move component over to
                    // output.
                    let mut comp = MaspAmount::default();
                    comp.insert(
                        (asset_epoch, token_addr.clone()),
                        denom_value.into(),
                    );
                    for ((e, token), val) in input.iter() {
                        if *token == token_addr && *e == asset_epoch {
                            comp.insert((*e, token.clone()), *val);
                        }
                    }
                    output += comp.clone();
                    input -= comp;
                }
            }
        }
        (output.into(), conversions)
    }

    /// Collect enough unspent notes in this context to exceed the given amount
    /// of the specified asset type. Return the total value accumulated plus
    /// notes and the corresponding diversifiers/merkle paths that were used to
    /// achieve the total value.
    pub async fn collect_unspent_notes<C: Client + Sync>(
        &mut self,
        client: &C,
        vk: &ViewingKey,
        target: Amount,
        target_epoch: Epoch,
    ) -> (
        Amount,
        Vec<(Diversifier, Note, MerklePath<Node>)>,
        Conversions,
    ) {
        // Establish connection with which to do exchange rate queries
        let mut conversions = HashMap::new();
        let mut val_acc = Amount::zero();
        let mut notes = Vec::new();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk).cloned() {
            for note_idx in &avail_notes {
                // No more transaction inputs are required once we have met
                // the target amount
                if val_acc >= target {
                    break;
                }
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note, merkle path, diversifier associated with this ID
                let note = *self.note_map.get(note_idx).unwrap();

                // The amount contributed by this note before conversion
                let pre_contr = Amount::from_pair(note.asset_type, note.value)
                    .expect("received note has invalid value or asset type");
                let input = self.decode_all_amounts(client, pre_contr).await;
                let (contr, proposed_convs) = self
                    .compute_exchanged_amount(
                        client,
                        input,
                        target_epoch,
                        conversions.clone(),
                    )
                    .await;

                // Use this note only if it brings us closer to our target
                if is_amount_required(
                    val_acc.clone(),
                    target.clone(),
                    contr.clone(),
                ) {
                    // Be sure to record the conversions used in computing
                    // accumulated value
                    val_acc += contr;
                    // Commit the conversions that were used to exchange
                    conversions = proposed_convs;
                    let merkle_path =
                        self.witness_map.get(note_idx).unwrap().path().unwrap();
                    let diversifier = self.div_map.get(note_idx).unwrap();
                    // Commit this note to our transaction
                    notes.push((*diversifier, note, merkle_path));
                }
            }
        }
        (val_acc, notes, conversions)
    }

    /// Compute the combined value of the output notes of the transaction pinned
    /// at the given payment address. This computation uses the supplied viewing
    /// keys to try to decrypt the output notes. If no transaction is pinned at
    /// the given payment address fails with
    /// `PinnedBalanceError::NoTransactionPinned`.
    pub async fn compute_pinned_balance<C: Client + Sync>(
        client: &C,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(Amount, Epoch), PinnedBalanceError> {
        // Check that the supplied viewing key corresponds to given payment
        // address
        let counter_owner = viewing_key.to_payment_address(
            *masp_primitives::sapling::PaymentAddress::diversifier(
                &owner.into(),
            ),
        );
        match counter_owner {
            Some(counter_owner) if counter_owner == owner.into() => {}
            _ => return Err(PinnedBalanceError::InvalidViewingKey),
        }
        // The address of the MASP account
        let masp_addr = masp();
        // Construct the key for where the transaction ID would be stored
        let pin_key = Key::from(masp_addr.to_db_key())
            .push(&(PIN_KEY_PREFIX.to_owned() + &owner.hash()))
            .expect("Cannot obtain a storage key");
        // Obtain the transaction pointer at the key
        let txidx = rpc::query_storage_value::<C, u64>(client, &pin_key)
            .await
            .ok_or(PinnedBalanceError::NoTransactionPinned)?;
        // Construct the key for where the pinned transaction is stored
        let tx_key = Key::from(masp_addr.to_db_key())
            .push(&(TX_KEY_PREFIX.to_owned() + &txidx.to_string()))
            .expect("Cannot obtain a storage key");
        // Obtain the pointed to transaction
        let (tx_epoch, _tx_height, _tx_index, _tx, shielded) =
            rpc::query_storage_value::<
                C,
                (Epoch, BlockHeight, TxIndex, Transfer, Transaction),
            >(client, &tx_key)
            .await
            .expect("Ill-formed epoch, transaction pair");
        // Accumulate the combined output note value into this Amount
        let mut val_acc = Amount::zero();
        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
            // Let's try to see if our viewing key can decrypt current note
            let decres = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&viewing_key.ivk()),
                so,
            );
            match decres {
                // So the given viewing key does decrypt this current note...
                Some((note, pa, _memo)) if pa == owner.into() => {
                    val_acc +=
                        Amount::from_nonnegative(note.asset_type, note.value)
                            .expect(
                                "found note with invalid value or asset type",
                            );
                }
                _ => {}
            }
        }
        Ok((val_acc, tx_epoch))
    }

    /// Compute the combined value of the output notes of the pinned transaction
    /// at the given payment address if there's any. The asset types may be from
    /// the epoch of the transaction or even before, so exchange all these
    /// amounts to the epoch of the transaction in order to get the value that
    /// would have been displayed in the epoch of the transaction.
    pub async fn compute_exchanged_pinned_balance<C: Client + Sync>(
        &mut self,
        client: &C,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(MaspAmount, Epoch), PinnedBalanceError> {
        // Obtain the balance that will be exchanged
        let (amt, ep) =
            Self::compute_pinned_balance(client, owner, viewing_key).await?;
        println!("Pinned balance: {:?}", amt);
        // Establish connection with which to do exchange rate queries
        let amount = self.decode_all_amounts(client, amt).await;
        println!("Decoded pinned balance: {:?}", amount);
        // Finally, exchange the balance to the transaction's epoch
        let computed_amount = self
            .compute_exchanged_amount(client, amount, ep, HashMap::new())
            .await
            .0;
        println!("Exchanged amount: {:?}", computed_amount);
        Ok((self.decode_all_amounts(client, computed_amount).await, ep))
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to. All asset types not corresponding to
    /// the given epoch are ignored.
    pub async fn decode_amount<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: Amount,
        target_epoch: Epoch,
    ) -> HashMap<Address, token::Change> {
        let mut res = HashMap::new();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded = self.decode_asset_type(client, *asset_type).await;
            // Only assets with the target timestamp count
            match decoded {
                Some(asset_type @ (_, _, epoch)) if epoch == target_epoch => {
                    decode_component(
                        asset_type,
                        *val,
                        &mut res,
                        |address, _| address,
                    );
                }
                _ => {}
            }
        }
        res
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to.
    pub async fn decode_all_amounts<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: Amount,
    ) -> MaspAmount {
        let mut res: HashMap<(Epoch, Address), Change> = HashMap::default();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            if let Some(decoded) =
                self.decode_asset_type(client, *asset_type).await
            {
                decode_component(decoded, *val, &mut res, |address, epoch| {
                    (epoch, address)
                })
            }
        }
        MaspAmount(res)
    }

    /// Make shielded components to embed within a Transfer object. If no
    /// shielded payment address nor spending key is specified, then no
    /// shielded components are produced. Otherwise a transaction containing
    /// nullifiers and/or note commitments are produced. Dummy transparent
    /// UTXOs are sometimes used to make transactions balanced, but it is
    /// understood that transparent account changes are effected only by the
    /// amounts and signatures specified by the containing Transfer object.
    #[cfg(feature = "masp-tx-gen")]
    pub async fn gen_shielded_transfer<C: Client + Sync>(
        &mut self,
        client: &C,
        args: &args::TxTransfer,
        shielded_gas: bool,
    ) -> Result<
        Option<(
            Builder<(), (), ExtendedFullViewingKey, ()>,
            Transaction,
            SaplingMetadata,
            Epoch,
        )>,
        builder::Error<std::convert::Infallible>,
    > {
        // No shielded components are needed when neither source nor destination
        // are shielded
        let spending_key = args.source.spending_key();
        let payment_address = args.target.payment_address();
        // No shielded components are needed when neither source nor
        // destination are shielded
        if spending_key.is_none() && payment_address.is_none() {
            return Ok(None);
        }
        // We want to fund our transaction solely from supplied spending key
        let spending_key = spending_key.map(|x| x.into());
        let spending_keys: Vec<_> = spending_key.into_iter().collect();
        // Load the current shielded context given the spending key we possess
        let _ = self.load().await;
        self.fetch(client, &spending_keys, &[]).await;
        // Save the update state so that future fetches can be short-circuited
        let _ = self.save().await;
        // Determine epoch in which to submit potential shielded transaction
        let epoch = rpc::query_epoch(client).await;
        // Context required for storing which notes are in the source's
        // possesion
        let memo = MemoBytes::empty();

        // Now we build up the transaction within this object
        let mut builder = Builder::<TestNetwork, OsRng>::new(NETWORK, 1.into());

        // break up a transfer into a number of transfers with suitable
        // denominations
        let InputAmount::Validated(amt) = args.amount else {
            unreachable!("The function `gen_shielded_transfer` is only called by `submit_tx` which validates amounts.")
        };
        // Convert transaction amount into MASP types
        let (asset_types, amount) =
            convert_amount(epoch, &args.token, amt.amount);

        let tx_fee =
        // If there are shielded inputs
        if let Some(sk) = spending_key {
            let InputAmount::Validated(fee) = args.tx.fee_amount else {
                unreachable!("The function `gen_shielded_transfer` is only called by `submit_tx` which validates amounts.")
            };
            // Transaction fees need to match the amount in the wrapper Transfer
            // when MASP source is used
            let (_, shielded_fee) =
                convert_amount(epoch, &args.tx.fee_token, fee.amount);
            let required_amt = if shielded_gas {
                amount + shielded_fee.clone()
            } else {
                amount
            };

            // Locate unspent notes that can help us meet the transaction amount
            let (_, unspent_notes, used_convs) = self
                .collect_unspent_notes(
                    client,
                    &to_viewing_key(&sk).vk,
                    required_amt,
                    epoch,
                )
                .await;
            // Commit the notes found to our transaction
            for (diversifier, note, merkle_path) in unspent_notes {
                builder
                    .add_sapling_spend(sk, diversifier, note, merkle_path)
                    .map_err(builder::Error::SaplingBuild)?;
            }
            // Commit the conversion notes used during summation
            for (conv, wit, value) in used_convs.values() {
                if value.is_positive() {
                    builder.add_sapling_convert(
                        conv.clone(),
                        *value as u64,
                        wit.clone(),
                    )
                    .map_err(builder::Error::SaplingBuild)?;
                }
            }
            shielded_fee
        } else {
            // We add a dummy UTXO to our transaction, but only the source of
            // the parent Transfer object is used to validate fund
            // availability
            let source_enc = args
                .source
                .address()
                .expect("source address should be transparent")
                .try_to_vec()
                .expect("source address encoding");
            let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                source_enc.as_ref(),
            ));
            let script = TransparentAddress(hash.into());
            for (denom, asset_type) in MaspDenom::iter().zip(asset_types.iter()) {
                builder
                    .add_transparent_input(TxOut {
                        asset_type: *asset_type,
                        value: denom.denominate(&amt) as i128,
                        address: script,
                    })
                    .map_err(builder::Error::TransparentBuild)?;
            }
            // No transfer fees come from the shielded transaction for non-MASP
            // sources
            Amount::zero()
        };

        // Now handle the outputs of this transaction
        // If there is a shielded output
        if let Some(pa) = payment_address {
            let ovk_opt = spending_key.map(|x| x.expsk.ovk);
            for (denom, asset_type) in MaspDenom::iter().zip(asset_types.iter())
            {
                builder
                    .add_sapling_output(
                        ovk_opt,
                        pa.into(),
                        *asset_type,
                        denom.denominate(&amt),
                        memo.clone(),
                    )
                    .map_err(builder::Error::SaplingBuild)?;
            }
        } else {
            // Embed the transparent target address into the shielded
            // transaction so that it can be signed
            let target_enc = args
                .target
                .address()
                .expect("target address should be transparent")
                .try_to_vec()
                .expect("target address encoding");
            let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                target_enc.as_ref(),
            ));
            for (denom, asset_type) in MaspDenom::iter().zip(asset_types.iter())
            {
                let vout = denom.denominate(&amt);
                if vout != 0 {
                    builder
                        .add_transparent_output(
                            &TransparentAddress(hash.into()),
                            *asset_type,
                            vout as i128,
                        )
                        .map_err(builder::Error::TransparentBuild)?;
                }
            }
        }

        // Now add outputs representing the change from this payment
        if let Some(sk) = spending_key {
            // Represents the amount of inputs we are short by
            let mut additional = Amount::zero();
            // The change left over from this transaction
            let value_balance = builder
                .value_balance()
                .expect("unable to compute value balance")
                - tx_fee.clone();
            for (asset_type, amt) in value_balance.components() {
                if *amt >= 0 {
                    // Send the change in this asset type back to the sender
                    builder
                        .add_sapling_output(
                            Some(sk.expsk.ovk),
                            sk.default_address().1,
                            *asset_type,
                            *amt as u64,
                            memo.clone(),
                        )
                        .map_err(builder::Error::SaplingBuild)?;
                } else {
                    // Record how much of the current asset type we are short by
                    additional +=
                        Amount::from_nonnegative(*asset_type, -*amt).unwrap();
                }
            }
            // If we are short by a non-zero amount, then we have insufficient
            // funds
            if additional != Amount::zero() {
                return Err(builder::Error::InsufficientFunds(additional));
            }
        }

        // Build and return the constructed transaction
        builder
            .clone()
            .build(
                &self.utils.local_tx_prover(),
                &FeeRule::non_standard(tx_fee),
            )
            .map(|(tx, metadata)| {
                Some((builder.map_builder(WalletMap), tx, metadata, epoch))
            })
    }

    /// Obtain the known effects of all accepted shielded and transparent
    /// transactions. If an owner is specified, then restrict the set to only
    /// transactions crediting/debiting the given owner. If token is specified,
    /// then restrict set to only transactions involving the given token.
    pub async fn query_tx_deltas<C: Client + Sync>(
        &mut self,
        client: &C,
        query_owner: &Either<BalanceOwner, Vec<Address>>,
        query_token: &Option<Address>,
        viewing_keys: &HashMap<String, ExtendedViewingKey>,
    ) -> BTreeMap<
        (BlockHeight, TxIndex),
        (Epoch, TransferDelta, TransactionDelta),
    > {
        const TXS_PER_PAGE: u8 = 100;
        let _ = self.load().await;
        let vks = viewing_keys;
        let fvks: Vec<_> = vks
            .values()
            .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
            .collect();
        self.fetch(client, &[], &fvks).await;
        // Save the update state so that future fetches can be short-circuited
        let _ = self.save().await;
        // Required for filtering out rejected transactions from Tendermint
        // responses
        let block_results = rpc::query_results(client).await;
        let mut transfers = self.get_tx_deltas().clone();
        // Construct the set of addresses relevant to user's query
        let relevant_addrs = match &query_owner {
            Either::Left(BalanceOwner::Address(owner)) => vec![owner.clone()],
            // MASP objects are dealt with outside of tx_search
            Either::Left(BalanceOwner::FullViewingKey(_viewing_key)) => vec![],
            Either::Left(BalanceOwner::PaymentAddress(_owner)) => vec![],
            // Unspecified owner means all known addresses are considered
            // relevant
            Either::Right(addrs) => addrs.clone(),
        };
        // Find all transactions to or from the relevant address set
        for addr in relevant_addrs {
            for prop in ["transfer.source", "transfer.target"] {
                // Query transactions involving the current address
                let mut tx_query = Query::eq(prop, addr.encode());
                // Elaborate the query if requested by the user
                if let Some(token) = &query_token {
                    tx_query =
                        tx_query.and_eq("transfer.token", token.encode());
                }
                for page in 1.. {
                    let txs = &client
                        .tx_search(
                            tx_query.clone(),
                            true,
                            page,
                            TXS_PER_PAGE,
                            Order::Ascending,
                        )
                        .await
                        .expect("Unable to query for transactions")
                        .txs;
                    for response_tx in txs {
                        let height = BlockHeight(response_tx.height.value());
                        let idx = TxIndex(response_tx.index);
                        // Only process yet unprocessed transactions which have
                        // been accepted by node VPs
                        let should_process = !transfers
                            .contains_key(&(height, idx))
                            && block_results[u64::from(height) as usize]
                                .is_accepted(idx.0 as usize);
                        if !should_process {
                            continue;
                        }
                        let tx = Tx::try_from(response_tx.tx.as_ref())
                            .expect("Ill-formed Tx");
                        let mut wrapper = None;
                        let mut transfer = None;
                        extract_payload(tx, &mut wrapper, &mut transfer);
                        // Epoch data is not needed for transparent transactions
                        let epoch =
                            wrapper.map(|x| x.epoch).unwrap_or_default();
                        if let Some(transfer) = transfer {
                            // Skip MASP addresses as they are already handled
                            // by ShieldedContext
                            if transfer.source == masp()
                                || transfer.target == masp()
                            {
                                continue;
                            }
                            // Describe how a Transfer simply subtracts from one
                            // account and adds the same to another

                            let delta = TransferDelta::from([(
                                transfer.source.clone(),
                                MaspChange {
                                    asset: transfer.token.clone(),
                                    change: -transfer.amount.amount.change(),
                                },
                            )]);

                            // No shielded accounts are affected by this
                            // Transfer
                            transfers.insert(
                                (height, idx),
                                (epoch, delta, TransactionDelta::new()),
                            );
                        }
                    }
                    // An incomplete page signifies no more transactions
                    if (txs.len() as u8) < TXS_PER_PAGE {
                        break;
                    }
                }
            }
        }
        transfers
    }
}

/// Extract the payload from the given Tx object
fn extract_payload(
    mut tx: Tx,
    wrapper: &mut Option<WrapperTx>,
    transfer: &mut Option<Transfer>,
) {
    let privkey =
        <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
    tx.decrypt(privkey).expect("unable to decrypt transaction");
    *wrapper = tx.header.wrapper();
    let _ = tx.data().map(|signed| {
        Transfer::try_from_slice(&signed[..]).map(|tfer| *transfer = Some(tfer))
    });
}

/// Make asset type corresponding to given address and epoch
pub fn make_asset_type(
    epoch: Option<Epoch>,
    token: &Address,
    denom: MaspDenom,
) -> AssetType {
    // Typestamp the chosen token with the current epoch
    let token_bytes = match epoch {
        None => (token, denom).try_to_vec().expect("token should serialize"),
        Some(epoch) => (token, denom, epoch.0)
            .try_to_vec()
            .expect("token should serialize"),
    };
    // Generate the unique asset identifier from the unique token address
    AssetType::new(token_bytes.as_ref()).expect("unable to create asset type")
}

/// Convert Anoma amount and token type to MASP equivalents
fn convert_amount(
    epoch: Epoch,
    token: &Address,
    val: token::Amount,
) -> ([AssetType; 4], Amount) {
    let mut amount = Amount::zero();
    let asset_types: [AssetType; 4] = MaspDenom::iter()
        .map(|denom| {
            let asset_type = make_asset_type(Some(epoch), token, denom);
            // Combine the value and unit into one amount
            amount +=
                Amount::from_nonnegative(asset_type, denom.denominate(&val))
                    .expect("invalid value for amount");
            asset_type
        })
        .collect::<Vec<AssetType>>()
        .try_into()
        .expect("This can't fail");
    (asset_types, amount)
}

mod tests {
    /// quick and dirty test. will fail on size check
    #[test]
    #[should_panic(expected = "parameter file size is not correct")]
    fn test_wrong_masp_params() {
        use std::io::Write;

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        let fake_params_paths =
            [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| tempdir.join(p));
        for path in fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            f.write_all(b"fake params")
                .expect("expected a writable temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        super::load_pvks();
    }

    /// a more involved test, using dummy parameters with the right
    /// size but the wrong hash.
    #[test]
    #[should_panic(expected = "parameter file is not correct")]
    fn test_wrong_masp_params_hash() {
        use masp_primitives::ff::PrimeField;
        use masp_proofs::bellman::groth16::{
            generate_random_parameters, Parameters,
        };
        use masp_proofs::bellman::{Circuit, ConstraintSystem, SynthesisError};
        use masp_proofs::bls12_381::{Bls12, Scalar};

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        struct FakeCircuit<E: PrimeField> {
            x: E,
        }

        impl<E: PrimeField> Circuit<E> for FakeCircuit<E> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                let x = cs.alloc(|| "x", || Ok(self.x)).unwrap();
                cs.enforce(
                    || {
                        "this is an extra long constraint name so that rustfmt \
                         is ok with wrapping the params of enforce()"
                    },
                    |lc| lc + x,
                    |lc| lc + x,
                    |lc| lc + x,
                );
                Ok(())
            }
        }

        let dummy_circuit = FakeCircuit { x: Scalar::zero() };
        let mut rng = rand::thread_rng();
        let fake_params: Parameters<Bls12> =
            generate_random_parameters(dummy_circuit, &mut rng)
                .expect("expected to generate fake params");

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        // TODO: get masp to export these consts
        let fake_params_paths = [
            (SPEND_NAME, 49848572u64),
            (CONVERT_NAME, 22570940u64),
            (OUTPUT_NAME, 16398620u64),
        ]
        .map(|(p, s)| (tempdir.join(p), s));
        for (path, size) in fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            fake_params
                .write(&mut f)
                .expect("expected a writable temp file");
            // the dummy circuit has one constraint, and therefore its
            // params should always be smaller than the large masp
            // circuit params. so this truncate extends the file, and
            // extra bytes at the end do not make it invalid.
            f.set_len(size).expect("expected to truncate the temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        super::load_pvks();
    }
}
