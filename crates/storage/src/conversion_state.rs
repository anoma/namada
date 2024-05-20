//! Shielded tokens conversion state

use std::collections::BTreeMap;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::masp_primitives::asset_type::AssetType;
use namada_core::masp_primitives::convert::AllowedConversion;
use namada_core::masp_primitives::merkle_tree::FrozenCommitmentTree;
use namada_core::masp_primitives::sapling;
use namada_core::storage::Epoch;
use namada_core::token::{Denomination, MaspDigitPos};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;

/// A representation of a leaf in the conversion tree
#[derive(Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub struct ConversionLeaf {
    /// The token associated with this asset type
    pub token: Address,
    /// The denomination associated with the above toke
    pub denom: Denomination,
    /// The digit position covered by this asset type
    pub digit_pos: MaspDigitPos,
    /// The epoch of the asset type
    pub epoch: Epoch,
    /// The actual conversion and generator
    pub conversion: AllowedConversion,
    /// The position of this leaf in the conversion tree
    pub leaf_pos: usize,
}

/// A representation of the conversion state
#[derive(
    Debug, Default, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
pub struct ConversionState {
    /// The last amount of the native token distributed
    pub normed_inflation: Option<u128>,
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<sapling::Node>,
    /// Map assets to their latest conversion and position in Merkle tree
    pub assets: BTreeMap<AssetType, ConversionLeaf>,
}

/// Able to borrow mutable conversion state.
pub trait WithConversionState {
    /// Borrow immutable conversion state
    fn conversion_state(&self) -> &ConversionState;

    /// Borrow mutable conversion state
    fn conversion_state_mut(&mut self) -> &mut ConversionState;
}
