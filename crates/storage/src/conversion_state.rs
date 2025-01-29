//! Shielded tokens conversion state

use std::collections::BTreeMap;

pub use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
pub use namada_core::masp::MaspEpoch;
pub use namada_core::masp_primitives::asset_type::AssetType;
pub use namada_core::masp_primitives::convert::AllowedConversion;
pub use namada_core::masp_primitives::merkle_tree::FrozenCommitmentTree;
pub use namada_core::masp_primitives::sapling::Node as SaplingNode;
pub use namada_core::token::{Denomination, MaspDigitPos};
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
    /// The masp epoch of the asset type
    pub epoch: MaspEpoch,
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
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<SaplingNode>,
    /// Map assets to their latest conversion and position in Merkle tree
    pub assets: BTreeMap<AssetType, ConversionLeaf>,
}

/// Able to borrow conversion state.
pub trait ReadConversionState {
    /// Borrow immutable conversion state
    fn conversion_state(&self) -> &ConversionState;
}

/// Able to borrow mutable conversion state.
pub trait WithConversionState: ReadConversionState {
    /// Borrow mutable conversion state
    fn conversion_state_mut(&mut self) -> &mut ConversionState;
}
