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

/// A representation of the conversion state
#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct ConversionState {
    /// The last amount of the native token distributed
    pub normed_inflation: Option<u128>,
    /// The tree currently containing all the conversions
    pub tree: FrozenCommitmentTree<sapling::Node>,
    /// A map from token alias to actual address.
    pub tokens: BTreeMap<String, Address>,
    /// Map assets to their latest conversion and position in Merkle tree
    #[allow(clippy::type_complexity)]
    pub assets: BTreeMap<
        AssetType,
        (
            (Address, Denomination, MaspDigitPos),
            Epoch,
            AllowedConversion,
            usize,
        ),
    >,
}

/// Able to borrow mutable conversion state.
pub trait WithConversionState {
    /// Borrow immutable conversion state
    fn conversion_state(&self) -> &ConversionState;

    /// Borrow mutable conversion state
    fn conversion_state_mut(&mut self) -> &mut ConversionState;
}
